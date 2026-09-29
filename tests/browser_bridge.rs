use serde_json::{Value, json};
use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message, WebSocket};

const ORIGIN: &str = "chrome-extension://ocnafaklbiicdcplipchkaekhbdkkgpa";

struct Daemon {
    child: Child,
    directory: PathBuf,
    browser_port: u16,
    udp: UdpSocket,
    udp_port: u16,
    token: String,
}

impl Daemon {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let browser_port = listener.local_addr().unwrap().port();
        drop(listener);
        let directory = std::env::temp_dir().join(format!(
            "applepw-bridge-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&directory).unwrap();
        let token = "a".repeat(64);
        fs::write(
            directory.join("browser-bridge.json"),
            json!({"port": browser_port, "token": token}).to_string(),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_applepw"))
            .args(["daemon", "--foreground"])
            .env("APPLEPW_HOME", &directory)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let udp_port = loop {
            let port = fs::read_to_string(directory.join("config.toml"))
                .ok()
                .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
                .and_then(|config| config.get("port").and_then(|p| p.as_integer()));
            if let Some(port) = port {
                break port as u16;
            }
            assert!(Instant::now() < deadline, "bridge did not start");
            std::thread::sleep(Duration::from_millis(20));
        };
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Self {
            child,
            directory,
            browser_port,
            udp,
            udp_port,
            token,
        }
    }
    fn websocket(&self, origin: &str) -> anyhow::Result<WebSocket<TcpStream>> {
        let address = format!("127.0.0.1:{}", self.browser_port);
        let stream = TcpStream::connect(&address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = format!("ws://{address}").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", origin.parse().unwrap());
        tungstenite::client::client(request, stream)
            .map(|(ws, _)| ws)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn connect(&self) -> WebSocket<TcpStream> {
        let mut ws = self.websocket(ORIGIN).unwrap();
        ws.send(Message::text(
            json!({"type": "authenticate", "token": self.token}).to_string(),
        ))
        .unwrap();
        assert_eq!(read_json(&mut ws)["type"], "ready");
        ws
    }
    fn request(&self, payload: &Value) {
        self.udp
            .send_to(payload.to_string().as_bytes(), ("127.0.0.1", self.udp_port))
            .unwrap();
    }
    fn response(&self) -> Value {
        let mut buffer = [0u8; 65535];
        let (size, source) = self.udp.recv_from(&mut buffer).unwrap();
        assert_eq!(source.port(), self.udp_port);
        serde_json::from_slice(&buffer[..size]).unwrap()
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn read_json(ws: &mut WebSocket<TcpStream>) -> Value {
    serde_json::from_str(ws.read().unwrap().to_text().unwrap()).unwrap()
}

#[test]
fn forwards_handshake_and_encrypted_requests_without_changing_payloads() {
    let daemon = Daemon::new();
    let mut ws = daemon.connect();
    for payload in [
        json!({"cmd":14}),
        json!({"cmd":2,"msg":{"QID":"m0","PAKE":"opaque-test-handshake"}}),
        json!({"cmd":5,"payload":{"SMSG":{"TID":"test","SDATA":"opaque-test-ciphertext"}}}),
        json!({"cmd":16,"payload":"opaque-test-otp"}),
    ] {
        daemon.request(&payload);
        let request = read_json(&mut ws);
        assert_eq!(request["payload"], payload);
        let response = json!({"cmd":payload["cmd"],"payload":"opaque-test-reply"});
        ws.send(Message::text(
            json!({"type":"response","id":request["id"],"payload":response}).to_string(),
        ))
        .unwrap();
        assert_eq!(daemon.response(), response);
    }
    let mode = fs::metadata(daemon.directory.join("config.toml"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn rejects_web_origins_and_incorrect_pairing_tokens() {
    let daemon = Daemon::new();
    assert!(daemon.websocket("https://example.com").is_err());
    let mut ws = daemon.websocket(ORIGIN).unwrap();
    ws.send(Message::text(
        json!({"type":"authenticate","token":"b".repeat(64)}).to_string(),
    ))
    .unwrap();
    assert!(matches!(ws.read(), Ok(Message::Close(_)) | Err(_)));
    drop(ws);
    let mut valid = daemon.connect();
    valid
        .send(Message::text("{\"type\":\"heartbeat\"}"))
        .unwrap();
    assert_eq!(read_json(&mut valid)["type"], "heartbeat");
}

#[test]
fn ignores_stale_responses_and_reports_busy_requests() {
    let daemon = Daemon::new();
    let mut ws = daemon.connect();
    daemon.request(&json!({"cmd":14}));
    let request = read_json(&mut ws);
    daemon.request(&json!({"cmd":2}));
    assert!(
        daemon.response()["error"]
            .as_str()
            .unwrap()
            .contains("busy")
    );
    ws.send(Message::text(
        json!({"type":"response","id":0,"payload":{"stale":true}}).to_string(),
    ))
    .unwrap();
    ws.send(Message::text(
        json!({"type":"response","id":request["id"],"payload":{"cmd":14}}).to_string(),
    ))
    .unwrap();
    assert_eq!(daemon.response(), json!({"cmd":14}));
}

#[test]
fn disconnect_invalidates_session_and_new_browser_can_reconnect() {
    let daemon = Daemon::new();
    let mut ws = daemon.connect();
    fs::write(
        daemon.directory.join("config.toml"),
        format!(
            "port = {}\nusername = 'fake-session'\nsharedKey = 'AQ=='\n",
            daemon.udp_port
        ),
    )
    .unwrap();
    daemon.request(&json!({"cmd":14}));
    let _ = read_json(&mut ws);
    ws.close(None).unwrap();
    assert!(
        daemon.response()["error"]
            .as_str()
            .unwrap()
            .contains("not connected")
    );
    drop(ws);
    let mut next = daemon.connect();
    let config = fs::read_to_string(daemon.directory.join("config.toml")).unwrap();
    assert!(!config.contains("sharedKey"));
    assert!(!config.contains("username"));
    daemon.request(&json!({"cmd":14}));
    let request = read_json(&mut next);
    next.send(Message::text(
        json!({"type":"response","id":request["id"],"payload":{"cmd":14}}).to_string(),
    ))
    .unwrap();
    assert_eq!(daemon.response(), json!({"cmd":14}));
}

#[test]
fn a_silent_helper_times_out_instead_of_hanging_the_cli() {
    let daemon = Daemon::new();
    let mut ws = daemon.connect();
    daemon.request(&json!({"cmd":14}));
    let _ = read_json(&mut ws);
    assert!(
        daemon.response()["error"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
}
