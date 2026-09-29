//! A signed browser owns Apple's native helper. This daemon only relays SRP
//! envelopes between the existing UDP client and an authenticated extension.
use crate::utils::{clear_session, data_path, write_config};
use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket, accept_hdr_with_config};

pub const EXTENSION_ID: &str = "ocnafaklbiicdcplipchkaekhbdkkgpa";
pub const HOST_NAME: &str = "com.applepw.browser_bridge";
pub const CONNECTION_HELP: &str = "The Apple Passwords browser bridge is not connected. Keep the bridge tab open in the configured browser, enter the pairing token from `applepw bridge setup`, and click Connect. Then retry `applepw auth` or Raycast Search Passwords.";
const MAX_MESSAGE: usize = 65507; // The existing CLI transport is one UDP datagram.

#[derive(Clone, Copy, ValueEnum)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
}

impl Browser {
    fn directory(self) -> &'static str {
        match self {
            Self::Chrome => "Google/Chrome",
            Self::Edge => "Microsoft Edge",
            Self::Brave => "BraveSoftware/Brave-Browser",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BridgeConfig {
    pub port: u16,
    pub token: String,
}

pub fn load_config() -> Result<Option<BridgeConfig>> {
    let path = data_path().join("browser-bridge.json");
    match fs::read_to_string(&path) {
        Ok(text) => {
            let config: BridgeConfig = serde_json::from_str(&text)
                .context("Invalid browser bridge config; rerun `applepw bridge setup`")?;
            if config.port == 0 || config.token.len() != 64 {
                return Err(anyhow!(
                    "Invalid browser bridge config; rerun `applepw bridge setup`"
                ));
            }
            Ok(Some(config))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn native_manifest(helper_path: &str) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Apple Passwords helper for the applepw browser bridge",
        "path": helper_path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")]
    })
}

pub fn setup(browser: Browser, port: u16) -> Result<()> {
    if port == 0 {
        return Err(anyhow!("The bridge port must be between 1 and 65535"));
    }
    let helper = crate::daemon::read_manifest()?;
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Home directory not found"))?;
    let manifest_dir = home
        .join("Library/Application Support")
        .join(browser.directory())
        .join("NativeMessagingHosts");
    let state_dir = data_path();
    fs::create_dir_all(&manifest_dir)?;
    fs::create_dir_all(&state_dir)?;
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;

    // Re-running setup is idempotent: do not silently invalidate a paired tab.
    let existing = load_config()?;
    let config = existing.unwrap_or_else(|| {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        BridgeConfig {
            port,
            token: hex::encode(bytes),
        }
    });
    if config.port != port {
        return Err(anyhow!(
            "Bridge is already configured on port {}; use that port",
            config.port
        ));
    }
    write_private(
        &manifest_dir.join(format!("{HOST_NAME}.json")),
        &serde_json::to_vec_pretty(&native_manifest(&helper.path))?,
    )?;
    // Ship the extension with the binary, including Homebrew installations.
    let extension_dir = state_dir.join("browser-extension");
    fs::create_dir_all(&extension_dir)?;
    for (name, contents) in [
        (
            "manifest.json",
            include_str!("../browser-extension/manifest.json"),
        ),
        (
            "bridge.html",
            include_str!("../browser-extension/bridge.html"),
        ),
        ("bridge.js", include_str!("../browser-extension/bridge.js")),
        ("relay.js", include_str!("../browser-extension/relay.js")),
    ] {
        write_private(&extension_dir.join(name), contents.as_bytes())?;
    }
    write_private(
        &state_dir.join("browser-bridge.json"),
        &serde_json::to_vec(&config)?,
    )?;
    // An existing direct daemon must stop before selecting the new backend.
    if crate::daemon::is_daemon_running() {
        crate::daemon::stop_daemon()?;
    }
    clear_session()?;
    println!(
        "Browser bridge configured (localhost only).\n\
        Load this unpacked extension in your browser's Extensions page: {}\n\
        Open the extension to launch its bridge tab. Keep that tab open.\n\
        Bridge port: {}\nPairing token: {}\n\
        Enter the port and token in that tab and click Connect, then run `applepw auth`\n\
        or open Raycast Search Passwords. The Apple Passwords PIN is a separate code.\n\
        The pairing token grants access to the local relay; do not share it.",
        extension_dir.display(),
        config.port,
        config.token
    );
    Ok(())
}

fn origin_allowed(origin: Option<&str>) -> bool {
    origin == Some(format!("chrome-extension://{EXTENSION_ID}").as_str())
}

fn token_matches(supplied: &str, expected: &str) -> bool {
    supplied.len() == expected.len()
        && supplied
            .as_bytes()
            .iter()
            .zip(expected.as_bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

// tungstenite requires an HTTP response as the callback error type.
#[allow(clippy::result_large_err)]
fn connect(stream: TcpStream, token: &str) -> Result<WebSocket<TcpStream>> {
    // On macOS an accepted socket inherits the listener's nonblocking flag.
    // The bounded HTTP/auth handshake needs blocking reads before the loop.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let mut ws = accept_hdr_with_config(
        stream,
        |request: &Request, response: Response| -> std::result::Result<Response, ErrorResponse> {
            if origin_allowed(
                request
                    .headers()
                    .get("origin")
                    .and_then(|s| s.to_str().ok()),
            ) {
                Ok(response)
            } else {
                Err(tungstenite::http::Response::builder()
                    .status(403)
                    .body(Some("Forbidden".into()))
                    .unwrap())
            }
        },
        Some(ws_config),
    )?;
    let auth: Value = serde_json::from_str(ws.read()?.to_text()?)?;
    if auth["type"] != "authenticate" || !token_matches(auth["token"].as_str().unwrap_or(""), token)
    {
        let _ = ws.close(Some(tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Policy,
            reason: "Invalid pairing token".into(),
        }));
        return Err(anyhow!("Browser bridge authentication failed"));
    }
    // No SRP secrets survive a helper connection or browser restart.
    clear_session()?;
    ws.send(Message::text(json!({"type": "ready"}).to_string()))?;
    ws.get_mut().set_nonblocking(true)?;
    Ok(ws)
}

struct Pending {
    id: u64,
    source: SocketAddr,
    deadline: Instant,
}

fn send_error(udp: &UdpSocket, source: SocketAddr, text: &str) {
    let _ = udp.send_to(json!({"error": text}).to_string().as_bytes(), source);
}

fn transient(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(e)
        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut))
}

/// Serve forever; a disconnected tab can reconnect without restarting the CLI.
/// One request is in flight, as required by Apple's per-helper SRP session.
pub fn serve(config: BridgeConfig, udp_port: u16) -> Result<()> {
    let listener =
        TcpListener::bind(("127.0.0.1", config.port)).context("Cannot bind browser bridge port")?;
    listener.set_nonblocking(true)?;
    let udp = UdpSocket::bind(("127.0.0.1", udp_port))?;
    udp.set_nonblocking(true)?;
    write_config(None, None, Some(udp.local_addr()?.port()))?;
    clear_session()?;
    let mut browser: Option<WebSocket<TcpStream>> = None;
    let mut pending: Option<Pending> = None;
    let mut next_id = 0u64;
    let mut buffer = [0u8; MAX_MESSAGE + 1];
    loop {
        if browser.is_none() {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Reject unauthenticated peers without logging frames/tokens.
                    if let Ok(ws) = connect(stream, &config.token) {
                        browser = Some(ws);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut disconnected = false;
        if let Some(ws) = browser.as_mut() {
            match ws.read() {
                Ok(Message::Text(text)) => {
                    if let Ok(reply) = serde_json::from_str::<Value>(&text) {
                        if reply["type"] == "heartbeat" {
                            disconnected =
                                ws.send(Message::text("{\"type\":\"heartbeat\"}")).is_err();
                        } else if reply["type"] == "response"
                            && pending
                                .as_ref()
                                .is_some_and(|p| reply["id"].as_u64() == Some(p.id))
                        {
                            let p = pending.take().unwrap();
                            let output = if let Some(error) = reply["error"].as_str() {
                                json!({"error": error})
                            } else {
                                reply["payload"].clone()
                            };
                            let data = serde_json::to_vec(&output)?;
                            if data.len() > MAX_MESSAGE {
                                send_error(
                                    &udp,
                                    p.source,
                                    "Helper response exceeds CLI message limit",
                                );
                            } else {
                                let _ = udp.send_to(&data, p.source);
                            }
                        }
                    }
                }
                Ok(Message::Close(_)) => disconnected = true,
                Ok(_) => {}
                Err(e) if transient(&e) => {}
                Err(_) => disconnected = true,
            }
            match ws.flush() {
                Err(e) if !transient(&e) => disconnected = true,
                _ => {}
            }
        }
        if pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.deadline)
        {
            if let Some(p) = pending.take() {
                send_error(
                    &udp,
                    p.source,
                    "Browser helper timed out; reconnect and authenticate again",
                );
            }
            // Never assign a late reply from an old helper to a new request.
            disconnected = true;
        }
        if disconnected {
            if let Some(mut ws) = browser.take() {
                let _ = ws.close(None);
            }
            if let Some(p) = pending.take() {
                send_error(&udp, p.source, CONNECTION_HELP);
            }
            clear_session()?;
        }
        match udp.recv_from(&mut buffer) {
            Ok((size, source)) => {
                if size > MAX_MESSAGE {
                    send_error(&udp, source, "CLI request exceeds message limit");
                } else if let Some(ws) = browser.as_mut() {
                    if pending.is_some() {
                        send_error(&udp, source, "Browser helper is busy; retry the command");
                    } else if let Ok(payload) = serde_json::from_slice::<Value>(&buffer[..size]) {
                        next_id = next_id.wrapping_add(1);
                        let request = json!({"type": "request", "id": next_id, "payload": payload});
                        if ws.send(Message::text(request.to_string())).is_ok() {
                            pending = Some(Pending {
                                id: next_id,
                                source,
                                deadline: Instant::now() + Duration::from_secs(4),
                            });
                        } else {
                            send_error(&udp, source, CONNECTION_HELP);
                            browser = None;
                            clear_session()?;
                        }
                    } else {
                        send_error(&udp, source, "Invalid CLI request");
                    }
                } else {
                    send_error(&udp, source, CONNECTION_HELP);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_packaged_extension_origin_is_allowed() {
        assert!(origin_allowed(Some(&format!(
            "chrome-extension://{EXTENSION_ID}"
        ))));
        for origin in [
            None,
            Some("null"),
            Some("https://example.com"),
            Some("http://127.0.0.1:32145"),
            Some("chrome-extension://other"),
        ] {
            assert!(!origin_allowed(origin));
        }
    }
    #[test]
    fn token_must_match_in_full() {
        let token = "a".repeat(64);
        assert!(token_matches(&token, &token));
        assert!(!token_matches("", &token));
        assert!(!token_matches(&("a".repeat(63) + "b"), &token));
        assert!(!token_matches(&(token.clone() + "a"), &token));
    }
    #[test]
    fn manifest_limits_native_host_to_one_extension() {
        let manifest = native_manifest("/System/AppleHelper");
        assert_eq!(manifest["path"], "/System/AppleHelper");
        assert_eq!(
            manifest["allowed_origins"],
            json!([format!("chrome-extension://{EXTENSION_ID}/")])
        );
        assert_eq!(manifest["name"], HOST_NAME);
    }
}
