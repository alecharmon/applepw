use crate::types::ManifestConfig;
use crate::utils::{clear_config, write_config};
use anyhow::{Result, anyhow};
use std::fs;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};

fn read_manifest() -> Result<ManifestConfig> {
    let paths = [
        "/Library/Application Support/Mozilla/NativeMessagingHosts/com.apple.passwordmanager.json",
        "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json",
    ];

    for path in &paths {
        if Path::new(path).exists() {
            let data = fs::read_to_string(path)?;
            let config: ManifestConfig = serde_json::from_str(&data)?;
            return Ok(config);
        }
    }

    Err(anyhow!(
        "applepw Helper manifest not found. You must be running macOS 14 or above."
    ))
}

pub fn start_daemon(mut port: u16) -> Result<()> {
    clear_config()?;
    let config = read_manifest()?;

    let mut child = Command::new(&config.path)
        .arg(".")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    println!("applepw helper found & launched.");

    let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))?;
    port = socket.local_addr()?.port();
    write_config(None, None, Some(port))?;

    println!("applepw Helper Listening on port {}.", port);

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let mut stdout = child.stdout.take().expect("Failed to open stdout");

    let mut buf = [0u8; 65535];
    loop {
        let (amt, src) = match socket.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Failed to receive UDP packet: {}", e);
                continue;
            }
        };
        let data = &buf[..amt];

        let len = (data.len() as u32).to_le_bytes();
        if let Err(e) = stdin.write_all(&len) {
            eprintln!("Failed to write length to stdin: {}", e);
            continue;
        }
        if let Err(e) = stdin.write_all(data) {
            eprintln!("Failed to write data to stdin: {}", e);
            continue;
        }
        if let Err(e) = stdin.flush() {
            eprintln!("Failed to flush stdin: {}", e);
            continue;
        }

        let mut out_len_buf = [0u8; 4];

        let read_result = stdout.read_exact(&mut out_len_buf);
        if let Err(e) = read_result {
            eprintln!("Command output wait timed out or failed: {}", e);
            let _ = socket.send_to(b"{\"error\": \"timeout\"}", src);
            continue;
        }

        let out_len = u32::from_le_bytes(out_len_buf) as usize;

        let mut out_data = vec![0u8; out_len];
        if let Err(e) = stdout.read_exact(&mut out_data) {
            eprintln!("Failed to read command output data: {}", e);
            continue;
        }

        if serde_json::from_slice::<serde_json::Value>(&out_data).is_ok() {
            let _ = socket.send_to(&out_data, src);
        } else {
            eprintln!(
                "Failed to parse JSON. Data was: {:?}",
                std::str::from_utf8(&out_data)
            );
            let _ = socket.send_to(&out_data, src);
        }
    }
}
