use crate::types::ManifestConfig;
use crate::utils::{data_path, write_config};
use anyhow::{Result, anyhow};
use daemonize::Daemonize;
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

pub fn is_daemon_running() -> bool {
    let dir = data_path();
    let pid_file = dir.join("daemon.pid");
    if !pid_file.exists() {
        return false;
    }

    if let Some(pid) = fs::read_to_string(&pid_file)
        .ok()
        .and_then(|c| c.trim().parse::<i32>().ok())
    {
        // On Unix, kill(pid, 0) checks if process exists
        return unsafe { libc::kill(pid, 0) == 0 };
    }
    false
}

pub fn stop_daemon() -> Result<()> {
    let dir = data_path();
    let pid_file = dir.join("daemon.pid");
    if !pid_file.exists() {
        return Err(anyhow!("Daemon is not running."));
    }

    if let Some(pid) = fs::read_to_string(&pid_file)
        .ok()
        .and_then(|c| c.trim().parse::<i32>().ok())
    {
        unsafe {
            if libc::kill(pid, 15) == 0 {
                let _ = fs::remove_file(pid_file);
                return Ok(());
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::NotFound {
                    let _ = fs::remove_file(pid_file);
                    return Ok(());
                }
                return Err(anyhow!("Failed to stop daemon with PID {}: {}", pid, err));
            }
        }
    }
    let _ = fs::remove_file(pid_file);
    Ok(())
}

pub fn start_daemon(mut port: u16, should_daemonize: bool) -> Result<()> {
    if is_daemon_running() && should_daemonize {
        return Ok(());
    }

    if should_daemonize {
        let dir = data_path();
        fs::create_dir_all(&dir)?;

        let stdout = fs::File::create(dir.join("daemon.out"))?;
        let stderr = fs::File::create(dir.join("daemon.err"))?;

        let daemonize = Daemonize::new()
            .pid_file(dir.join("daemon.pid"))
            .working_directory(&dir)
            .stdout(stdout)
            .stderr(stderr);

        daemonize.start()?;
    }

    let config = read_manifest()?;

    let mut child = Command::new(&config.path)
        .arg(".")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    if !should_daemonize {
        println!("applepw helper found & launched.");
    }

    let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))?;
    port = socket.local_addr()?.port();
    write_config(None, None, Some(port))?;

    if !should_daemonize {
        println!("applepw Helper Listening on port {}.", port);
    }

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
            break;
        }
        if let Err(e) = stdin.write_all(data) {
            eprintln!("Failed to write data to stdin: {}", e);
            break;
        }
        if let Err(e) = stdin.flush() {
            eprintln!("Failed to flush stdin: {}", e);
            break;
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
    Ok(())
}
