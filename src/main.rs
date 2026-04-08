pub mod client;
pub mod consts;
pub mod daemon;
pub mod srp;
pub mod types;
pub mod utils;

use clap::{Parser, Subcommand};
use client::ApplePasswordManager;
use consts::{Status, VERSION};
use std::process::exit;
use types::{Entry, Payload};
use utils::{read_bigint, to_base64};

#[derive(Parser)]
#[command(name = "applepw-cli")]
#[command(version = VERSION)]
#[command(about = "🔑 a CLI for Apple Passwords 🔒")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// URL to search for (default action is pw list)
    query: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate CLI with daemon.
    Auth {
        #[command(subcommand)]
        command: Option<AuthCommands>,
    },
    /// Interactively list accounts/passwords.
    Pw {
        #[command(subcommand)]
        command: PwCommands,
    },
    /// Interactively list accounts/OTPs.
    Otp {
        #[command(subcommand)]
        command: OtpCommands,
    },
    /// Stop the daemon.
    Stop,
    #[command(hide = true)]
    Daemon {
        #[arg(short, long, default_value_t = 0)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Request a challenge from the daemon.
    Request,
    /// Respond to a challenge from the daemon.
    Response {
        #[arg(short, long)]
        pin: String,
        #[arg(short, long)]
        salt: String,
        #[arg(short = 'k', long)]
        server_key: String,
        #[arg(short = 'c', long)]
        client_key: String,
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Subcommand)]
enum PwCommands {
    /// Get a password for a website.
    Get {
        url: String,
        username: Option<String>,
    },
    /// List available accounts for a website.
    List { url: String },
}

#[derive(Subcommand)]
enum OtpCommands {
    /// Get a OTP for a website.
    Get { url: String },
    /// List available OTPs for a website.
    List { url: String },
}

fn print_entries(payload: Payload, otp_usernames: Option<std::collections::HashSet<String>>) {
    if payload.STATUS != Status::Success && payload.STATUS != Status::NoResults {
        eprintln!("Error: {}", payload.STATUS);
        exit(payload.STATUS as i32);
    }

    let mut results = serde_json::Map::new();
    if let Some(entries) = payload.Entries {
        for (i, entry) in entries.into_iter().enumerate() {
            match entry {
                Entry::Password(p) => {
                    let domain = p.sites.first().cloned().unwrap_or_default();
                    let username = p.USR.clone();
                    let uuid_name = format!("{}:{}:{}", domain, username, i);
                    let id = uuid::Uuid::new_v5(&consts::APPLEPW_NAMESPACE, uuid_name.as_bytes())
                        .to_string();

                    let mut record = serde_json::json!({
                        "id": id,
                        "username": username,
                        "domain": domain,
                        "password": p.PWD.unwrap_or_else(|| "Not Included".to_string()),
                    });

                    if let Some(otps) = &otp_usernames {
                        record["has_otp"] = serde_json::Value::Bool(otps.contains(&username));
                    }

                    results.insert(id, record);
                }
                Entry::TOTP(t) => {
                    let domain = t.domain.clone();
                    let username = t.username.clone();
                    let uuid_name = format!("{}:{}:{}", domain, username, i);
                    let id = uuid::Uuid::new_v5(&consts::APPLEPW_NAMESPACE, uuid_name.as_bytes())
                        .to_string();

                    results.insert(
                        id.clone(),
                        serde_json::json!({
                            "id": id,
                            "username": username,
                            "domain": domain,
                            "code": t.code.unwrap_or_else(|| "Not Included".to_string()),
                        }),
                    );
                }
            }
        }
    }

    let output = serde_json::json!({
        "results": results,
        "status": Status::Success as i32
    });

    println!("{}", serde_json::to_string(&output).unwrap());
}

fn main() {
    let cli = Cli::parse();

    match run(cli) {
        Ok(_) => {}
        Err(e) => {
            let output = serde_json::json!({
                "error": e.to_string(),
                "status": Status::GenericError as i32,
                "results": []
            });
            eprintln!("{}", serde_json::to_string(&output).unwrap());
            exit(Status::GenericError as i32);
        }
    }
}

fn ensure_daemon() -> anyhow::Result<bool> {
    let mut needs_start = !daemon::is_daemon_running();
    let mut restarted = false;

    if !needs_start {
        // Test if the daemon is responsive
        let client = ApplePasswordManager::new();
        if client.get_capabilities().is_err() {
            // Unresponsive, kill and restart
            let _ = daemon::stop_daemon();
            needs_start = true;
        }
    }

    if needs_start {
        let exe = std::env::current_exe()?;
        std::process::Command::new(exe).arg("daemon").spawn()?;
        restarted = true;

        // Wait for daemon to start and update config
        let mut attempts = 0;
        let mut success = false;
        while attempts < 10 {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let is_responsive = daemon::is_daemon_running()
                && std::panic::catch_unwind(ApplePasswordManager::new)
                    .ok()
                    .and_then(|client| client.get_capabilities().ok())
                    .is_some();

            if is_responsive {
                success = true;
                break;
            }
            attempts += 1;
        }
        if !success {
            return Err(anyhow::anyhow!(
                "Daemon failed to become responsive after start"
            ));
        }
    }
    Ok(restarted)
}

fn run_search(client: &mut ApplePasswordManager, url: &str) -> anyhow::Result<()> {
    let otp_payload = client.list_otp_for_url(url).ok();
    let otp_usernames = otp_payload.as_ref().and_then(|p| {
        p.Entries.as_ref().map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    if let Entry::TOTP(t) = e {
                        Some(t.username.clone())
                    } else {
                        None
                    }
                })
                .collect::<std::collections::HashSet<_>>()
        })
    });

    let mut payload = client.get_login_names_for_url(url)?;

    if let Some(otp_entries) = otp_payload.and_then(|mut op| op.Entries.take()) {
        if let Some(ref mut entries) = payload.Entries {
            entries.extend(otp_entries);
        } else {
            payload.Entries = Some(otp_entries);
        }
    }

    print_entries(payload, otp_usernames);
    Ok(())
}

fn run_interactive_auth(client: &mut ApplePasswordManager) -> anyhow::Result<()> {
    client.request_challenge()?;
    print!("Enter PIN: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut pin = String::new();
    std::io::stdin().read_line(&mut pin)?;
    let pin = pin.trim();
    client.verify_challenge(pin)?;
    Ok(())
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Commands::Daemon { port }) => {
            daemon::start_daemon(port, true)?;
        }
        Some(Commands::Stop) => {
            daemon::stop_daemon()?;
            println!("Daemon stopped.");
        }
        Some(Commands::Auth { command }) => {
            let _ = ensure_daemon()?;
            let mut client = ApplePasswordManager::new();
            match command {
                Some(AuthCommands::Request) => {
                    client.request_challenge()?;
                    let srp_values = client.session.return_values();
                    let output = serde_json::json!({
                        "salt": to_base64(&utils::to_buffer(srp_values.salt.as_ref().unwrap())),
                        "serverKey": to_base64(&utils::to_buffer(srp_values.serverPublicKey.as_ref().unwrap())),
                        "username": srp_values.username.unwrap(),
                        "clientKey": to_base64(&utils::to_buffer(srp_values.clientPrivateKey.as_ref().unwrap())),
                    });
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                Some(AuthCommands::Response {
                    pin,
                    salt,
                    server_key,
                    client_key,
                    username,
                }) => {
                    let server_public_key = read_bigint(&utils::from_base64(&server_key)?);
                    let client_private_key = read_bigint(&utils::from_base64(&client_key)?);
                    let salt_response = read_bigint(&utils::from_base64(&salt)?);

                    let values = crate::types::SRPValues {
                        username: Some(username),
                        salt: Some(salt_response),
                        clientPrivateKey: Some(client_private_key),
                        serverPublicKey: Some(server_public_key),
                        ..Default::default()
                    };

                    client.session.update_with_values(values);
                    client.verify_challenge(&pin)?;

                    let output = serde_json::json!({ "status": Status::Success as i32 });
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                None => {
                    run_interactive_auth(&mut client)?;
                }
            }
        }
        Some(Commands::Pw { command }) => {
            let restarted = ensure_daemon()?;
            let mut client = ApplePasswordManager::new();
            if restarted || client.session.shared_key.is_none() {
                run_interactive_auth(&mut client)?;
                // Refresh client after auth
                client = ApplePasswordManager::new();
            }

            match command {
                PwCommands::Get { url, username } => {
                    let otp_usernames = client.list_otp_for_url(&url).ok().and_then(|p| {
                        p.Entries.map(|entries| {
                            entries
                                .into_iter()
                                .filter_map(|e| {
                                    if let Entry::TOTP(t) = e {
                                        Some(t.username)
                                    } else {
                                        None
                                    }
                                })
                                .collect::<std::collections::HashSet<_>>()
                        })
                    });
                    let payload =
                        client.get_password_for_url(&url, username.as_deref().unwrap_or(""))?;
                    print_entries(payload, otp_usernames);
                }
                PwCommands::List { url } => {
                    run_search(&mut client, &url)?;
                }
            }
        }
        Some(Commands::Otp { command }) => {
            let restarted = ensure_daemon()?;
            let mut client = ApplePasswordManager::new();
            if restarted || client.session.shared_key.is_none() {
                run_interactive_auth(&mut client)?;
                // Refresh client after auth
                client = ApplePasswordManager::new();
            }
            match command {
                OtpCommands::Get { url } => {
                    let payload = client.get_otp_for_url(&url)?;
                    print_entries(payload, None);
                }
                OtpCommands::List { url } => {
                    let payload = client.list_otp_for_url(&url)?;
                    print_entries(payload, None);
                }
            }
        }
        None => {
            if let Some(url) = cli.query {
                let restarted = ensure_daemon()?;
                let mut client = ApplePasswordManager::new();
                if restarted || client.session.shared_key.is_none() {
                    run_interactive_auth(&mut client)?;
                    client = ApplePasswordManager::new();
                }

                run_search(&mut client, &url)?;
            } else {
                // No command and no query, show help
                use clap::CommandFactory;
                Cli::command().print_help()?;
                println!();
            }
        }
    }

    Ok(())
}
