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
    command: Commands,
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
    /// Start the daemon.
    Start {
        /// Port to listen on.
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

fn print_entries(payload: Payload) {
    if payload.STATUS != Status::Success {
        eprintln!("Error: {}", payload.STATUS);
        exit(payload.STATUS as i32);
    }

    let mut results = Vec::new();
    for entry in payload.Entries {
        match entry {
            Entry::Password(p) => {
                results.push(serde_json::json!({
                    "username": p.USR,
                    "domain": p.sites.first().cloned().unwrap_or_default(),
                    "password": p.PWD.unwrap_or_else(|| "Not Included".to_string()),
                }));
            }
            Entry::TOTP(t) => {
                results.push(serde_json::json!({
                    "username": t.username,
                    "domain": t.domain,
                    "code": t.code.unwrap_or_else(|| "Not Included".to_string()),
                }));
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

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Start { port } => {
            daemon::start_daemon(port)?;
        }
        Commands::Auth { command } => {
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
                    client.request_challenge()?;
                    print!("Enter PIN: ");
                    std::io::Write::flush(&mut std::io::stdout())?;
                    let mut pin = String::new();
                    std::io::stdin().read_line(&mut pin)?;
                    let pin = pin.trim();
                    client.verify_challenge(pin)?;
                }
            }
        }
        Commands::Pw { command } => {
            let client = ApplePasswordManager::new();
            match command {
                PwCommands::Get { url, username } => {
                    let payload =
                        client.get_password_for_url(&url, username.as_deref().unwrap_or(""))?;
                    print_entries(payload);
                }
                PwCommands::List { url } => {
                    let payload = client.get_login_names_for_url(&url)?;
                    print_entries(payload);
                }
            }
        }
        Commands::Otp { command } => {
            let client = ApplePasswordManager::new();
            match command {
                OtpCommands::Get { url } => {
                    let payload = client.get_otp_for_url(&url)?;
                    print_entries(payload);
                }
                OtpCommands::List { url } => {
                    let payload = client.list_otp_for_url(&url)?;
                    print_entries(payload);
                }
            }
        }
    }

    Ok(())
}
