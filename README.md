# applepw 🔑

`applepw` is a fast, lightweight, and secure CLI for accessing your **Apple Passwords** (iCloud Keychain) on macOS. It allows you to search for passwords and TOTP codes directly from your terminal.

## Features

- **Shorthand Search**: Just run `applepw carta` to find credentials for `carta.com`.
- **Automatic TOTP**: Shows your 2FA codes alongside your passwords automatically.
- **Self-Healing Daemon**: Automatically manages a background helper process to communicate with macOS security services.
- **Deterministic IDs**: Generates stable UUIDs for every record for easy piping into other tools.

## Installation

### Homebrew (Recommended)

```bash
brew install alecharmon/tap/applepw
```

### From Source

Requires Rust 1.75+.

```bash
git clone https://github.com/alecharmon/applepw
cd applepw
cargo install --path .
```

## Usage

### Simple Search
The fastest way to find a password or OTP:
```bash
applepw carta
```
This will automatically search for `carta`, `carta.com`, `carta.net`, etc.

### Password Commands
```bash
# List all accounts for a domain
applepw pw list google.com

# Get a specific password (requires system prompt)
applepw pw get github.com
```

### OTP Commands
```bash
# List all OTP accounts for a domain
applepw otp list carta.com

# Get a specific OTP code
applepw otp get carta.com
```

### Management
```bash
# Stop the background daemon
applepw stop

# Manually re-authenticate
applepw auth
```

## How it Works

`applepw` communicates with the official macOS `PasswordManagerBrowserExtensionHelper` via a background daemon. It uses the **SRP (Secure Remote Password)** protocol to establish a secure, encrypted session with the system keychain, ensuring your credentials never leave your machine unencrypted.


