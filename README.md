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

Requires a current stable Rust toolchain (edition 2024).

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
# Report daemon/auth status as JSON
applepw status

# Stop the background daemon
applepw stop

# Manually re-authenticate
applepw auth
```

## How it Works

`applepw` communicates with the official macOS `PasswordManagerBrowserExtensionHelper` via a background daemon. It uses the **SRP (Secure Remote Password)** protocol to establish a secure, encrypted session with the system keychain, ensuring your credentials never leave your machine unencrypted.


## macOS 26 and later: browser bridge

Recent macOS versions add a **parent launch constraint** to
`PasswordManagerBrowserExtensionHelper`: a signed, allowed browser must launch
it. The helper is killed when a CLI launches it directly, before the authentication
PIN appears.
If `applepw` detects that constraint it now explains the required setup instead
of waiting for an unresponsive daemon.

The optional browser bridge preserves the CLI commands used by Raycast. Chrome,
Edge, or Brave launches Apple's helper with `runtime.connectNative`; the bridge
relays the existing SRP/encrypted messages to the local daemon. It does not
remove or bypass the helper's launch constraint.

1. Build/install this version of `applepw` with a current stable Rust toolchain.
2. Run `applepw bridge setup` (Chrome), or
   `applepw bridge setup --browser edge` / `--browser brave`.
   No administrator privileges are needed. Setup registers a separate native
   host in that browser's user-level `NativeMessagingHosts` directory; it does
   not modify Apple's system manifest.
3. Open that browser's Extensions page, enable **Developer mode**, and choose
   **Load unpacked**. Select the extension directory printed by setup (normally
   `~/.applepw/browser-extension`). This extension is bundled in the CLI binary,
   so this works with an installed binary as well as a source checkout.
4. Click the extension to open its persistent bridge tab. Enter the port and
   pairing token printed by setup, and click **Connect**. Keep the tab and
   browser open. The tab reconnects while waiting for the CLI daemon to start.
5. Run `applepw auth`, or open **Search Passwords** in Raycast. Enter the separate
   PIN displayed by Apple Passwords. Password and OTP commands are unchanged.

`applepw bridge setup` can be rerun to show the existing pairing token. If the
port is occupied, select another with `--port` on the first setup. The pairing
input is remembered only in the bridge tab's memory, so reopening the tab
requires pairing again. Closing the tab or restarting the browser destroys the
helper's SRP session; reconnect and authenticate again.

### Access and security

- The extension requests only `nativeMessaging`. It has no content scripts,
  website permissions, or external-message handlers.
- The WebSocket listener binds only `127.0.0.1`. It requires the packaged
  extension's exact Origin **and** a random 256-bit pairing token. The token is
  stored in `browser-bridge.json` with mode `0600`, inside a `0700` directory;
  treat it as a local secret and do not share setup output.
- Only the CLI's existing read/authentication commands are relayed. Credential
  creation/update commands and unsolicited helper events are not forwarded as
  request replies. The extension never decrypts or caches credentials.
- SRP session files use mode `0600`. Connecting or disconnecting a helper clears
  any old session key, preventing a restarted browser from appearing already
  authenticated. A stalled helper is disconnected so a late reply cannot be
  mistaken for the next command's response.
- The browser must remain running. This backend is opt-in; machines that can
  launch the helper directly retain the original backend.

To return to direct mode, stop `applepw`, close/remove the browser extension,
then move `~/.applepw/browser-bridge.json` out of the state directory. Direct mode
still requires a macOS helper without a restrictive parent launch constraint.
`APPLEPW_HOME` can select a separate CLI state directory for development/tests.

### Verification

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
node --test browser-extension/*.test.mjs
```

The automated bridge tests use a simulated browser/native helper and fake
protocol envelopes. They verify routing, origin/token rejection, timeout,
reconnection, session invalidation, file permissions, unsolicited events, and
command restrictions. They do not access a real password vault. A live browser
and Apple Passwords PIN exchange should also be validated before release.
