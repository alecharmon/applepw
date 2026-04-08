# Contributing to applepw

Thank you for your interest in improving `applepw`! We welcome contributions of all kinds.

## Development Setup

1.  **Prerequisites**: You must be running **macOS 14 (Sonoma)** or later.
2.  **Clone the Repo**:
    ```bash
    git clone https://github.com/alecharmon/applepw
    cd applepw
    ```
3.  **Build**:
    ```bash
    cargo build
    ```

## Development Workflow

### Coding Standards
We use standard Rust tools to keep the codebase clean:
- **Formatting**: Run `cargo fmt` before committing.
- **Linting**: Run `cargo clippy -- -D warnings` to ensure there are no lint errors.
- **Verification**: Run `cargo check` to verify the build.

### Architecture
- `src/main.rs`: CLI entry point and command routing.
- `src/client.rs`: SRP session management and communication with the daemon.
- `src/daemon.rs`: The background process that bridges the CLI to the macOS native messaging host.
- `src/srp.rs`: Implementation of the Secure Remote Password protocol.

## Releasing

To release a new version:
1.  Update the `version` in `Cargo.toml`.
2.  Commit the change: `git commit -am "Bump version to X.Y.Z"`.
3.  Tag the commit: `git tag vX.Y.Z`.
4.  Push the tag: `git push origin main --tags`.

The GitHub Action will automatically:
- Verify the version match.
- Build Intel and ARM binaries.
- Create a GitHub Release.
- Update the Homebrew Tap.

## Questions?
Feel free to open an issue for bug reports or feature requests!
