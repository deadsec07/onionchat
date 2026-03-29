# onionchat

`onionchat` is a minimal, production-oriented, privacy-focused CLI chat application for direct peer-to-peer text exchange over Tor onion services.

Project site:

- GitHub Pages marketing site: `https://deadsec07.github.io/onionchat/`

It is intentionally small:

- No accounts
- No phone numbers
- No email
- No cloud backend
- No telemetry
- No GUI
- No file transfer

The current MVP uses:

- Rust
- Tor control port integration
- `SAFECOOKIE` authentication when Tor offers it
- Tor v3 onion services for inbound reachability
- Tor SOCKS for outbound delivery
- Signed invite export/import for contact exchange
- Direct chat and invite-only group fan-out
- A simple length-prefixed JSON message frame

## Status

This is a realistic MVP, not a finished secure messenger. It is suitable as a clean base for a real open-source privacy tool, but it does not claim to make users untrackable.

## Threat Model

`onionchat` aims to reduce exposure by avoiding central servers and sending traffic over Tor onion services. It does not try to solve every anonymity or endpoint-security problem.

What it tries to do:

- Avoid account-based identity
- Avoid centralized infrastructure
- Keep contact discovery manual and explicit
- Minimize local state
- Avoid plaintext message logging by default
- Keep the protocol and storage simple enough to audit

What it does not guarantee:

- It does not guarantee users are "untrackable"
- It does not prevent deanonymization through timing analysis
- It does not protect a compromised OS, compromised Tor daemon, or compromised endpoint
- It does not stop users from leaking identifying information in messages
- It does not currently add application-layer end-to-end encryption beyond Tor transport

Risks to understand:

- Anyone with access to your machine can read local config and identity files
- Peer onion addresses and invite-derived contact metadata are stored locally
- Group membership lists are stored locally
- Traffic still depends on correct Tor configuration and a healthy Tor network
- Terminal scrollback may expose message content on the local machine

## Protocol

Transport is deliberately small:

- Outbound delivery uses Tor SOCKS to connect to `<peer>.onion:<virtual_port>`
- Inbound reachability uses a Tor v3 onion service published through the control port
- Each message is one TCP connection carrying one frame
- Direct and group messages use the same frame format
- Groups are invite-only local fan-out groups; there is no coordinator or server-side group state
- Frame format is `4-byte big-endian length` + `JSON payload`

Current JSON payload:

```json
{
  "version": 1,
  "from": "exampleexampleexampleexampleexampleexampleexampleexample.onion",
  "timestamp_unix": 1710000000,
  "payload": {
    "kind": "direct",
    "body": "hello"
  }
}
```

There is no delivery queue, message history sync, presence protocol, or decentralized discovery service.

## Tor Requirements

`onionchat` expects a local Tor daemon with:

- A SOCKS port
- A control port
- Cookie authentication enabled for `SAFECOOKIE` if possible

Typical Tor settings:

```torrc
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

If Tor is already installed as a system service, `onionchat` will use it. If not, run Tor locally and point `onionchat` at the relevant ports through the config file.

## Build

### Linux / macOS

```bash
cargo build --release
```

Binary output:

```bash
target/release/onionchat
```

### Windows

```powershell
cargo build --release
```

Binary output:

```powershell
target\release\onionchat.exe
```

Notes:

- The binary is a single Rust executable.
- "Static-ish" distribution is the goal; exact linkage depends on target platform and toolchain.
- For fully static Linux builds, target musl separately if desired.

Example:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Configuration

Default config location is platform-specific:

- Linux: `~/.config/onionchat/config.toml`
- macOS: `~/Library/Application Support/io.onionchat.onionchat/config.toml`
- Windows: `%APPDATA%\onionchat\onionchat\config\config.toml` or equivalent platform-resolved config dir

You can override the whole config root for testing:

```bash
export ONIONCHAT_CONFIG_DIR=/tmp/onionchat-a
```

The app creates:

- `config.toml`
- `identity.json`
- `peers.json`
- `groups.json`

Example config:

```toml
[tor]
control_host = "127.0.0.1"
control_port = 9051
socks_host = "127.0.0.1"
socks_port = 9050

[app]
onion_virtual_port = 17654
log_level = "info"
max_message_bytes = 4096
```

## Usage

Initialize local identity:

```bash
onionchat init
```

Show local identity:

```bash
onionchat identity show
```

Export a signed invite file:

```bash
onionchat invite export --name alice --output alice-invite.json
```

Import another person's invite:

```bash
onionchat invite import alice-invite.json
```

Save a peer manually:

```bash
onionchat peers add abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion --name alice
```

List saved peers:

```bash
onionchat peers list
```

Listen for inbound messages:

```bash
onionchat listen
```

Send one message:

```bash
onionchat send abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion "hello"
```

Interactive terminal chat:

```bash
onionchat chat abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion
```

`chat` is intentionally simple:

- It publishes your onion service
- It listens for incoming messages
- Every line you type is sent as a separate Tor connection
- The peer should be running either `listen` or `chat`

Create an invite-only group from known peers:

```bash
onionchat groups create team \
  abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion \
  bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz23456.onion
```

List local groups:

```bash
onionchat groups list
```

Inspect a group's members:

```bash
onionchat groups show <group_id>
```

Send a one-off group message:

```bash
onionchat groups send <group_id> "hello team"
```

Run an interactive group chat session:

```bash
onionchat groups chat <group_id>
```

## Discovery Model

`onionchat` does not implement public discovery, usernames, or a global directory.

How people find each other:

- They exchange signed invite files out of band
- They share raw onion addresses manually
- They add peers locally with `peers add`
- They create groups only from peers already known locally

This is deliberate. It avoids introducing a central server, public index, or discovery protocol that would add metadata leakage and abuse pressure.

## Local Demo

Two peers can be tested on one machine if both use the same Tor daemon but separate config roots.

Terminal A:

```bash
export ONIONCHAT_CONFIG_DIR=/tmp/onionchat-a
cargo run -- init
cargo run -- identity show
cargo run -- invite export --name alice --output /tmp/alice-invite.json
cargo run -- listen
```

Terminal B:

```bash
export ONIONCHAT_CONFIG_DIR=/tmp/onionchat-b
cargo run -- init
cargo run -- identity show
cargo run -- invite import /tmp/alice-invite.json
cargo run -- chat <peer_a_onion>
```

If you want bidirectional live chat, run `chat` on both sides and use each side's onion address.

Minimal group demo:

```bash
export ONIONCHAT_CONFIG_DIR=/tmp/onionchat-b
cargo run -- peers add <peer_a_onion> --name alice
cargo run -- groups create duo <peer_a_onion>
cargo run -- groups chat <group_id>
```

## Logging

Defaults are privacy-oriented:

- No telemetry
- No analytics
- No plaintext message logging in normal logs
- Only operational events are logged

Set `RUST_LOG=onionchat=debug` for debugging. Message bodies are still not logged by the application.

## Limitations

- No application-layer end-to-end encryption yet
- No public discovery or searchable directory
- No offline delivery
- No message history synchronization
- No NAT traversal outside Tor onion services
- Invite signatures authenticate contact-card integrity, but direct messages are not yet signed end-to-end
- Assumes reachable local Tor control and SOCKS ports
- `SAFECOOKIE` and `NULL` auth are supported; password-authenticated control ports are not yet implemented
- Group delivery is simple fan-out to each member and does not handle membership churn or acknowledgements

If a Tor feature is missing locally, the app fails explicitly rather than pretending to work.

## Tests

```bash
cargo test
```

## Packaging Notes

The codebase is structured for later packaging through:

- Homebrew
- winget
- native Linux packages

The immediate goal is standalone release binaries first.

## Project Layout

```text
src/main.rs
src/cli.rs
src/config.rs
src/identity.rs
src/tor.rs
src/transport.rs
src/chat.rs
src/storage.rs
src/error.rs
```
