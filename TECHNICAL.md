# RustBlocker Technical Reference

This file contains the technical, build, test, storage, API, and deployment details that are intentionally kept out of the quick-start README.

## Features

- **Blocklist**: block domains by exact match or wildcard (`*.example.com`)
- **Allowlist**: bypass blocklist for specific domains
- **DNS Rewrite**: return custom IPs for specific domains
- **Parallel Forwarding**: races queries across multiple upstream resolvers
- **UDP + TCP**: listens on both protocols simultaneously
- **Web Management UI**: TailwindCSS dark UI
- **Query Statistics**: tracks totals, top clients, top domains, and recent queries
- **Live Query Log**: Server-Sent Events stream
- **REST API**: CRUD for lists, rewrites, settings, upstreams, sources, stats, sync, and ACME
- **SQLite database**: portable single-file storage
- **Hot reload**: list and rewrite changes take effect immediately
- **Auto-update sources**: scheduled blocklist/allowlist URL refresh
- **Admin password authentication**: generated/reset through `--genpass`
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Replica sync**: hash-diffed configuration mirroring
- **HTTPS with ACME**: Let's Encrypt via Cloudflare DNS-01
- **Certificate auto-renewal**: checks every 24 hours, renews within 7 days of expiry
- **Activity log**: real-time ACME, settings, restart, and update progress

## Build From Source

Prerequisites:

- Rust toolchain
- Node.js, only needed for Tailwind CSS builds

```bash
npm install
npm run build:css
cargo build --release
sudo ./target/release/rustblocker
```

Port 53 requires elevated privileges.

## Cross-Compile From Windows Or Another Host

For a static Linux binary, `cargo-zigbuild` is recommended:

```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

On Linux you can also use:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

## Testing

Required checks before committing code changes:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

If `static/index.html` or `static/input.css` changes:

```bash
npm run build:css
git diff --exit-code static/tailwind.min.css
```

If `static/app.js` changes:

```bash
node --check static/app.js
```

## SQLite Database

RustBlocker uses SQLite (`rustblocker.db`) for configuration and runtime state.

- Created automatically on first run
- No config files required
- Stores settings, upstream servers, blocklist domains, allowlist domains, rewrite rules, query logs, sources, TLS certificates, and auth/session settings
- Portable: copy the database to migrate configuration

Installed service database path:

```text
/var/lib/rustblocker/rustblocker.db
```

## Web Management UI

The Web UI is available at:

```text
http://<server-ip>:54
```

Default tabs:

- **Dashboard**: summary counters and source state
- **Upstreams**: upstream DNS servers
- **Sources**: scheduled blocklist/allowlist sources
- **Blocklist**: blocked domains
- **Allowlist**: allowed domains
- **Rewrites**: local DNS rewrites
- **Settings**: listen address, ports, sinkhole IPs, timeouts, ACL, sync, password
- **HTTPS**: ACME settings, certificate status, renewal state
- **Activity Log**: real-time progress stream

Changes to blocklist, allowlist, rewrites, sinkhole IPs, upstream timeout, stats retention, and ACL apply live. Listen address, listen port, and log level require restart.

## REST API

Base URL:

```text
http://<listen_address>:<listen_port + 1>/api
```

Protected endpoints require a session cookie from `/api/auth/login`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/auth/login` | Log in with admin password |
| `POST` | `/api/auth/logout` | Clear session cookie |
| `GET` | `/api/auth/check` | Check active session |
| `PUT` | `/api/auth/password` | Change admin password |
| `GET` | `/api/settings` | Get settings |
| `PUT` | `/api/settings` | Update one setting |
| `GET` | `/api/upstreams` | List upstream servers |
| `POST` | `/api/upstreams` | Add upstream server |
| `DELETE` | `/api/upstreams/{id}` | Remove upstream server |
| `GET` | `/api/blocklist` | List blocked domains |
| `POST` | `/api/blocklist` | Add blocked domain |
| `DELETE` | `/api/blocklist/{id}` | Remove blocked domain |
| `POST` | `/api/blocklist/import` | Bulk import blocklist |
| `GET` | `/api/allowlist` | List allowed domains |
| `POST` | `/api/allowlist` | Add allowed domain |
| `DELETE` | `/api/allowlist/{id}` | Remove allowed domain |
| `POST` | `/api/allowlist/import` | Bulk import allowlist |
| `GET` | `/api/rewrites` | List DNS rewrites |
| `POST` | `/api/rewrites` | Add DNS rewrite |
| `DELETE` | `/api/rewrites/{id}` | Remove DNS rewrite |
| `GET` | `/api/sources` | List auto-update sources |
| `POST` | `/api/sources` | Add source and fetch immediately |
| `DELETE` | `/api/sources/{id}` | Remove source |
| `POST` | `/api/sources/refresh` | Refresh all enabled sources |
| `GET` | `/api/stats` | Query statistics |
| `GET` | `/api/stats/queries` | Recent query log |
| `GET` | `/api/stats/live` | Live query stream |
| `DELETE` | `/api/stats` | Clear query statistics |
| `GET` | `/api/sync/config` | Get replica sync config |
| `PUT` | `/api/sync/config` | Save replica sync config |
| `GET` | `/api/sync/manifest` | Master-side category hashes |
| `GET` | `/api/sync/snapshot/{category}` | Master-side data snapshot |
| `POST` | `/api/acme/request` | Request certificate |
| `POST` | `/api/acme/renew` | Force certificate renewal |
| `GET` | `/api/acme/status` | Certificate and renewal status |
| `GET` | `/api/activity/stream` | Activity SSE stream |
| `POST` | `/api/cloudflare/test` | Test Cloudflare token |

## API Examples

Log in:

```bash
curl -c jar.txt -X POST http://127.0.0.1:54/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "your-genpass-password"}'
```

Add a blocked domain:

```bash
curl -b jar.txt -X POST http://127.0.0.1:54/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.example.com"}'
```

Bulk import blocklist content:

```bash
curl -b jar.txt -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"content": "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com"}'
```

## HTTPS Setup Via API

```bash
curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "domain", "value": "dns.example.com"}'

curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "acme_email", "value": "admin@example.com"}'

curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "cloudflare_api_token", "value": "your-token-here"}'

curl -b jar.txt -X POST http://127.0.0.1:54/api/cloudflare/test \
  -H "Content-Type: application/json" \
  -d '{"api_token": "your-token-here"}'

curl -b jar.txt -X POST http://127.0.0.1:54/api/acme/request \
  -H "Content-Type: application/json" \
  -d '{"domain": "dns.example.com", "wildcard": false}'

curl -b jar.txt http://127.0.0.1:54/api/acme/status
```

## Replica Sync Setup Via API

```bash
curl -b jar.txt -X PUT http://192.168.1.2:54/api/sync/config \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "master_url": "http://192.168.1.1:54",
    "password": "<master-admin-password>",
    "interval_secs": 30
  }'

curl -b jar.txt http://192.168.1.2:54/api/sync/config
```

Restart the replica for the setting to take effect.

## Auto-Update Sources

RustBlocker can fetch and update blocklists or allowlists from URLs on a schedule.

Add a source from the Web UI **Sources** tab, or via API:

```bash
curl -b jar.txt -X POST http://127.0.0.1:54/api/sources \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "list_type": "blocklist", "update_interval_hours": 24}'
```

Refresh all sources:

```bash
curl -b jar.txt -X POST http://127.0.0.1:54/api/sources/refresh
```

## URL Import

One-time URL import without saving a recurring source:

```bash
curl -b jar.txt -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'
```

## Blocklist Format

```text
# Plain domain
ads.example.com

# Wildcard, matches subdomains but not the bare domain
*.tracking.example.com

# Hosts file format, leading IP is stripped
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
```

## Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_address` | `0.0.0.0` | Bind address |
| `listen_port` | `53` | DNS listen port |
| `sinkhole_ipv4` | `0.0.0.0` | IPv4 for blocked domains |
| `sinkhole_ipv6` | `::` | IPv6 for blocked domains |
| `log_level` | `info` | Log level |
| `upstream_timeout_secs` | `5` | Upstream timeout |
| `allowed_networks` | empty | CIDR ACL |
| `domain` | empty | HTTPS certificate domain |
| `acme_email` | empty | Let's Encrypt contact email |
| `cloudflare_api_token` | empty | Cloudflare token |
| `wildcard_cert` | `false` | Wildcard certificate flag |
| `acme_directory_url` | Let's Encrypt production | ACME directory override |

## Deploy On Alpine Linux

Install:

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

Build directly on Alpine:

```bash
apk add rust cargo musl-dev
git clone https://github.com/shabilullah/rustblocker.git
cd rustblocker
cargo build --release
sudo ./scripts/install.sh
```

## Agent Mock Deploy Test

`scripts/mock-deploy.sh` is the agent-friendly end-to-end test for a designated deploy machine.

```bash
cp scripts/.deployenv.example scripts/.deployenv
# Fill SSH_HOST, SSH_USER, SSH_PASSWORD, WEBUI_PASSWORD, DOMAIN, ACME_EMAIL, and CF_TOKEN.

bash scripts/mock-deploy.sh --timeout=45
```

Useful options:

```bash
bash scripts/mock-deploy.sh --skip-build
bash scripts/mock-deploy.sh --skip-deploy
FORCE_ACME=true bash scripts/mock-deploy.sh --timeout=45
ACME_POLL_ATTEMPTS=30 bash scripts/mock-deploy.sh --timeout=45
```

## Docker Multi-Stage Build

```dockerfile
FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.20
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rustblocker /usr/local/bin/
EXPOSE 53/udp 53/tcp 54/tcp
CMD ["rustblocker"]
```

## Deployment Layout

```text
/usr/local/bin/
└── rustblocker              # wrapper script
/usr/local/lib/rustblocker/
└── rustblocker              # real binary
/var/lib/rustblocker/
└── rustblocker.db           # service database
/var/log/
└── rustblocker.log
```

## Architecture

```text
DNS Request
     |
     v
 RequestHandler
     |
     |- Rewrite match?  -> Return custom IP
     |- Allowlist?      -> Skip blocklist
     |- Blocklist?      -> Return sinkhole IP
     `- Forward         -> Race upstream resolvers

Web UI + API
     |
     |- SQLite database
     |- Hot-reload stores
     |- Activity SSE stream
     `- Embedded static UI

HTTPS
     |
     |- ACME client
     |- Cloudflare DNS-01
     |- rustls server config
     `- Auto-renewal every 24h, 7-day threshold

Replica Sync
     |
     |- Login to master
     |- Fetch manifest hashes
     |- Fetch changed snapshots
     `- Apply changed categories
```

## License

MIT OR Apache-2.0
