# RustBlocker

A DNS blocker written in Rust — similar to Pi-hole but simpler. It intercepts DNS queries, applies blocklist/allowlist/rewrite rules, and forwards unblocked queries to upstream resolvers.

## Features

- **Blocklist** — block domains by exact match or wildcard (`*.example.com`)
- **Allowlist** — bypass blocklist for specific domains
- **DNS Rewrite** — return custom IPs for specific domains (local DNS overrides)
- **Parallel Forwarding** — races queries across multiple upstream resolvers, uses the first response
- **UDP + TCP** — listens on both protocols simultaneously
- **Web Management UI** — manage all settings from a browser (TailwindCSS, dark theme)
- **REST API** — full CRUD for blocklists, allowlists, rewrites, settings, and upstreams
- **SQLite database** — portable single-file storage, zero-config startup
- **Hot-reload** — blocklist/allowlist/rewrite changes via web UI take effect immediately
- **URL blocklists** — fetch remote blocklists from URLs via the API
- **Hosts file format** — auto-strips `0.0.0.0` / `127.0.0.1` prefixes

## Quick Start

```bash
# Build
cargo build --release

# Run — just start it, no config files needed
./target/release/rustblocker
```

The server starts with sensible defaults:
- DNS on `127.0.0.1:5353`
- Web UI on `http://127.0.0.1:5354`
- Upstream: Google DNS (`8.8.8.8:53`)
- Sinkhole: `0.0.0.0` (IPv4) / `::` (IPv6)

Open the web UI in your browser to configure everything. All settings are stored in `rustblocker.db` (created automatically).

Port 53 requires elevated privileges — use `sudo` or run as root.

## Web Management UI

Available at `http://<listen_address>:<listen_port + 1>` (default: `http://127.0.0.1:5354`).

- **Dashboard** — stats for blocked/allowed domains, rewrites, upstream servers
- **Blocklist** — add, remove, bulk import blocked domains
- **Allowlist** — add, remove, bulk import allowed domains
- **Rewrites** — manage DNS rewrite rules (domain → custom IP)
- **Settings** — configure listen address, port, sinkhole IPs, upstream timeout
- **Theme** — dark mode with TailwindCSS

Changes to blocklist, allowlist, and rewrites take effect **immediately**. Changes to settings (listen address, port, sinkhole IPs) require a restart.

## SQLite Database

RustBlocker uses SQLite (`rustblocker.db`) for all configuration:

- **Created automatically** on first run with sensible defaults
- **No config files needed** — everything is managed via web UI or API
- **Stores**: settings, upstream servers, blocklist domains, allowlist domains, rewrite rules
- **Portable**: copy `rustblocker.db` to migrate all configuration

## REST API

All configuration is accessible via a REST API at `http://<listen_address>:<listen_port + 1>/api`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/settings` | Get all settings |
| `PUT` | `/api/settings` | Update a setting |
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

### Example API usage

```bash
# Check health
curl http://127.0.0.1:5354/api/health

# Add a blocked domain
curl -X POST http://127.0.0.1:5354/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.example.com"}'

# Remove a blocked domain
curl -X DELETE http://127.0.0.1:5354/api/blocklist/1

# Get all settings
curl http://127.0.0.1:5354/api/settings

# Bulk import a blocklist file
curl -X POST http://127.0.0.1:5354/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"content": "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com"}'
```

## Blocklist Format

One entry per line. Lines starting with `#` are comments. Supports three formats:

```
# Plain domain
ads.example.com

# Wildcard — matches sub.example.com, sub.sub.example.com
# but NOT example.com itself
*.tracking.example.com

# Hosts file format (leading IP is stripped)
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
```

## Hot-Reload

Changes made via the web UI or API take effect **immediately** for:
- **Blocklist domains** — blocked/allowed instantly
- **Allowlist domains** — bypasses applied instantly
- **DNS rewrites** — new IPs served instantly

Changes to **settings** (listen address, port, sinkhole IPs, upstream timeout) require a server restart.

## Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_address` | `127.0.0.1` | Bind address |
| `listen_port` | `5353` | DNS listen port (web UI on port+1) |
| `sinkhole_ipv4` | `0.0.0.0` | IPv4 returned for blocked domains |
| `sinkhole_ipv6` | `::` | IPv6 returned for blocked domains |
| `log_level` | `info` | Log level (overridable via `RUST_LOG` env var) |
| `upstream_timeout_secs` | `5` | Timeout for upstream DNS queries |

## Deploy on Alpine Linux

### Cross-compile from your machine

```bash
# Install the musl target (Alpine uses musl libc)
rustup target add x86_64-unknown-linux-musl

# Build a fully static binary
cargo build --release --target x86_64-unknown-linux-musl

# Copy to Alpine — no runtime dependencies needed
scp target/x86_64-unknown-linux-musl/release/rustblocker user@alpine:/usr/local/bin/
```

### Docker multi-stage build

```dockerfile
FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.20
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rustblocker /usr/local/bin/
EXPOSE 53/udp 53/tcp 5354/tcp
CMD ["rustblocker"]
```

```bash
docker build -t rustblocker .
docker run -d --name rustblocker \
  -p 53:53/udp -p 53:53/tcp -p 5354:5354 \
  rustblocker
```

### Build directly on Alpine

```bash
apk add rust cargo musl-dev
git clone <repo-url> && cd rustblocker
cargo build --release
cp target/release/rustblocker /usr/local/bin/
```

### Run as an OpenRC service

Create `/etc/init.d/rustblocker`:

```bash
#!/sbin/openrc-run

name="rustblocker"
description="DNS Blocker"
command="/usr/local/bin/rustblocker"
command_background=true
pidfile="/run/rustblocker.pid"
output_log="/var/log/rustblocker.log"
error_log="/var/log/rustblocker.log"

depend() {
    need net
    after firewall
}
```

```bash
chmod +x /etc/init.d/rustblocker
rc-update add rustblocker default
rc-service rustblocker start
```

### Run as a systemd service

Create `/etc/systemd/system/rustblocker.service`:

```ini
[Unit]
Description=RustBlocker DNS Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rustblocker
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now rustblocker
```

### Deployment directory layout

```
/usr/local/bin/
└── rustblocker
/var/lib/rustblocker/
└── rustblocker.db          (created automatically on first run)
/var/log/
└── rustblocker.log
```

### DNS client configuration

Point your clients or `/etc/resolv.conf` to the RustBlocker server:

```
nameserver 127.0.0.1
```

## Testing

```bash
cargo test
```

## Architecture

```
DNS Request
     │
     ▼
 RequestHandler (handler.rs)
     │
     ├─ 1. Rewrite match?  → Return custom IP
     ├─ 2. Allowlist match? → Skip blocklist
     ├─ 3. Blocklist match? → Return sinkhole IP
     └─ 4. Forward         → Race upstream resolvers

Web UI + API (actix-web on port+1)
     │
     ├─ SQLite database (rustblocker.db)
     ├─ Hot-reload Arc<RwLock<>> stores
     └─ Changes take effect immediately
```

## License

MIT OR Apache-2.0
