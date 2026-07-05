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
- **Auto-update sources** — add blocklist URLs, set update interval, automatic refresh on schedule
- **URL import** — import blocklists from URLs via web UI or API
- **Hosts file format** — auto-strips `0.0.0.0` / `127.0.0.1` prefixes

## Quick Start

**One-line install (Alpine, Ubuntu, Debian, any Linux):**

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

This installs the binary, sets up a system service (OpenRC or systemd), and starts it. Re-run to update.

**Uninstall:**

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash -s -- --uninstall
```

This stops the service, removes the binary, database, service file, and logs.


**Or build from source:**

```bash
cargo build --release
sudo ./target/release/rustblocker
```

The server starts with sensible defaults:
- DNS on `127.0.0.1:53`
- Web UI on `http://127.0.0.1:54`
- Upstream: Google DNS (`8.8.8.8:53`)
- Sinkhole: `0.0.0.0` (IPv4) / `::` (IPv6)

Open the web UI in your browser to configure everything. All settings are stored in `rustblocker.db` (created automatically).

Port 53 requires elevated privileges — use `sudo` or run as root.

**CLI options:**
```bash
rustblocker                               # Default: DNS 53, web 54
rustblocker --dns-port 5353 --web-port 8080   # Custom ports (useful for local dev)
```

## Web Management UI

Available at `http://<listen_address>:<listen_port + 1>` (default: `http://127.0.0.1:54`).

- **Dashboard** — stats for blocked/allowed domains, rewrites, upstream servers, auto-update sources
- **Upstreams** — add/remove upstream DNS servers
- **Sources** — manage auto-update blocklist/allowlist URLs with configurable refresh intervals
- **Blocklist** — add, remove, bulk import, search/paginate blocked domains; import from URL
- **Allowlist** — add, remove, bulk import, search/paginate allowed domains; import from URL
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
| `GET` | `/api/blocklist` | List blocked domains (paginated, searchable) |
| `POST` | `/api/blocklist` | Add blocked domain |
| `DELETE` | `/api/blocklist/{id}` | Remove blocked domain |
| `POST` | `/api/blocklist/import` | Bulk import blocklist (from content or URL) |
| `GET` | `/api/allowlist` | List allowed domains (paginated, searchable) |
| `POST` | `/api/allowlist` | Add allowed domain |
| `DELETE` | `/api/allowlist/{id}` | Remove allowed domain |
| `POST` | `/api/allowlist/import` | Bulk import allowlist (from content or URL) |
| `GET` | `/api/rewrites` | List DNS rewrites |
| `POST` | `/api/rewrites` | Add DNS rewrite |
| `DELETE` | `/api/rewrites/{id}` | Remove DNS rewrite |
| `GET` | `/api/sources` | List auto-update sources |
| `POST` | `/api/sources` | Add source (immediately fetches) |
| `DELETE` | `/api/sources/{id}` | Remove source |
| `POST` | `/api/sources/refresh` | Refresh all sources now |

### Example API usage

```bash
# Check health
curl http://127.0.0.1:54/api/health

# Add a blocked domain
curl -X POST http://127.0.0.1:54/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.example.com"}'

# Remove a blocked domain
curl -X DELETE http://127.0.0.1:54/api/blocklist/1

# Get all settings
curl http://127.0.0.1:54/api/settings

# Bulk import a blocklist file
curl -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"content": "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com"}'
```

## Auto-Update Sources

RustBlocker can automatically fetch and update blocklists from URLs on a schedule. Manage sources via the **Sources** tab in the web UI.

**Adding a source:**
1. Go to the Sources tab
2. Paste a URL (e.g., `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`)
3. Choose type: Blocklist or Allowlist
4. Set update interval (default: 24 hours)
5. Click "Add Source"

The server immediately fetches the URL and imports all domains. On subsequent runs, it auto-refreshes stale sources every 10 minutes.

**Manual refresh:** Click "Refresh All Now" on the Sources tab or Dashboard to immediately re-fetch all sources.

**API:**
```bash
# List sources
curl http://127.0.0.1:54/api/sources

# Add a source (immediately fetches)
curl -X POST http://127.0.0.1:54/api/sources \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "list_type": "blocklist", "update_interval_hours": 24}'

# Refresh all sources now
curl -X POST http://127.0.0.1:54/api/sources/refresh
```

## URL Import

Import blocklists directly from a URL without saving it as a source. Use the **Import URL** button on the Blocklist or Allowlist tab, or call the API:

```bash
curl -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'
```

This fetches the URL, parses all domains (including hosts-file format), and imports them. Use this for one-time imports; use Sources for recurring updates.


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
| `listen_port` | `53` | DNS listen port (web UI on port+1) |
| `sinkhole_ipv4` | `0.0.0.0` | IPv4 returned for blocked domains |
| `sinkhole_ipv6` | `::` | IPv6 returned for blocked domains |
| `log_level` | `info` | Log level (overridable via `RUST_LOG` env var) |
| `upstream_timeout_secs` | `5` | Timeout for upstream DNS queries |

## Deploy on Alpine Linux

### One-line install

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

### Cross-compile from your machine

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
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
EXPOSE 53/udp 53/tcp 54/tcp
CMD ["rustblocker"]
```

```bash
docker build -t rustblocker .
docker run -d --name rustblocker \
  -p 53:53/udp -p 53:53/tcp -p 54:54 \
  rustblocker
```

### Build directly on Alpine

```bash
apk add rust cargo musl-dev
git clone https://github.com/shabilullah/rustblocker.git && cd rustblocker
cargo build --release
cp target/release/rustblocker /usr/local/bin/
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
