# RustBlocker

A DNS blocker written in Rust, similar to Pi-hole but simpler. It intercepts DNS queries, applies blocklist, allowlist, and rewrite rules, then forwards unblocked queries to upstream resolvers.

For build, test, REST API, SQLite, architecture, source import, and API setup details, see [TECHNICAL.md](TECHNICAL.md).

## Installation Quick Start

Tested platform: Alpine Linux `x86_64` only.

One-line install for Alpine, Ubuntu, Debian, and other Linux systems:

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

This installs the binary, sets up an OpenRC or systemd service, and starts RustBlocker. Re-run the same command to update.

Uninstall:

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash -s -- --uninstall
```

Defaults after installation:

- DNS listens on `0.0.0.0:53`
- Web UI listens on `http://<server-ip>:54`
- HTTPS listens on `https://<domain>` automatically after a valid certificate exists
- Default upstream is Google DNS (`8.8.8.8:53`)
- SQLite database lives at `/var/lib/rustblocker/rustblocker.db`

Generate or reset the Web UI admin password:

```bash
sudo rustblocker --genpass
```

Open the Web UI, log in with the generated password, then configure upstreams, lists, sync, HTTPS, and access control.

## CLI Options

```bash
rustblocker                                      # Default: DNS 53, web 54
rustblocker --dns-port 5353 --web-port 8080      # Custom ports
sudo rustblocker --genpass                       # Generate/reset admin password
rustblocker --genpass --db-path /path/to/db      # Use an explicit database path
rustblocker --https-port 8443                    # Custom HTTPS port when a valid cert exists
rustblocker --force-http                         # Force HTTP-only even if HTTPS is configured
```

`--genpass` auto-detects the service database at `/var/lib/rustblocker/rustblocker.db` when it exists. When run as root, it restarts the `rustblocker` service so existing Web UI sessions are invalidated immediately.

Replica sync CLI overrides:

```bash
rustblocker --sync-master http://192.168.1.1:54 \
             --sync-password <master-admin-password> \
             --sync-interval 30
```

CLI flags take precedence over the stored database config.

## Replica Sync

RustBlocker supports a master/replica setup where a second instance mirrors configuration from a primary instance. The replica polls the master and only fetches categories whose content hash changed, so large blocklists are not re-downloaded unnecessarily.

### Setup

On the replica instance:

1. Open the Web UI.
2. Go to **Settings** -> **Sync (Replica Mode)**.
3. Enable sync.
4. Enter the master URL, for example `http://192.168.1.1:54`.
5. Enter the master's admin password.
6. Set the poll interval, default `30` seconds.
7. Save and restart when prompted.

After restart, the replica begins syncing. The password is stored locally in the replica SQLite database and is never returned by the API.

### What Syncs

| Category | Synced | Notes |
|----------|--------|-------|
| Blocklist | Yes | Full replace on change |
| Allowlist | Yes | Full replace on change |
| Rewrites | Yes | Full replace on change |
| Upstreams | Yes | Hot-reloads forwarder |
| Sources | Yes | URL list only, not fetched domain contents |
| Settings | Partial | Node-local settings are preserved |
| Listen address / port | No | Replica keeps its own |
| Allowed networks | No | Replica keeps its own |
| Admin password | No | Never synced |
| HTTPS certificate settings | No | Each node keeps its own domain, token, and certificate |

Settings that could lock out the replica admin or compromise credentials are never overwritten by sync.

## HTTPS & ACME

RustBlocker supports automatic HTTPS via Let's Encrypt using ACME DNS-01 challenges through Cloudflare. Certificates are stored in SQLite and auto-renewed when 7 days or less remain.

### Prerequisites

- A domain managed by Cloudflare, for example `dns.example.com`
- A Cloudflare API token with `Zone.DNS: Edit`
- An email address for Let's Encrypt notifications

### Setup

1. Open the Web UI.
2. Go to the **HTTPS** tab.
3. Enter the domain.
4. Enter the ACME email.
5. Enter the Cloudflare API token.
6. Click **Test Connection**.
7. Optionally enable a wildcard certificate.
8. Click **Save Settings**.
9. Click **Request Certificate**.

Real-time progress appears in the Activity Log. After the certificate is verified and stored, RustBlocker automatically restarts so the supervised service comes back with HTTPS enabled.

### Runtime Behavior

By default, RustBlocker starts HTTP and then checks for a valid stored certificate. If a valid certificate exists, it also binds HTTPS on port `443`. No `--https` flag is required.

Use `--https-port` to choose a different HTTPS port, or `--force-http` to disable HTTPS even when a certificate exists.

### Auto-Renewal

A background task checks every 24 hours for certificates expiring within 7 days and renews them automatically. The HTTPS tab shows whether auto-renewal is enabled, the check interval, and the renewal threshold.

### HTTPS Settings

| Setting | Description |
|---------|-------------|
| `domain` | Primary domain for the certificate |
| `acme_email` | Contact email for Let's Encrypt |
| `cloudflare_api_token` | Cloudflare API token with `Zone.DNS:Edit` permission |
| `wildcard_cert` | Request `*.domain.com + domain.com` when enabled |
| `acme_directory_url` | Optional Let's Encrypt directory URL override |

## Network Access Control

RustBlocker has two layers of network access control:

| Setting | Controls | Default |
|---------|----------|---------|
| `listen_address` | OS-level bind restriction | `0.0.0.0` |
| `allowed_networks` | Application-level ACL | empty, allow all |

Both layers must allow a client for the request to succeed.

| `listen_address` | `allowed_networks` | Result |
|---|---|---|
| `127.0.0.1` | empty | Only localhost |
| `0.0.0.0` | empty | Anyone on the network |
| `0.0.0.0` | `192.168.0.0/24` | Binds everywhere, rejects non-matching clients |
| `127.0.0.1` | `192.168.0.0/24` | Only localhost, ACL is effectively irrelevant |

The ACL applies to both DNS and Web UI requests. It is independent of the admin password: `allowed_networks` controls which client IPs may connect, while the password controls Web UI access after connecting.

Set `allowed_networks` from the Web UI **Settings** tab. Changes take effect immediately.

## License

RustBlocker is licensed under the [MIT License](LICENSE).
