#!/bin/sh
set -e

# RustBlocker installer, updater, and uninstaller
# Install:  curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
# Uninstall: curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash -s -- --uninstall

REPO="shabilullah/rustblocker"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/rustblocker"
SERVICE_NAME="rustblocker"
BINARY_NAME="rustblocker"
LOG_FILE="/var/log/rustblocker.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; exit 1; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root. Use: sudo sh install.sh"
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
        aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
        *) error "Unsupported architecture: $ARCH. Supported: x86_64, aarch64" ;;
    esac
    info "Detected architecture: $ARCH ($TARGET)"
}

check_deps() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required tool '$cmd' not found. Install it first."
        fi
    done
}

get_latest_version() {
    VERSION=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest release version from GitHub"
    fi
    info "Latest version: $VERSION"
}

get_installed_version() {
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        INSTALLED_VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null | awk '{print $2}' || echo "installed")
    else
        INSTALLED_VERSION=""
    fi
}

install_binary() {
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/rustblocker-$VERSION-$TARGET.tar.gz"
    TEMP_DIR=$(mktemp -d)

    info "Downloading $DOWNLOAD_URL ..."
    if ! curl -fSL --retry 3 --retry-delay 5 -o "$TEMP_DIR/rustblocker.tar.gz" "$DOWNLOAD_URL"; then
        rm -rf "$TEMP_DIR"
        error "Download failed. Check if release $VERSION exists for $TARGET"
    fi

    info "Extracting..."
    tar xzf "$TEMP_DIR/rustblocker.tar.gz" -C "$TEMP_DIR"

    stop_service 2>/dev/null || true

    info "Installing binary to $INSTALL_DIR/$BINARY_NAME"
    mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    rm -rf "$TEMP_DIR"
    info "Binary installed successfully"
}

setup_data_dir() {
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
        info "Created data directory: $DATA_DIR"
    fi
    # Migrate DB and WAL/SHM from old location (working directory was /) to DATA_DIR.
    if [ -f /rustblocker.db ] && [ ! -f "$DATA_DIR/rustblocker.db" ]; then
        for f in /rustblocker.db /rustblocker.db-wal /rustblocker.db-shm; do
            [ -f "$f" ] && mv "$f" "$DATA_DIR/"
        done
        info "Migrated existing database to $DATA_DIR/"
    fi
}

setup_service() {
    if [ -d /run/systemd/system ]; then
        setup_systemd
    elif command -v openrc-run >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
        setup_openrc
    else
        warn "No supported init system detected. Run '$INSTALL_DIR/$BINARY_NAME' manually."
    fi
}

setup_openrc() {
    INIT_SCRIPT="/etc/init.d/$SERVICE_NAME"
    info "Setting up OpenRC service..."

    cat > "$INIT_SCRIPT" << 'INITEOF'
#!/sbin/openrc-run

name="rustblocker"
description="RustBlocker DNS Blocker"
command="/usr/local/bin/rustblocker"
command_args="--dns-port 53"
pidfile="/run/rustblocker.pid"
output_log="/var/log/rustblocker.log"
error_log="/var/log/rustblocker.log"

start() {
    cd /var/lib/rustblocker || return 1
    start-stop-daemon --start --background --make-pidfile \
        --pidfile "$pidfile" \
        --exec "$command" -- $command_args
}

depend() {
    need net
    after firewall
}
INITEOF

    chmod +x "$INIT_SCRIPT"
    rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
    info "OpenRC service created and enabled"
}

setup_systemd() {
    SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
    info "Setting up systemd service..."

    cat > "$SERVICE_FILE" << 'SERVICEEOF'
[Unit]
Description=RustBlocker DNS Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rustblocker --dns-port 53
WorkingDirectory=/var/lib/rustblocker
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    info "systemd service created and enabled"
}

start_service() {
    if [ -d /run/systemd/system ]; then
        systemctl start "$SERVICE_NAME" 2>/dev/null || true
        info "Service started via systemd"
    elif command -v openrc-run >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
        rc-service "$SERVICE_NAME" start 2>/dev/null || true
        info "Service started via OpenRC"
    fi
}

stop_service() {
    if [ -d /run/systemd/system ]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    elif command -v openrc-run >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
        rc-service "$SERVICE_NAME" stop 2>/dev/null || true
    fi
}

# --- Uninstall ---

uninstall() {
    check_root

    info "Stopping RustBlocker service..."
    stop_service || true

    # Remove service files
    if [ -d /run/systemd/system ]; then
        if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
            systemctl disable "$SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/systemd/system/$SERVICE_NAME.service"
            systemctl daemon-reload 2>/dev/null || true
            info "Removed systemd service"
        fi
    elif command -v openrc-run >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
        if [ -f "/etc/init.d/$SERVICE_NAME" ]; then
            rc-update del "$SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/init.d/$SERVICE_NAME"
            info "Removed OpenRC service"
        fi
    fi

    # Remove binary
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        rm -f "$INSTALL_DIR/$BINARY_NAME"
        info "Removed binary: $INSTALL_DIR/$BINARY_NAME"
    else
        warn "Binary not found at $INSTALL_DIR/$BINARY_NAME"
    fi

    # Remove data directory
    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"
        info "Removed data directory: $DATA_DIR"
    else
        warn "Data directory not found at $DATA_DIR"
    fi

    # Clean up DB and WAL/SHM from old location (working directory was / before v2)
    for f in /rustblocker.db /rustblocker.db-wal /rustblocker.db-shm; do
        if [ -f "$f" ]; then
            rm -f "$f"
            info "Removed old database file: $f"
        fi
    done

    # Remove compiled blocklist files (may be in working dir)
    for f in compiled-blocklist.txt compiled-allowlist.txt; do
        if [ -f "$f" ]; then
            rm -f "$f"
            info "Removed $f"
        fi
    done

    # Remove log file
    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
        info "Removed log file: $LOG_FILE"
    fi

    echo ""
    echo "============================================"
    echo "  RustBlocker has been completely removed."
    echo "============================================"
    echo ""
    echo "  Removed:"
    echo "    - Binary:     $INSTALL_DIR/$BINARY_NAME"
    echo "    - Database:   $DATA_DIR/rustblocker.db"
    echo "    - Service:    $SERVICE_NAME"
    echo "    - Logs:       $LOG_FILE"
    echo ""
    echo "  To reinstall, run the install script again."
    echo "============================================"
}

print_summary() {
    # Detect LAN IP for remote access hint
    LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$LAN_IP" ] && LAN_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{sub(/\/.*/, "", $2); print $2; exit}')
    [ -z "$LAN_IP" ] && LAN_IP="<server-ip>"

    echo ""
    echo "============================================"
    echo "  RustBlocker $VERSION installed successfully!"
    echo "============================================"
    echo ""
    echo "  DNS port:  53"
    echo "  Web UI:    http://${LAN_IP}:54"
    echo "  Data:      $DATA_DIR/rustblocker.db"
    echo "  Binary:    $INSTALL_DIR/$BINARY_NAME"
    echo ""
    echo "  Manage via web UI or API:"
    echo "    curl http://${LAN_IP}:54/api/health"
    echo ""
    echo "  CLI options:"
    echo "    rustblocker --dns-port 5353 --web-port 8080"
    echo ""
    echo "  Uninstall:"
    echo "    curl -sSL https://raw.githubusercontent.com/$REPO/main/scripts/install.sh | sudo bash -s -- --uninstall"
    echo "============================================"
}

# Main
main() {
    # Check for --uninstall flag
    for arg in "$@"; do
        case "$arg" in
            --uninstall)
                uninstall
                exit 0
                ;;
        esac
    done

    echo ""
    echo "  RustBlocker Installer"
    echo "  https://github.com/$REPO"
    echo ""

    check_root
    detect_arch
    check_deps
    get_latest_version
    get_installed_version

    if [ -n "$INSTALLED_VERSION" ]; then
        info "Currently installed: $INSTALLED_VERSION"
        if [ "$INSTALLED_VERSION" = "$VERSION" ]; then
            info "Already up to date!"
            exit 0
        fi
        info "Updating from $INSTALLED_VERSION to $VERSION..."
    else
        info "Fresh install..."
    fi

    install_binary
    setup_data_dir
    setup_service
    start_service
    print_summary
}

main "$@"
