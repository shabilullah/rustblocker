#!/bin/sh
set -e

# RustBlocker installer and updater
# Usage: curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | bash

REPO="shabilullah/rustblocker"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/rustblocker"
SERVICE_NAME="rustblocker"
BINARY_NAME="rustblocker"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; exit 1; }

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root. Use: sudo sh install.sh"
    fi
}

# Detect system architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            TARGET="x86_64-unknown-linux-musl"
            ;;
        aarch64|arm64)
            TARGET="aarch64-unknown-linux-musl"
            ;;
        *)
            error "Unsupported architecture: $ARCH. Supported: x86_64, aarch64"
            ;;
    esac
    info "Detected architecture: $ARCH ($TARGET)"
}

# Detect OS
detect_os() {
    OS=$(uname -s)
    case "$OS" in
        Linux)
            ;;
        *)
            error "Unsupported OS: $OS. This script supports Linux only (Alpine, Debian, Ubuntu, etc.)"
            ;;
    esac

    # Check for musl
    if ldd --version 2>&1 | grep -q musl 2>/dev/null; then
        info "Detected musl libc"
    elif [ -f /etc/alpine-release ]; then
        info "Detected Alpine Linux"
    else
        warn "Non-musl system detected. The musl static binary will still work."
    fi
}

# Check for required tools
check_deps() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required tool '$cmd' not found. Install it first."
        fi
    done
}

# Get the latest release version from GitHub
get_latest_version() {
    VERSION=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest release version from GitHub"
    fi
    info "Latest version: $VERSION"
}

# Get installed version
get_installed_version() {
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        INSTALLED_VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null | awk '{print $2}' || echo "unknown")
        if [ "$INSTALLED_VERSION" = "unknown" ]; then
            # Binary exists but --version not supported, check via service
            INSTALLED_VERSION="installed"
        fi
    else
        INSTALLED_VERSION=""
    fi
}

# Download and install the binary
install_binary() {
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/rustblocker-$VERSION-$TARGET.tar.gz"
    TEMP_DIR=$(mktemp -d)

    info "Downloading $DOWNLOAD_URL ..."
    if ! curl -sSL -o "$TEMP_DIR/rustblocker.tar.gz" "$DOWNLOAD_URL"; then
        rm -rf "$TEMP_DIR"
        error "Download failed. Check if release $VERSION exists for $TARGET"
    fi

    info "Extracting..."
    tar xzf "$TEMP_DIR/rustblocker.tar.gz" -C "$TEMP_DIR"

    # Stop service if running
    stop_service 2>/dev/null || true

    info "Installing binary to $INSTALL_DIR/$BINARY_NAME"
    mv "$TEMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    rm -rf "$TEMP_DIR"
    info "Binary installed successfully"
}

# Create data directory
setup_data_dir() {
    if [ ! -d "$DATA_DIR" ]; then
        mkdir -p "$DATA_DIR"
        info "Created data directory: $DATA_DIR"
    fi
}

# Detect init system and create service
setup_service() {
    if [ -d /etc/openrc ]; then
        setup_openrc
    elif [ -d /etc/systemd ]; then
        setup_systemd
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
command_background=true
pidfile="/run/rustblocker.pid"
output_log="/var/log/rustblocker.log"
error_log="/var/log/rustblocker.log"

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
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    info "systemd service created and enabled"
}

# Start the service
start_service() {
    if [ -d /etc/openrc ]; then
        rc-service "$SERVICE_NAME" start 2>/dev/null || true
        info "Service started via OpenRC"
    elif [ -d /etc/systemd ]; then
        systemctl start "$SERVICE_NAME" 2>/dev/null || true
        info "Service started via systemd"
    fi
}

# Stop the service
stop_service() {
    if [ -d /etc/openrc ]; then
        rc-service "$SERVICE_NAME" stop 2>/dev/null || true
    elif [ -d /etc/systemd ]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "============================================"
    echo "  RustBlocker $VERSION installed successfully!"
    echo "============================================"
    echo ""
    echo "  DNS port:  53"
    echo "  Web UI:    http://127.0.0.1:54"
    echo "  Data:      $DATA_DIR/rustblocker.db"
    echo "  Binary:    $INSTALL_DIR/$BINARY_NAME"
    echo ""
    echo "  Manage via web UI or API:"
    echo "    curl http://127.0.0.1:54/api/health"
    echo ""
    echo "  CLI options:"
    echo "    rustblocker --dns-port 5353 --web-port 8080"
    echo ""
    echo "  Re-run this script to update to the latest version."
    echo "============================================"
}

# Main
main() {
    echo ""
    echo "  RustBlocker Installer"
    echo "  https://github.com/$REPO"
    echo ""

    check_root
    detect_arch
    detect_os
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
