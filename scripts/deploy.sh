#!/bin/bash
# Deploy RustBlocker to remote server
# Usage: ./deploy.sh <host> <user>
# Example: ./deploy.sh 192.168.0.4 dns2

set -e

HOST=${1:-192.168.0.4}
USER=${2:-dns2}
REMOTE_DIR="/home/${USER}/rustblocker"

echo "==> Building release binary..."
cargo build --release

echo "==> Creating remote directory..."
ssh "${USER}@${HOST}" "mkdir -p ${REMOTE_DIR}"

echo "==> Copying binary (self-contained, includes web UI)..."
scp target/release/rustblocker "${USER}@${HOST}:${REMOTE_DIR}/"

echo "==> Setting permissions..."
ssh "${USER}@${HOST}" "chmod +x ${REMOTE_DIR}/rustblocker"

echo "==> Testing binary..."
ssh "${USER}@${HOST}" "${REMOTE_DIR}/rustblocker --version"

echo ""
echo "==> Deploy complete! To test on the server:"
echo "    ssh ${USER}@${HOST}"
echo "    cd ${REMOTE_DIR}"
echo "    ./rustblocker --dns-port 5353 --web-port 8080 --https-port 8443"
echo ""
echo "    Then open http://${HOST}:8080 in your browser"
echo "    Go to HTTPS tab, configure settings, test connection, request cert"
