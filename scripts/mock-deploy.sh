#!/bin/bash
# RustBlocker deploy + mock test — agent-friendly mode.
# Sources .deployenv for credentials (gitignored). See .deployenv.example.
# Outputs JSON-lines: {"step":N,"name":"...","status":"ok|fail|skip","detail":"..."}
# Exit 0 = all steps pass, non-zero = at least one failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOYENV="$SCRIPT_DIR/.deployenv"
SKIP_BUILD=false
SKIP_DEPLOY=false
TIMEOUT=30
ACME_POLL_ATTEMPTS="${ACME_POLL_ATTEMPTS:-30}"

for arg in "$@"; do
    case "$arg" in
        --skip-build)  SKIP_BUILD=true ;;
        --skip-deploy) SKIP_DEPLOY=true ;;
        --timeout=*)   TIMEOUT="${arg#*=}" ;;
        *) echo "Unknown arg: $arg"; exit 2 ;;
    esac
done

# --- Helpers ---
ok()   { printf '{"step":%s,"name":"%s","status":"ok","detail":"%s"}\n' "$1" "$2" "$3"; }
fail() { printf '{"step":%s,"name":"%s","status":"fail","detail":"%s"}\n' "$1" "$2" "$3"; FAILED=1; }
skip() { printf '{"step":%s,"name":"%s","status":"skip","detail":"%s"}\n' "$1" "$2" "$3"; }
shell_quote() { printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"; }
FAILED=0
STEP=0
step() { STEP=$((STEP+1)); }

# --- Load credentials ---
if [ ! -f "$DEPLOYENV" ]; then
    fail 0 "env" ".deployenv not found at $DEPLOYENV"
    echo "Create it from .deployenv.example and fill in your credentials."
    exit 1
fi
source "$DEPLOYENV"

: "${SSH_HOST:?}" "${SSH_USER:?}" "${SSH_PASSWORD:?}" "${WEBUI_PASSWORD:?}"
BINARY_NAME="rustblocker"
REMOTE_INSTALL_DIR="/usr/local/lib/rustblocker"
WEB_PORT="${WEB_PORT:-54}"
BASE_URL="http://${SSH_HOST}:${WEB_PORT}"

# SSH setup: prefer sshpass, fall back to SSH_ASKPASS (askpass.sh)
export SSHPASS="$SSH_PASSWORD"
if command -v sshpass &>/dev/null; then
    SSH=(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(sshpass -e scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
elif [ -f "$SCRIPT_DIR/../askpass.bat" ]; then
    export SSH_ASKPASS="$SCRIPT_DIR/../askpass.bat"
    export DISPLAY=dummy
    export SSH_ASKPASS_REQUIRE=force
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
elif [ -f "$SCRIPT_DIR/../askpass.sh" ]; then
    export SSH_ASKPASS="$SCRIPT_DIR/../askpass.sh"
    export DISPLAY=dummy
    export SSH_ASKPASS_REQUIRE=force
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
else
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
fi
REMOTE="${SSH_USER}@${SSH_HOST}"
CURL=(curl -s --connect-timeout 5 --max-time "$TIMEOUT")

remote_root() {
    local command="$1"
    local quoted_command quoted_password
    quoted_command=$(shell_quote "$command")
    quoted_password=$(shell_quote "$SSH_PASSWORD")
    "${SSH[@]}" "$REMOTE" "if [ \"\$(id -u)\" -eq 0 ]; then sh -c $quoted_command; elif command -v sudo >/dev/null 2>&1; then printf '%s\n' $quoted_password | sudo -S sh -c $quoted_command; elif command -v doas >/dev/null 2>&1; then printf '%s\n' $quoted_password | doas sh -c $quoted_command; else echo 'root privileges required: install sudo/doas or deploy as root' >&2; exit 1; fi"
}

ensure_remote_service_defaults() {
    remote_root "if [ -f /etc/init.d/rustblocker ]; then sed -i 's#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443\"#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db\"#' /etc/init.d/rustblocker; elif [ -f /etc/systemd/system/rustblocker.service ]; then sed -i 's#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db#' /etc/systemd/system/rustblocker.service; systemctl daemon-reload 2>/dev/null || true; fi"
}

REMOTE_ARCH=$("${SSH[@]}" "$REMOTE" "uname -m" 2>/dev/null || true)
case "$REMOTE_ARCH" in
    x86_64|amd64) DEPLOY_TARGET="${DEPLOY_TARGET:-x86_64-unknown-linux-musl}" ;;
    aarch64|arm64) DEPLOY_TARGET="${DEPLOY_TARGET:-aarch64-unknown-linux-musl}" ;;
    *)
        fail 0 "target" "unsupported or unknown remote architecture: ${REMOTE_ARCH:-unknown}"
        exit 1
        ;;
esac
BINARY_PATH="target/${DEPLOY_TARGET}/release/${BINARY_NAME}"

# --- Deploy ---
if [ "$SKIP_BUILD" != true ]; then
    step; ok "$STEP" "build" "building release binary..."
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        BUILD_CMD=(cargo zigbuild --release --target "$DEPLOY_TARGET")
    else
        BUILD_CMD=(cargo build --release --target "$DEPLOY_TARGET")
    fi
    if ! "${BUILD_CMD[@]}" 2>&1; then
        fail "$STEP" "build" "cargo build failed"
        exit 1
    fi
    ok "$STEP" "build" "release binary built for $DEPLOY_TARGET"
else
    step; skip "$STEP" "build" "skipped"
fi

if [ ! -f "$BINARY_PATH" ]; then
    fail 0 "build" "missing binary: $BINARY_PATH"
    exit 1
fi

if [ "$SKIP_DEPLOY" != true ]; then
    step
    if remote_root "systemctl stop rustblocker 2>/dev/null || rc-service rustblocker stop 2>/dev/null || true"; then
        ok "$STEP" "deploy" "service stopped"
    else
        fail "$STEP" "deploy" "stop failed (non-fatal)"
    fi

    step
    REMOTE_TMP="/tmp/${BINARY_NAME}.$$"
    if "${SCP[@]}" "$BINARY_PATH" "${REMOTE}:${REMOTE_TMP}"; then
        ok "$STEP" "deploy" "binary uploaded"
    else
        fail "$STEP" "deploy" "scp failed"; exit 1
    fi

    step
    if remote_root "mkdir -p ${REMOTE_INSTALL_DIR} && cp ${REMOTE_TMP} ${REMOTE_INSTALL_DIR}/${BINARY_NAME} && chmod +x ${REMOTE_INSTALL_DIR}/${BINARY_NAME} && rm -f ${REMOTE_TMP}"; then
        ok "$STEP" "deploy" "binary installed"
    else
        fail "$STEP" "deploy" "install failed"; exit 1
    fi

    step
    if ensure_remote_service_defaults; then
        ok "$STEP" "deploy" "service configured for default HTTPS behavior"
    else
        fail "$STEP" "deploy" "failed to configure service defaults"; exit 1
    fi

    step
    if remote_root "systemctl start rustblocker 2>/dev/null || rc-service rustblocker start 2>/dev/null || true"; then
        ok "$STEP" "deploy" "service started"
    else
        fail "$STEP" "deploy" "start failed"; exit 1
    fi

    step
    HEALTHY=false
    for i in $(seq 1 10); do
        sleep 2
        if "${CURL[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null | grep -q '200'; then
            HEALTHY=true; break
        fi
    done
    if [ "$HEALTHY" = true ]; then
        ok "$STEP" "deploy" "health check passed (after $((i*2))s)"
    else
        fail "$STEP" "deploy" "health check failed — service did not start"
        "${SSH[@]}" "$REMOTE" "rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
    fi
else
    step; skip "$STEP" "deploy" "skipped"
fi

COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

# Step: Login
step
HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -c "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$WEBUI_PASSWORD\"}")
if [ "$HTTP_CODE" = "200" ]; then
    ok "$STEP" "login" "authenticated"
else
    fail "$STEP" "login" "HTTP $HTTP_CODE"
fi

# Step: Get current settings (sanity check)
step
SETTINGS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/settings")
if echo "$SETTINGS" | grep -q '"'; then
    ok "$STEP" "settings" "settings endpoint reachable"
else
    fail "$STEP" "settings" "could not read settings"
fi

# Step: Configure HTTPS settings (only if provided)
for pair in "domain=${DOMAIN:-}" "acme_email=${ACME_EMAIL:-}" "cloudflare_api_token=${CF_TOKEN:-}" "wildcard_cert=${WILDCARD:-false}"; do
    key="${pair%%=*}"
    value="${pair#*=}"
    if [ -z "$value" ]; then
        step; skip "$STEP" "configure" "$key not set"
        continue
    fi
    step
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X PUT "$BASE_URL/api/settings" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"$key\",\"value\":\"$value\"}")
    if [ "$HTTP_CODE" = "200" ]; then
        masked="${value}"
        [ ${#masked} -gt 20 ] && masked="${value:0:4}...${value: -4}"
        ok "$STEP" "configure" "$key = $masked"
    else
        fail "$STEP" "configure" "$key -> HTTP $HTTP_CODE"
    fi
done

# Step: Test Cloudflare connection
if [ -n "${CF_TOKEN:-}" ]; then
    step
    RESP=$("${CURL[@]}" -b "$COOKIE_JAR" -X POST "$BASE_URL/api/cloudflare/test" \
        -H "Content-Type: application/json" \
        -d "{\"api_token\":\"$CF_TOKEN\"}")
    if echo "$RESP" | grep -q '"ok":true'; then
        ok "$STEP" "cf-test" "token valid"
    else
        ERR=$(echo "$RESP" | grep -o '"error":"[^"]*"' | head -1 | cut -d'"' -f4)
        fail "$STEP" "cf-test" "${ERR:-invalid token}"
    fi
else
    step; skip "$STEP" "cf-test" "CF_TOKEN not set"
fi

# Step: Request certificate
if [ -n "${DOMAIN:-}" ]; then
    BEFORE_CERT_PID=$("${SSH[@]}" "$REMOTE" "pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1" 2>/dev/null || true)

    step
    RESP=$("${CURL[@]}" -b "$COOKIE_JAR" -X POST "$BASE_URL/api/acme/request" \
        -H "Content-Type: application/json" \
        -d "{\"domain\":\"$DOMAIN\",\"wildcard\":${WILDCARD:-false}}")
    OP_ID=$(echo "$RESP" | grep -o '"op_id":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$OP_ID" ]; then
        ok "$STEP" "acme-request" "accepted op_id=$OP_ID"
    else
        fail "$STEP" "acme-request" "request rejected"
        exit 1
    fi

    # Step: Poll for certificate (default max 30 attempts = 300s)
    step
    ok "$STEP" "acme-poll" "polling for certificate (op_id=$OP_ID)..."
    GOT_CERT=false
    POLL_FAILED=false
    for i in $(seq 1 "$ACME_POLL_ATTEMPTS"); do
        sleep 10
        STATUS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/acme/status")
        if echo "$STATUS" | grep -q '"has_certificate":true'; then
            DAYS=$(echo "$STATUS" | grep -o '"days_remaining":[0-9]*' | cut -d: -f2)
            ok "$STEP" "acme-poll" "certificate obtained (${DAYS:-?}d remaining) after $((i*10))s"
            GOT_CERT=true
            break
        fi
        if echo "$STATUS" | grep -q '"acme_error":"'; then
            ERR=$(echo "$STATUS" | sed -n 's/.*"acme_error":"\([^"]*\)".*/\1/p' | head -1)
            fail "$STEP" "acme-poll" "${ERR:-ACME request failed}"
            POLL_FAILED=true
            break
        fi
        # Log intermediate poll as info in detail
        ok "$STEP" "acme-poll" "still waiting ($((i*10))s)..." >&2
    done
    if [ "$GOT_CERT" != true ] && [ "$POLL_FAILED" != true ]; then
        fail "$STEP" "acme-poll" "timeout after $((ACME_POLL_ATTEMPTS*10))s — check Activity Log in web UI"
        "${SSH[@]}" "$REMOTE" "tail -n 120 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
    fi
    if [ "$GOT_CERT" = true ]; then
        step
        RESTARTED=false
        AFTER_CERT_PID=""
        for i in $(seq 1 20); do
            sleep 1
            AFTER_CERT_PID=$("${SSH[@]}" "$REMOTE" "pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1" 2>/dev/null || true)
            if [ -n "$BEFORE_CERT_PID" ] && [ -n "$AFTER_CERT_PID" ] && [ "$BEFORE_CERT_PID" != "$AFTER_CERT_PID" ]; then
                RESTARTED=true; break
            fi
        done
        if [ "$RESTARTED" = true ]; then
            ok "$STEP" "https" "automatic restart observed (${BEFORE_CERT_PID} -> ${AFTER_CERT_PID})"
        else
            fail "$STEP" "https" "automatic restart was not observed"
        fi

        step
        HTTPS_URL="https://${DOMAIN}/api/health"
        HTTPS_OK=false
        for i in $(seq 1 20); do
            sleep 2
            if "${CURL[@]}" -k -o /dev/null -w "%{http_code}" "$HTTPS_URL" 2>/dev/null | grep -q '200'; then
                HTTPS_OK=true; break
            fi
        done
        if [ "$HTTPS_OK" = true ]; then
            ok "$STEP" "https" "HTTPS health check passed after automatic restart (after $((i*2))s)"
        else
            fail "$STEP" "https" "HTTPS health check failed after automatic restart"
            "${SSH[@]}" "$REMOTE" "rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
        fi
    fi
else
    step; skip "$STEP" "acme" "DOMAIN not set"
fi

# --- Summary ---
echo ""
if [ "$FAILED" -eq 0 ]; then
    ok 99 "summary" "ALL STEPS PASSED"
else
    fail 99 "summary" "SOME STEPS FAILED — see above"
fi

exit $FAILED
