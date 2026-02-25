#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# Xray Interactive Installer (Hardened)
# - Official Xray install only (XTLS/Xray-install)
# - Supports VLESS + REALITY and/or Shadowsocks 2022
# - Interactive menu: install, status, uninstall
# - Port strategy: random high port or custom
# - Post-install health checks (config, service, listening ports)
# =========================================================

INSTALLER_URL="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"
SCRIPT_VERSION="2026-02-25.10"

XRAY_DIR="/usr/local/etc/xray"
LOG_DIR="/var/log/xray"
STATE_DIR="/var/lib/xray-installer"
STATE_FILE="${STATE_DIR}/issued_tokens.txt"
META_FILE="${STATE_DIR}/install_meta.json"
OUT_DIR="/root/xray-share"

ENABLE_VLESS=0
ENABLE_SS=0
VLESS_PORT=""
SS_PORT=""
REALITY_SERVERNAMES=""
REALITY_DEST=""
VLESS_UUID=""
REALITY_SHORT_ID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SS_PASSWORD_B64=""
SHARE_HOST=""
SELECTED_PORTS=()

on_error() {
  local line_no="$1"
  local cmd="$2"
  local code="$3"
  echo
  echo "[ERROR] line ${line_no}: ${cmd} (exit=${code})"
}

trap 'on_error "${LINENO}" "${BASH_COMMAND}" "$?"' ERR

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash xray-install.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

print_header() {
  cat <<'EOF'
=========================================================
Xray Interactive Installer
=========================================================
EOF
  echo "Script version: ${SCRIPT_VERSION}"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

require_apt() {
  if ! command_exists apt-get; then
    echo "This script currently supports Debian/Ubuntu (apt-get required)."
    exit 1
  fi
}

b64url_no_pad() {
  base64 -w 0 | tr '+/' '-_' | tr -d '='
}

random_hex_bytes() {
  local n="${1:-8}"
  od -An -N"${n}" -tx1 /dev/urandom | tr -d ' \n'
}

random_b64_bytes() {
  local n="${1:-32}"
  head -c "${n}" /dev/urandom | base64 -w 0
}

format_host_for_url() {
  local host="$1"
  if [[ "${host}" == *:* && "${host}" != \[*\] ]]; then
    echo "[${host}]"
  else
    echo "${host}"
  fi
}

detect_share_host() {
  local host=""

  host="$(curl -4 -fsSL --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "${host}" ]]; then
    host="$(curl -4 -fsSL --max-time 6 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\n' || true)"
  fi
  if [[ -z "${host}" ]]; then
    host="$(hostname -I | awk '{for(i=1;i<=NF;i++) if ($i !~ /:/) {print $i; exit}}')"
  fi
  if [[ -z "${host}" ]]; then
    host="$(curl -6 -fsSL --max-time 6 https://api64.ipify.org 2>/dev/null || true)"
  fi
  if [[ -z "${host}" ]]; then
    host="$(hostname -I | awk '{print $1}')"
  fi

  echo "${host}"
}

is_valid_port() {
  local port="${1:-}"
  [[ "${port}" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

is_port_in_selected() {
  local target="$1"
  local p
  for p in "${SELECTED_PORTS[@]:-}"; do
    if [[ "${p}" == "${target}" ]]; then
      return 0
    fi
  done
  return 1
}

port_is_listening_any() {
  local port="$1"
  if ! command_exists ss; then
    return 1
  fi
  ss -lntuH 2>/dev/null | awk '{print $5}' | grep -Eo '[0-9]+$' | grep -qx "${port}"
}

is_listening_tcp() {
  local port="$1"
  if ! command_exists ss; then
    return 1
  fi
  ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

is_listening_udp() {
  local port="$1"
  if ! command_exists ss; then
    return 1
  fi
  ss -lnuH 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

pick_random_high_port() {
  local candidate=""
  local i
  for i in $(seq 1 300); do
    if command_exists shuf; then
      candidate="$(shuf -i 20000-59999 -n 1)"
    else
      candidate="$((RANDOM % 40000 + 20000))"
    fi
    if ! is_port_in_selected "${candidate}" && ! port_is_listening_any "${candidate}"; then
      echo "${candidate}"
      return 0
    fi
  done
  echo "Failed to allocate a random high port after many attempts."
  exit 1
}

prompt_port_mode() {
  local label="$1"
  local mode=""
  local custom_port=""
  local random_port=""
  while true; do
    echo >&2
    echo "${label} port mode:" >&2
    echo "1) Random high port (20000-59999)" >&2
    echo "2) Custom port" >&2
    read -rp "Select [1/2] (default 1): " mode
    mode="${mode:-1}"
    case "${mode}" in
      1)
        random_port="$(pick_random_high_port)"
        echo "Selected random port: ${random_port}" >&2
        echo "${random_port}"
        return 0
        ;;
      2)
        read -rp "Enter custom ${label} port: " custom_port
        if ! is_valid_port "${custom_port}"; then
          echo "Invalid port." >&2
          continue
        fi
        if is_port_in_selected "${custom_port}"; then
          echo "Port ${custom_port} already selected in this run." >&2
          continue
        fi
        if port_is_listening_any "${custom_port}"; then
          local force_use="n"
          read -rp "Port ${custom_port} appears in use. Continue anyway? [y/N]: " force_use
          if [[ ! "${force_use}" =~ ^[Yy]$ ]]; then
            continue
          fi
        fi
        echo "${custom_port}"
        return 0
        ;;
      *)
        echo "Invalid selection." >&2
        ;;
    esac
  done
}

prompt_service_port() {
  local label="$1"
  local out_var="$2"
  local p=""
  while true; do
    p="$(prompt_port_mode "${label}")"
    if is_port_in_selected "${p}"; then
      echo "Port ${p} already selected in this run."
      continue
    fi
    SELECTED_PORTS+=("${p}")
    printf -v "${out_var}" '%s' "${p}"
    return 0
  done
}

prompt_install_profile() {
  local choice=""
  while true; do
    echo
    echo "Install type:"
    echo "1) VLESS + REALITY only"
    echo "2) Shadowsocks 2022 only"
    echo "3) Both VLESS + REALITY and SS2022"
    read -rp "Select [1/2/3]: " choice
    case "${choice}" in
      1)
        ENABLE_VLESS=1
        ENABLE_SS=0
        return 0
        ;;
      2)
        ENABLE_VLESS=0
        ENABLE_SS=1
        return 0
        ;;
      3)
        ENABLE_VLESS=1
        ENABLE_SS=1
        return 0
        ;;
      *)
        echo "Invalid selection."
        ;;
    esac
  done
}

prompt_vless_settings() {
  local mode=""

  while true; do
    echo
    echo "REALITY target mode:"
    echo "1) Use stable default (recommended): www.cloudflare.com:443"
    echo "2) Manual input"
    read -rp "Select [1/2] (default 1): " mode
    mode="${mode:-1}"
    case "${mode}" in
      1)
        REALITY_SERVERNAMES="www.cloudflare.com"
        REALITY_DEST="www.cloudflare.com:443"
        echo "Selected default target: ${REALITY_DEST}"
        break
        ;;
      2)
        while true; do
          read -rp "REALITY serverNames (comma separated, e.g. www.microsoft.com,www.cloudflare.com): " REALITY_SERVERNAMES
          if [[ -n "${REALITY_SERVERNAMES}" ]]; then
            break
          fi
          echo "serverNames cannot be empty."
        done

        while true; do
          read -rp "REALITY dest (e.g. www.microsoft.com:443): " REALITY_DEST
          if [[ -n "${REALITY_DEST}" ]]; then
            break
          fi
          echo "dest cannot be empty."
        done
        break
        ;;
      *)
        echo "Invalid selection."
        ;;
    esac
  done

}

prompt_share_host() {
  read -rp "Client connect host/IP (empty = auto detect public IPv4): " SHARE_HOST
}

install_prerequisites() {
  apt-get update -y
  apt-get install -y curl wget jq openssl uuid-runtime python3 ca-certificates logrotate iproute2
}

ensure_placeholder_config() {
  mkdir -p "${XRAY_DIR}"
  if [[ ! -s "${XRAY_DIR}/config.json" ]]; then
    cat >"${XRAY_DIR}/config.json" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
}
EOF
  fi
}

install_official_xray() {
  local rc=0
  set +e
  if command_exists timeout; then
    timeout 300 bash -c "$(curl -fsSL "${INSTALLER_URL}")" @ install
  else
    bash -c "$(curl -fsSL "${INSTALLER_URL}")" @ install
  fi
  rc=$?
  set -e
  if [[ ! -x /usr/local/bin/xray ]]; then
    echo "Xray binary not found at /usr/local/bin/xray after install."
    exit 1
  fi
  if (( rc != 0 )); then
    echo "Warning: official installer returned non-zero (${rc}), continuing with custom config setup."
  fi
  systemctl stop xray >/dev/null 2>&1 || true
}

prepare_paths() {
  mkdir -p "${XRAY_DIR}" "${LOG_DIR}" "${STATE_DIR}" "${OUT_DIR}"
  touch "${STATE_FILE}"
  chmod 700 "${STATE_DIR}" "${OUT_DIR}"
  chmod 600 "${STATE_FILE}"
  chown -R nobody:nogroup "${LOG_DIR}" 2>/dev/null || true
}

gen_unique() {
  local kind="$1"
  local val=""
  local attempt=0
  while (( attempt < 200 )); do
    attempt=$((attempt + 1))
    case "${kind}" in
      uuid)
        if [[ -r /proc/sys/kernel/random/uuid ]]; then
          val="$(tr 'A-Z' 'a-z' < /proc/sys/kernel/random/uuid)"
        else
          val="$(uuidgen | tr 'A-Z' 'a-z')"
        fi
        ;;
      shortid)
        val="$(random_hex_bytes 8)"
        ;;
      sspass)
        val="$(random_b64_bytes 32 | tr -d '\n')"
        ;;
      *)
        echo "Unknown token kind: ${kind}"
        exit 1
        ;;
    esac
    if ! grep -Fxq "${kind}:${val}" "${STATE_FILE}"; then
      echo "${kind}:${val}" >> "${STATE_FILE}"
      echo "${val}"
      return 0
    fi
  done
  echo "Failed to generate unique ${kind} after many attempts."
  exit 1
}

gen_unique_x25519() {
  local out=""
  local priv=""
  local pub=""
  local attempt=0
  local key_file=""
  local -a keys=()

  for attempt in $(seq 1 8); do
    out=""
    priv=""
    pub=""
    keys=()
    echo "  - generating REALITY keypair (attempt ${attempt}/8)..." >&2

    if command_exists timeout; then
      out="$(timeout 8 /usr/local/bin/xray x25519 2>&1 || true)"
    else
      out="$(/usr/local/bin/xray x25519 2>&1 || true)"
    fi

    priv="$(printf '%s\n' "${out}" | sed -nE 's/.*Private key:[[:space:]]*([^[:space:]]+).*/\1/p' | head -n 1)"
    pub="$(printf '%s\n' "${out}" | sed -nE 's/.*Public key:[[:space:]]*([^[:space:]]+).*/\1/p' | head -n 1)"

    if [[ -z "${priv}" || -z "${pub}" ]]; then
      mapfile -t keys < <(printf '%s\n' "${out}" | grep -Eo '[A-Za-z0-9_-]{40,}=?' | head -n 2 || true)
      if (( ${#keys[@]} >= 2 )); then
        priv="${keys[0]}"
        pub="${keys[1]}"
      fi
    fi

    if [[ -n "${priv}" && -n "${pub}" ]] \
      && ! grep -Fxq "reality_priv:${priv}" "${STATE_FILE}" \
      && ! grep -Fxq "reality_pub:${pub}" "${STATE_FILE}"; then
      echo "reality_priv:${priv}" >> "${STATE_FILE}"
      echo "reality_pub:${pub}" >> "${STATE_FILE}"
      echo "${priv}|${pub}"
      return 0
    fi
    sleep 0.2
  done

  # Fallback: derive X25519 keypair via openssl and convert to base64url.
  if command_exists openssl; then
    echo "  - xray x25519 did not return usable output, trying openssl fallback..." >&2
    key_file="$(mktemp)"
    if openssl genpkey -algorithm X25519 -out "${key_file}" >/dev/null 2>&1; then
      priv="$(openssl pkey -in "${key_file}" -outform DER 2>/dev/null | tail -c 32 | b64url_no_pad)"
      pub="$(openssl pkey -in "${key_file}" -pubout -outform DER 2>/dev/null | tail -c 32 | b64url_no_pad)"
    fi
    rm -f "${key_file}" || true

    if [[ -n "${priv}" && -n "${pub}" ]] \
      && ! grep -Fxq "reality_priv:${priv}" "${STATE_FILE}" \
      && ! grep -Fxq "reality_pub:${pub}" "${STATE_FILE}"; then
      echo "reality_priv:${priv}" >> "${STATE_FILE}"
      echo "reality_pub:${pub}" >> "${STATE_FILE}"
      echo "${priv}|${pub}"
      return 0
    fi
  fi

  echo "Failed to generate REALITY x25519 key pair."
  echo "Last xray x25519 output:"
  printf '%s\n' "${out}"
  exit 1
}

generate_credentials() {
  if (( ENABLE_VLESS == 1 )); then
    local key_pair=""
    echo "  - generating VLESS UUID..." >&2
    VLESS_UUID="$(gen_unique uuid)"
    echo "  - generating REALITY shortId..." >&2
    REALITY_SHORT_ID="$(gen_unique shortid)"
    key_pair="$(gen_unique_x25519)"
    REALITY_PRIVATE_KEY="${key_pair%%|*}"
    REALITY_PUBLIC_KEY="${key_pair##*|}"
  fi

  if (( ENABLE_SS == 1 )); then
    echo "  - generating SS2022 password..." >&2
    SS_PASSWORD_B64="$(gen_unique sspass)"
  fi
}

build_servernames_json() {
  printf '%s' "${REALITY_SERVERNAMES}" | jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))'
}

build_xray_config() {
  local vless_json="null"
  local ss_json="null"

  if (( ENABLE_VLESS == 1 )); then
    local servernames_json
    servernames_json="$(build_servernames_json)"
    if [[ "${servernames_json}" == "[]" ]]; then
      echo "REALITY serverNames is empty after parsing."
      exit 1
    fi

    vless_json="$(jq -n \
      --argjson port "${VLESS_PORT}" \
      --arg uuid "${VLESS_UUID}" \
      --arg dest "${REALITY_DEST}" \
      --arg privateKey "${REALITY_PRIVATE_KEY}" \
      --arg shortId "${REALITY_SHORT_ID}" \
      --argjson serverNames "${servernames_json}" \
      '{
        tag: "vless-reality-in",
        listen: "0.0.0.0",
        port: $port,
        protocol: "vless",
        settings: {
          clients: [
            {
              id: $uuid,
              flow: "xtls-rprx-vision",
              email: "main@local"
            }
          ],
          decryption: "none"
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: $dest,
            xver: 0,
            serverNames: $serverNames,
            privateKey: $privateKey,
            shortIds: [$shortId]
          }
        },
        sniffing: {
          enabled: true,
          destOverride: ["http", "tls", "quic"]
        }
      }')"
  fi

  if (( ENABLE_SS == 1 )); then
    ss_json="$(jq -n \
      --argjson port "${SS_PORT}" \
      --arg password "${SS_PASSWORD_B64}" \
      '{
        tag: "ss2022-in",
        listen: "0.0.0.0",
        port: $port,
        protocol: "shadowsocks",
        settings: {
          method: "2022-blake3-aes-256-gcm",
          password: $password,
          network: "tcp,udp"
        }
      }')"
  fi

  jq -n \
    --arg logDir "${LOG_DIR}" \
    --argjson vless "${vless_json}" \
    --argjson ss "${ss_json}" \
    '{
      log: {
        loglevel: "warning",
        access: ($logDir + "/access.log"),
        error: ($logDir + "/error.log")
      },
      inbounds: [],
      outbounds: [
        { protocol: "freedom", tag: "direct" },
        { protocol: "blackhole", tag: "block" }
      ]
    }
    | .inbounds += (if $vless == null then [] else [$vless] end)
    | .inbounds += (if $ss == null then [] else [$ss] end)
    ' > "${XRAY_DIR}/config.json"

  if [[ ! -s "${XRAY_DIR}/config.json" ]]; then
    echo "Failed to generate ${XRAY_DIR}/config.json"
    exit 1
  fi
}

configure_firewall() {
  echo "Skipping firewall configuration (UFW/iptables disabled by design)."
}

write_systemd_override() {
  mkdir -p /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service.d/override.conf <<'EOF'
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
EOF
}

write_logrotate() {
  cat >/etc/logrotate.d/xray <<EOF
${LOG_DIR}/*.log {
  daily
  rotate 7
  compress
  missingok
  notifempty
  copytruncate
}
EOF
}

check_installation_health() {
  local failed=0

  echo
  echo "Running installation checks..."

  if /usr/local/bin/xray -test -config "${XRAY_DIR}/config.json" >/dev/null 2>&1; then
    echo "[OK] Xray config test passed."
  else
    echo "[FAIL] Xray config test failed."
    failed=1
  fi

  systemctl daemon-reload
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 1

  if [[ "$(systemctl is-active xray 2>/dev/null || true)" == "active" ]]; then
    echo "[OK] xray service is active."
  else
    echo "[FAIL] xray service is not active."
    failed=1
  fi

  if (( ENABLE_VLESS == 1 )); then
    if is_listening_tcp "${VLESS_PORT}"; then
      echo "[OK] VLESS TCP port ${VLESS_PORT} is listening."
    else
      echo "[FAIL] VLESS TCP port ${VLESS_PORT} is not listening."
      failed=1
    fi
  fi

  if (( ENABLE_SS == 1 )); then
    if is_listening_tcp "${SS_PORT}"; then
      echo "[OK] SS2022 TCP port ${SS_PORT} is listening."
    else
      echo "[FAIL] SS2022 TCP port ${SS_PORT} is not listening."
      failed=1
    fi
    if is_listening_udp "${SS_PORT}"; then
      echo "[OK] SS2022 UDP port ${SS_PORT} is listening."
    else
      echo "[FAIL] SS2022 UDP port ${SS_PORT} is not listening."
      failed=1
    fi
  fi

  return "${failed}"
}

urlencode() {
  python3 - <<'PY' "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

build_share_links() {
  local server_ip=""
  local server_host_url=""
  local sni_first=""
  local vless_name=""
  local ss_name=""
  local vless_name_enc=""
  local ss_name_enc=""
  local vless_link=""
  local ss_link=""
  local ss_userinfo_b64=""

  server_ip="${SHARE_HOST}"
  if [[ -z "${server_ip}" ]]; then
    server_ip="$(detect_share_host)"
  fi
  if [[ -z "${server_ip}" ]]; then
    echo "Failed to detect client connect host/IP."
    exit 1
  fi
  server_host_url="$(format_host_for_url "${server_ip}")"

  : > "${OUT_DIR}/links.txt"

  {
    echo "GeneratedAt: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "ServerHost: ${server_ip}"
    echo
  } >> "${OUT_DIR}/links.txt"

  if (( ENABLE_VLESS == 1 )); then
    sni_first="$(echo "${REALITY_SERVERNAMES}" | cut -d',' -f1 | xargs)"
    vless_name="vless-reality-${server_ip}"
    vless_name_enc="$(urlencode "${vless_name}")"
    vless_link="vless://${VLESS_UUID}@${server_host_url}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni_first}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&headerType=none#${vless_name_enc}"

    {
      echo "VLESS:"
      echo "${vless_link}"
      echo
    } >> "${OUT_DIR}/links.txt"
  fi

  if (( ENABLE_SS == 1 )); then
    ss_name="ss2022-${server_ip}"
    ss_name_enc="$(urlencode "${ss_name}")"
    ss_userinfo_b64="$(printf '%s' "2022-blake3-aes-256-gcm:${SS_PASSWORD_B64}" | base64 -w 0)"
    ss_link="ss://${ss_userinfo_b64}@${server_host_url}:${SS_PORT}#${ss_name_enc}"

    {
      echo "SS2022:"
      echo "${ss_link}"
      echo
    } >> "${OUT_DIR}/links.txt"
  fi

  chmod 600 "${OUT_DIR}/links.txt"

  echo
  echo "Share links saved: ${OUT_DIR}/links.txt"
  echo "Client connect host/IP: ${server_ip}"

  if (( ENABLE_VLESS == 1 )); then
    echo
    echo "---------- VLESS LINK ----------"
    echo "${vless_link}"
  fi

  if (( ENABLE_SS == 1 )); then
    echo
    echo "---------- SS2022 LINK ---------"
    echo "${ss_link}"
  fi
}

save_meta() {
  local vless_port_json="null"
  local ss_port_json="null"
  if [[ -n "${VLESS_PORT}" ]]; then
    vless_port_json="${VLESS_PORT}"
  fi
  if [[ -n "${SS_PORT}" ]]; then
    ss_port_json="${SS_PORT}"
  fi

  jq -n \
    --arg updatedAt "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson enableVless "${ENABLE_VLESS}" \
    --argjson enableSs "${ENABLE_SS}" \
    --argjson vlessPort "${vless_port_json}" \
    --argjson ssPort "${ss_port_json}" \
    --arg realityServerNames "${REALITY_SERVERNAMES:-}" \
    --arg realityDest "${REALITY_DEST:-}" \
    '{
      updated_at: $updatedAt,
      enable_vless: $enableVless,
      enable_ss: $enableSs,
      vless_port: $vlessPort,
      ss_port: $ssPort,
      reality_servernames: $realityServerNames,
      reality_dest: $realityDest
    }' > "${META_FILE}"
  chmod 600 "${META_FILE}"
}

show_status() {
  echo
  echo "================ XRAY STATUS ================"

  if [[ -x /usr/local/bin/xray ]]; then
    local ver_line
    ver_line="$(/usr/local/bin/xray version 2>/dev/null | head -n 1 || true)"
    echo "Binary: installed ${ver_line:+(${ver_line})}"
  else
    echo "Binary: not installed"
  fi

  echo "Service active: $(systemctl is-active xray 2>/dev/null || echo not-found)"
  echo "Service enabled: $(systemctl is-enabled xray 2>/dev/null || echo not-found)"

  if [[ -f "${XRAY_DIR}/config.json" ]]; then
    if [[ -x /usr/local/bin/xray ]] && /usr/local/bin/xray -test -config "${XRAY_DIR}/config.json" >/dev/null 2>&1; then
      echo "Config test: pass"
    else
      echo "Config test: fail"
    fi

    echo "Inbounds:"
    jq -r '.inbounds[]? | "- \(.tag) | \(.protocol) | port=\(.port)"' "${XRAY_DIR}/config.json"

    while read -r protocol port; do
      [[ -z "${protocol}" || -z "${port}" ]] && continue
      local tcp_state="down"
      local udp_state="n/a"
      if is_listening_tcp "${port}"; then
        tcp_state="ok"
      fi
      if [[ "${protocol}" == "shadowsocks" ]]; then
        if is_listening_udp "${port}"; then
          udp_state="ok"
        else
          udp_state="down"
        fi
      fi
      echo "  - port ${port}: tcp=${tcp_state}, udp=${udp_state}"
    done < <(jq -r '.inbounds[]? | "\(.protocol) \(.port)"' "${XRAY_DIR}/config.json")
  else
    echo "Config: not found (${XRAY_DIR}/config.json)"
  fi

  if [[ -f "${META_FILE}" ]]; then
    echo "Last install profile:"
    jq -r '"  updated_at=\(.updated_at), enable_vless=\(.enable_vless), enable_ss=\(.enable_ss), vless_port=\(.vless_port), ss_port=\(.ss_port)"' "${META_FILE}"
  fi

  if [[ -f "${OUT_DIR}/links.txt" ]]; then
    echo "Share links file: ${OUT_DIR}/links.txt"
  else
    echo "Share links file: not found"
  fi

  echo "============================================="
}

run_uninstall() {
  local confirm="n"
  echo
  echo "This will uninstall Xray and remove installer-generated files."
  read -rp "Continue uninstall? [y/N]: " confirm
  if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    return 0
  fi

  systemctl stop xray >/dev/null 2>&1 || true
  systemctl disable xray >/dev/null 2>&1 || true

  if command_exists curl; then
    bash -c "$(curl -fsSL "${INSTALLER_URL}")" @ remove || true
  fi

  rm -f "${XRAY_DIR}/config.json" || true
  rm -rf "${STATE_DIR}" "${OUT_DIR}" || true
  rm -f /etc/logrotate.d/xray || true
  rm -f /etc/systemd/system/xray.service.d/override.conf || true
  rmdir /etc/systemd/system/xray.service.d >/dev/null 2>&1 || true
  systemctl daemon-reload || true

  echo "Uninstall complete."
  show_status
}

run_install() {
  local confirm="y"

  ENABLE_VLESS=0
  ENABLE_SS=0
  VLESS_PORT=""
  SS_PORT=""
  REALITY_SERVERNAMES=""
  REALITY_DEST=""
  SHARE_HOST=""
  SELECTED_PORTS=()

  prompt_install_profile

  if (( ENABLE_VLESS == 1 )); then
    prompt_service_port "VLESS+REALITY" VLESS_PORT
    if [[ "${VLESS_PORT}" != "443" ]]; then
      echo "Warning: VLESS+REALITY on non-443 port (${VLESS_PORT}) may be less stable across some networks."
      echo "Recommended VLESS port: 443"
    fi
    prompt_vless_settings
  fi

  if (( ENABLE_SS == 1 )); then
    prompt_service_port "SS2022" SS_PORT
  fi

  prompt_share_host

  echo
  echo "Installation summary:"
  if (( ENABLE_VLESS == 1 )); then
    echo "- VLESS+REALITY: enabled on tcp/${VLESS_PORT}"
    if [[ "${VLESS_PORT}" != "443" ]]; then
      echo "- VLESS note: non-443 selected; 443 is recommended for stability"
    fi
    echo "- REALITY serverNames: ${REALITY_SERVERNAMES}"
    echo "- REALITY dest: ${REALITY_DEST}"
  else
    echo "- VLESS+REALITY: disabled"
  fi
  if (( ENABLE_SS == 1 )); then
    echo "- SS2022: enabled on tcp+udp/${SS_PORT}"
  else
    echo "- SS2022: disabled"
  fi
  if [[ -n "${SHARE_HOST}" ]]; then
    echo "- Client connect host/IP: ${SHARE_HOST}"
  else
    echo "- Client connect host/IP: auto detect"
  fi
  read -rp "Proceed with install/reconfigure? [Y/n]: " confirm
  confirm="${confirm:-Y}"
  if [[ "${confirm}" =~ ^[Nn]$ ]]; then
    echo "Install cancelled."
    return 0
  fi

  require_apt
  echo "[1/11] Installing prerequisites..."
  install_prerequisites
  echo "[2/11] Preparing work directories..."
  prepare_paths
  echo "[3/11] Writing placeholder config..."
  ensure_placeholder_config
  echo "[4/11] Installing official Xray..."
  install_official_xray
  echo "[5/11] Preparing work directories (post-install)..."
  prepare_paths
  echo "[6/11] Generating credentials..."
  generate_credentials
  echo "[7/11] Writing final Xray config..."
  build_xray_config
  echo "[8/11] Skipping firewall changes..."
  configure_firewall
  echo "[9/11] Applying systemd hardening and logrotate..."
  write_systemd_override
  write_logrotate
  echo "[10/11] Saving install metadata and generating links..."
  save_meta
  build_share_links
  echo "[11/11] Running health checks..."

  if check_installation_health; then
    echo
    echo "Install checks passed."
  else
    echo
    echo "Install checks found issues. Please inspect: systemctl status xray --no-pager"
  fi

  show_status
}

quick_status_banner() {
  echo
  if [[ -x /usr/local/bin/xray ]]; then
    echo "Current server state: Xray installed, service=$(systemctl is-active xray 2>/dev/null || echo unknown)"
    if [[ ! -f "${XRAY_DIR}/config.json" ]]; then
      echo "Warning: ${XRAY_DIR}/config.json is missing. Choose [1] Install / Reinstall to recover."
    fi
  else
    echo "Current server state: Xray not installed"
  fi
}

main_menu() {
  local choice=""
  print_header
  quick_status_banner

  while true; do
    echo
    echo "Choose action:"
    echo "1) Install / Reinstall"
    echo "2) Show status"
    echo "3) Uninstall"
    echo "4) Exit"
    read -rp "Select [1-4]: " choice
    case "${choice}" in
      1) run_install ;;
      2) show_status ;;
      3) run_uninstall ;;
      4)
        echo "Bye."
        exit 0
        ;;
      *)
        echo "Invalid selection."
        ;;
    esac
  done
}

main_menu
