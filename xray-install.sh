#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Xray Interactive Installer (Hardened)
# - Official Xray install only (XTLS/Xray-install)
# - Supports VLESS + REALITY and/or Shadowsocks 2022
# - Interactive menu: install, status, uninstall
# - Port strategy: random high port or custom
# - Post-install health checks (config, service, listening ports)
# =========================================================

INSTALLER_URL="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

XRAY_DIR="/usr/local/etc/xray"
LOG_DIR="/var/log/xray"
STATE_DIR="/var/lib/xray-installer"
STATE_FILE="${STATE_DIR}/issued_tokens.txt"
META_FILE="${STATE_DIR}/install_meta.json"
OUT_DIR="/root/xray-share"

ENABLE_VLESS=0
ENABLE_SS=0
SSH_PORT=22
VLESS_PORT=""
SS_PORT=""
REALITY_SERVERNAMES=""
REALITY_DEST=""
VLESS_ALLOW_CIDR=""
VLESS_UUID=""
REALITY_SHORT_ID=""
REALITY_PRIVATE_KEY=""
REALITY_PUBLIC_KEY=""
SS_PASSWORD_B64=""
SELECTED_PORTS=()

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
        if [[ "${custom_port}" == "${SSH_PORT}" ]]; then
          echo "Port ${custom_port} conflicts with SSH port." >&2
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
    if [[ "${p}" == "${SSH_PORT}" ]]; then
      echo "Port ${p} conflicts with SSH port."
      continue
    fi
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

prompt_ssh_port() {
  local input_port=""
  while true; do
    read -rp "SSH port (default 22): " input_port
    input_port="${input_port:-22}"
    if is_valid_port "${input_port}"; then
      SSH_PORT="${input_port}"
      return 0
    fi
    echo "Invalid SSH port."
  done
}

pick_random_reality_site() {
  local sites=(
    "www.cloudflare.com"
    "www.microsoft.com"
    "www.apple.com"
    "www.amazon.com"
    "www.wikipedia.org"
    "www.bing.com"
    "www.github.com"
    "www.adobe.com"
  )
  local idx=0
  if command_exists shuf; then
    idx="$(shuf -i 0-$((${#sites[@]} - 1)) -n 1)"
  else
    idx="$((RANDOM % ${#sites[@]}))"
  fi
  echo "${sites[idx]}"
}

prompt_vless_settings() {
  local mode=""
  local auto_site=""

  while true; do
    echo
    echo "REALITY target mode:"
    echo "1) Auto random popular website (recommended)"
    echo "2) Manual input"
    read -rp "Select [1/2] (default 1): " mode
    mode="${mode:-1}"
    case "${mode}" in
      1)
        auto_site="$(pick_random_reality_site)"
        REALITY_SERVERNAMES="${auto_site}"
        REALITY_DEST="${auto_site}:443"
        echo "Auto selected site: ${auto_site}"
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

  read -rp "Optional: restrict VLESS source CIDR (empty = any): " VLESS_ALLOW_CIDR
}

install_prerequisites() {
  apt-get update -y
  apt-get install -y curl wget jq openssl uuid-runtime ufw qrencode python3 ca-certificates logrotate iproute2
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
  bash -c "$(curl -fsSL "${INSTALLER_URL}")" @ install
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
  while true; do
    case "${kind}" in
      uuid)    val="$(uuidgen | tr 'A-Z' 'a-z')" ;;
      shortid) val="$(openssl rand -hex 8)" ;;
      sspass)  val="$(openssl rand -base64 32 | tr -d '\n')" ;;
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
}

gen_unique_x25519() {
  local out=""
  local priv=""
  local pub=""
  while true; do
    out="$(/usr/local/bin/xray x25519)"
    priv="$(echo "${out}" | awk '/Private key:/ {print $3}')"
    pub="$(echo "${out}" | awk '/Public key:/ {print $3}')"
    if [[ -n "${priv}" && -n "${pub}" ]] \
      && ! grep -Fxq "reality_priv:${priv}" "${STATE_FILE}" \
      && ! grep -Fxq "reality_pub:${pub}" "${STATE_FILE}"; then
      echo "reality_priv:${priv}" >> "${STATE_FILE}"
      echo "reality_pub:${pub}" >> "${STATE_FILE}"
      echo "${priv}|${pub}"
      return 0
    fi
  done
}

generate_credentials() {
  if (( ENABLE_VLESS == 1 )); then
    local key_pair=""
    VLESS_UUID="$(gen_unique uuid)"
    REALITY_SHORT_ID="$(gen_unique shortid)"
    key_pair="$(gen_unique_x25519)"
    REALITY_PRIVATE_KEY="${key_pair%%|*}"
    REALITY_PUBLIC_KEY="${key_pair##*|}"
  fi

  if (( ENABLE_SS == 1 )); then
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
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"

  if (( ENABLE_VLESS == 1 )); then
    ufw allow "${VLESS_PORT}/tcp"
  fi
  if (( ENABLE_SS == 1 )); then
    ufw allow "${SS_PORT}/tcp"
    ufw allow "${SS_PORT}/udp"
  fi
  ufw --force enable

  if (( ENABLE_VLESS == 1 )) && [[ -n "${VLESS_ALLOW_CIDR}" ]]; then
    apt-get install -y iptables-persistent >/dev/null 2>&1 || true
    iptables -C INPUT -p tcp --dport "${VLESS_PORT}" -s "${VLESS_ALLOW_CIDR}" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT -p tcp --dport "${VLESS_PORT}" -s "${VLESS_ALLOW_CIDR}" -j ACCEPT
    iptables -C INPUT -p tcp --dport "${VLESS_PORT}" -j DROP 2>/dev/null \
      || iptables -A INPUT -p tcp --dport "${VLESS_PORT}" -j DROP
    netfilter-persistent save >/dev/null 2>&1 || true
  fi
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
  local sni_first=""
  local vless_name=""
  local ss_name=""
  local vless_name_enc=""
  local ss_name_enc=""
  local vless_link=""
  local ss_link=""
  local ss_userinfo_b64=""

  server_ip="$(curl -s https://api.ipify.org || true)"
  if [[ -z "${server_ip}" ]]; then
    server_ip="$(hostname -I | awk '{print $1}')"
  fi

  : > "${OUT_DIR}/links.txt"

  {
    echo "GeneratedAt: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "ServerIP: ${server_ip}"
    echo
  } >> "${OUT_DIR}/links.txt"

  if (( ENABLE_VLESS == 1 )); then
    sni_first="$(echo "${REALITY_SERVERNAMES}" | cut -d',' -f1 | xargs)"
    vless_name="vless-reality-${server_ip}"
    vless_name_enc="$(urlencode "${vless_name}")"
    vless_link="vless://${VLESS_UUID}@${server_ip}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni_first}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&headerType=none#${vless_name_enc}"

    {
      echo "VLESS:"
      echo "${vless_link}"
      echo
    } >> "${OUT_DIR}/links.txt"

    qrencode -o "${OUT_DIR}/vless.png" -s 8 -m 2 "${vless_link}"
  fi

  if (( ENABLE_SS == 1 )); then
    ss_name="ss2022-${server_ip}"
    ss_name_enc="$(urlencode "${ss_name}")"
    ss_userinfo_b64="$(printf '%s' "2022-blake3-aes-256-gcm:${SS_PASSWORD_B64}" | base64 -w 0)"
    ss_link="ss://${ss_userinfo_b64}@${server_ip}:${SS_PORT}#${ss_name_enc}"

    {
      echo "SS2022:"
      echo "${ss_link}"
      echo
    } >> "${OUT_DIR}/links.txt"

    qrencode -o "${OUT_DIR}/ss2022.png" -s 8 -m 2 "${ss_link}"
  fi

  chmod 600 "${OUT_DIR}/links.txt"

  echo
  echo "Share links saved: ${OUT_DIR}/links.txt"
  if (( ENABLE_VLESS == 1 )); then
    echo "QR PNG: ${OUT_DIR}/vless.png"
  fi
  if (( ENABLE_SS == 1 )); then
    echo "QR PNG: ${OUT_DIR}/ss2022.png"
  fi

  if (( ENABLE_VLESS == 1 )); then
    echo
    echo "---------- VLESS LINK ----------"
    echo "${vless_link}"
    echo "---------- VLESS QR ------------"
    qrencode -t UTF8 "${vless_link}" || true
  fi

  if (( ENABLE_SS == 1 )); then
    echo
    echo "---------- SS2022 LINK ---------"
    echo "${ss_link}"
    echo "---------- SS2022 QR -----------"
    qrencode -t UTF8 "${ss_link}" || true
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
    --argjson sshPort "${SSH_PORT}" \
    --argjson vlessPort "${vless_port_json}" \
    --argjson ssPort "${ss_port_json}" \
    --arg realityServerNames "${REALITY_SERVERNAMES:-}" \
    --arg realityDest "${REALITY_DEST:-}" \
    --arg vlessAllowCidr "${VLESS_ALLOW_CIDR:-}" \
    '{
      updated_at: $updatedAt,
      enable_vless: $enableVless,
      enable_ss: $enableSs,
      ssh_port: $sshPort,
      vless_port: $vlessPort,
      ss_port: $ssPort,
      reality_servernames: $realityServerNames,
      reality_dest: $realityDest,
      vless_allow_cidr: $vlessAllowCidr
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
    jq -r '"  updated_at=\(.updated_at), enable_vless=\(.enable_vless), enable_ss=\(.enable_ss), ssh_port=\(.ssh_port)"' "${META_FILE}"
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

  echo "Uninstall complete. UFW rules were left unchanged for safety."
  show_status
}

run_install() {
  local confirm="y"

  ENABLE_VLESS=0
  ENABLE_SS=0
  SSH_PORT=22
  VLESS_PORT=""
  SS_PORT=""
  REALITY_SERVERNAMES=""
  REALITY_DEST=""
  VLESS_ALLOW_CIDR=""
  SELECTED_PORTS=()

  prompt_install_profile
  prompt_ssh_port

  if (( ENABLE_VLESS == 1 )); then
    prompt_service_port "VLESS+REALITY" VLESS_PORT
    prompt_vless_settings
  fi

  if (( ENABLE_SS == 1 )); then
    prompt_service_port "SS2022" SS_PORT
  fi

  echo
  echo "Installation summary:"
  echo "- SSH port: ${SSH_PORT}"
  if (( ENABLE_VLESS == 1 )); then
    echo "- VLESS+REALITY: enabled on tcp/${VLESS_PORT}"
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
  read -rp "Proceed with install/reconfigure? [Y/n]: " confirm
  confirm="${confirm:-Y}"
  if [[ "${confirm}" =~ ^[Nn]$ ]]; then
    echo "Install cancelled."
    return 0
  fi

  require_apt
  install_prerequisites
  prepare_paths
  ensure_placeholder_config
  install_official_xray
  prepare_paths
  generate_credentials
  build_xray_config
  configure_firewall
  write_systemd_override
  write_logrotate
  save_meta
  build_share_links

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
