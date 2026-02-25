#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Xray Official One-Click Installer (Hardened)
# Features:
# - Official Xray install only (XTLS/Xray-install)
# - VLESS + REALITY (TCP, xtls-rprx-vision)
# - Shadowsocks 2022 (2022-blake3-aes-256-gcm)
# - Custom ports
# - Strong random credentials (UUID/keys/shortId/password)
# - Local uniqueness tracking (no reuse on same server)
# - UFW firewall hardening
# - systemd hardening override
# - logrotate for xray logs
# - Auto generate share links for v2rayN/Shadowrocket
# - Auto generate QR codes (terminal + PNG files)
# =========================================================

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

need_cmd() { command -v "$1" >/dev/null 2>&1; }

apt-get update -y
apt-get install -y curl wget jq openssl uuid-runtime ufw qrencode python3 ca-certificates logrotate

# ---------- Inputs ----------
read -rp "SSH port (default 22): " SSH_PORT
SSH_PORT="${SSH_PORT:-22}"

read -rp "VLESS+REALITY listen port (e.g. 443): " VLESS_PORT
read -rp "SS2022 listen port (e.g. 8443): " SS_PORT
read -rp "REALITY serverNames (comma separated, e.g. www.microsoft.com,www.cloudflare.com): " REALITY_SERVERNAMES
read -rp "REALITY dest (e.g. www.microsoft.com:443): " REALITY_DEST
read -rp "Optional: restrict VLESS source CIDR (empty = any): " VLESS_ALLOW_CIDR

if [[ -z "${VLESS_PORT}" || -z "${SS_PORT}" || -z "${REALITY_SERVERNAMES}" || -z "${REALITY_DEST}" ]]; then
  echo "Missing required inputs."
  exit 1
fi

if [[ "${VLESS_PORT}" == "${SS_PORT}" ]]; then
  echo "VLESS and SS ports must be different."
  exit 1
fi

if ! [[ "${SSH_PORT}" =~ ^[0-9]+$ && "${VLESS_PORT}" =~ ^[0-9]+$ && "${SS_PORT}" =~ ^[0-9]+$ ]]; then
  echo "Ports must be numeric."
  exit 1
fi

for p in "${SSH_PORT}" "${VLESS_PORT}" "${SS_PORT}"; do
  if (( p < 1 || p > 65535 )); then
    echo "Invalid port: ${p}"
    exit 1
  fi
done

# ---------- Install official Xray ----------
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

if [[ ! -x /usr/local/bin/xray ]]; then
  echo "Xray binary not found at /usr/local/bin/xray"
  exit 1
fi

# ---------- Paths ----------
XRAY_DIR="/usr/local/etc/xray"
LOG_DIR="/var/log/xray"
STATE_DIR="/var/lib/xray-installer"
STATE_FILE="${STATE_DIR}/issued_tokens.txt"
OUT_DIR="/root/xray-share"

mkdir -p "${XRAY_DIR}" "${LOG_DIR}" "${STATE_DIR}" "${OUT_DIR}"
touch "${STATE_FILE}"
chmod 700 "${STATE_DIR}" "${OUT_DIR}"
chmod 600 "${STATE_FILE}"
chown -R nobody:nogroup "${LOG_DIR}" || true

# ---------- Unique credential generators ----------
gen_unique() {
  local kind="$1"
  local val=""
  while true; do
    case "${kind}" in
      uuid)    val="$(uuidgen | tr 'A-Z' 'a-z')" ;;
      shortid) val="$(openssl rand -hex 8)" ;;
      sspass)  val="$(openssl rand -base64 32 | tr -d '\n')" ;;
      *) echo "unknown kind"; exit 1 ;;
    esac
    if ! grep -Fxq "${kind}:${val}" "${STATE_FILE}"; then
      echo "${kind}:${val}" >> "${STATE_FILE}"
      echo "${val}"
      return 0
    fi
  done
}

gen_unique_x25519() {
  local out priv pub
  while true; do
    out="$(/usr/local/bin/xray x25519)"
    priv="$(echo "${out}" | awk '/Private key:/ {print $3}')"
    pub="$(echo "${out}"  | awk '/Public key:/ {print $3}')"
    if [[ -n "${priv}" && -n "${pub}" ]] \
      && ! grep -Fxq "reality_priv:${priv}" "${STATE_FILE}" \
      && ! grep -Fxq "reality_pub:${pub}" "${STATE_FILE}"; then
      echo "reality_priv:${priv}" >> "${STATE_FILE}"
      echo "reality_pub:${pub}"  >> "${STATE_FILE}"
      echo "${priv}|${pub}"
      return 0
    fi
  done
}

VLESS_UUID="$(gen_unique uuid)"
REALITY_SHORT_ID="$(gen_unique shortid)"
SS_PASSWORD_B64="$(gen_unique sspass)"
KEY_PAIR="$(gen_unique_x25519)"
REALITY_PRIVATE_KEY="${KEY_PAIR%%|*}"
REALITY_PUBLIC_KEY="${KEY_PAIR##*|}"

# ---------- Build JSON arrays ----------
SERVERNAMES_JSON="$(echo "${REALITY_SERVERNAMES}" | awk -F',' '{
  printf "[";
  for(i=1;i<=NF;i++){
    gsub(/^ +| +$/, "", $i);
    printf "\"%s\"", $i;
    if(i<NF) printf ",";
  }
  printf "]";
}')"

# ---------- Write xray config ----------
cat >"${XRAY_DIR}/config.json" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "${LOG_DIR}/access.log",
    "error": "${LOG_DIR}/error.log"
  },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "listen": "0.0.0.0",
      "port": ${VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${VLESS_UUID}",
            "flow": "xtls-rprx-vision",
            "email": "main@local"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DEST}",
          "xver": 0,
          "serverNames": ${SERVERNAMES_JSON},
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    },
    {
      "tag": "ss2022-in",
      "listen": "0.0.0.0",
      "port": ${SS_PORT},
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-256-gcm",
        "password": "${SS_PASSWORD_B64}",
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF

# ---------- Optional CIDR restriction for VLESS ----------
# If specified, allow only CIDR to VLESS port, drop others.
if [[ -n "${VLESS_ALLOW_CIDR}" ]]; then
  apt-get install -y iptables-persistent >/dev/null 2>&1 || true
  iptables -I INPUT -p tcp --dport "${VLESS_PORT}" -s "${VLESS_ALLOW_CIDR}" -j ACCEPT
  iptables -A INPUT -p tcp --dport "${VLESS_PORT}" -j DROP
  netfilter-persistent save || true
fi

# ---------- UFW hardening ----------
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"
ufw allow "${VLESS_PORT}/tcp"
ufw allow "${SS_PORT}/tcp"
ufw allow "${SS_PORT}/udp"
ufw --force enable

# ---------- systemd hardening ----------
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

# ---------- logrotate ----------
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

# ---------- Validate + start ----------
/usr/local/bin/xray -test -config "${XRAY_DIR}/config.json"
systemctl daemon-reload
systemctl enable xray
systemctl restart xray

# ---------- Build share links ----------
SERVER_IP="$(curl -s https://api.ipify.org || true)"
if [[ -z "${SERVER_IP}" ]]; then
  SERVER_IP="$(hostname -I | awk '{print $1}')"
fi

SNI_FIRST="$(echo "${REALITY_SERVERNAMES}" | cut -d',' -f1 | xargs)"
VLESS_NAME="vless-reality-${SERVER_IP}"
SS_NAME="ss2022-${SERVER_IP}"

urlencode() {
  python3 - <<'PY' "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

VLESS_NAME_ENC="$(urlencode "${VLESS_NAME}")"
SS_NAME_ENC="$(urlencode "${SS_NAME}")"

VLESS_LINK="vless://${VLESS_UUID}@${SERVER_IP}:${VLESS_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI_FIRST}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp&headerType=none#${VLESS_NAME_ENC}"

SS_USERINFO_B64="$(printf '%s' "2022-blake3-aes-256-gcm:${SS_PASSWORD_B64}" | base64 -w 0)"
SS_LINK="ss://${SS_USERINFO_B64}@${SERVER_IP}:${SS_PORT}#${SS_NAME_ENC}"

cat >"${OUT_DIR}/links.txt" <<EOF
VLESS:
${VLESS_LINK}

SS2022:
${SS_LINK}
EOF
chmod 600 "${OUT_DIR}/links.txt"

qrencode -o "${OUT_DIR}/vless.png" -s 8 -m 2 "${VLESS_LINK}"
qrencode -o "${OUT_DIR}/ss2022.png" -s 8 -m 2 "${SS_LINK}"

# ---------- Print ----------
echo
echo "================ INSTALL DONE ================"
echo "Server IP: ${SERVER_IP}"
echo "Config: ${XRAY_DIR}/config.json"
echo "Xray status: systemctl status xray --no-pager"
echo "Error log: tail -f ${LOG_DIR}/error.log"
echo
echo "VLESS UUID: ${VLESS_UUID}"
echo "REALITY PublicKey: ${REALITY_PUBLIC_KEY}"
echo "REALITY ShortID: ${REALITY_SHORT_ID}"
echo "VLESS Port: ${VLESS_PORT}"
echo "SNI: ${SNI_FIRST}"
echo
echo "SS2022 Method: 2022-blake3-aes-256-gcm"
echo "SS2022 Password(Base64): ${SS_PASSWORD_B64}"
echo "SS2022 Port: ${SS_PORT}"
echo
echo "Share links saved: ${OUT_DIR}/links.txt"
echo "QR PNG saved:"
echo "  ${OUT_DIR}/vless.png"
echo "  ${OUT_DIR}/ss2022.png"
echo
echo "---------- VLESS LINK ----------"
echo "${VLESS_LINK}"
echo "---------- VLESS QR ------------"
qrencode -t UTF8 "${VLESS_LINK}" || true
echo
echo "---------- SS2022 LINK ---------"
echo "${SS_LINK}"
echo "---------- SS2022 QR -----------"
qrencode -t UTF8 "${SS_LINK}" || true
echo "=============================================="
