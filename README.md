# Xray Install Script

Interactive script for:
- VLESS + REALITY
- Shadowsocks 2022
- Dual-protocol installation and config management

Script file: `xray-install.sh`

## One-Click

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/Kpowered/xray-install-script/main/xray-install.sh?ts=$(date +%s)")
```

## Main Menu

After running, the script provides:
1. Install Xray (VLESS/Shadowsocks)
2. Update Xray
3. Uninstall Xray
4. Modify config
5. Restart Xray
6. View Xray logs
7. View subscription info

## Security Hardening Added

- Official installer is pinned to a fixed `XTLS/Xray-install` commit.
- SHA256 is verified before running the installer script.
- Removed direct `curl | bash` execution path.
- REALITY `shortId` is now random (not fixed).
- REALITY key parsing supports current and legacy `xray x25519` outputs.
- Config file permission is tightened (`640` root:nogroup or `600` root:root).
- Subscription export file is written with strict permission (`600`).

## Non-Interactive Example

```bash
sudo bash xray-install.sh install --type dual --vless-port 443 --ss-port 8388
```
