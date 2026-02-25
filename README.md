# Xray Installer

Interactive hardened installer for:
- VLESS + REALITY (TCP, `xtls-rprx-vision`)
- Shadowsocks 2022 (`2022-blake3-aes-256-gcm`)

Script file: `xray-install.sh`

## One-Click Usage (Public Repo)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Kpowered/xray-install-script/main/xray-install.sh)
```

## What the Script Supports

- Interactive menu:
  - `Install / Reinstall`
  - `Show status`
  - `Uninstall`
- Install mode choice:
  - VLESS + REALITY only
  - SS2022 only
  - Both
- Port choice during install:
  - Random high port (`20000-59999`)
  - Custom port
- Simpler install flow:
  - No SSH port prompt
  - No UFW/iptables changes
- REALITY target choice:
  - Auto random popular website (default)
  - Manual `serverNames` + `dest`
- Post-install checks:
  - `xray -test` config validation
  - `systemctl is-active xray`
  - Port listening checks (TCP/UDP)
- Share output:
  - Prints VLESS/SS links in terminal
  - Saves links file to `/root/xray-share/links.txt`
- Installer robustness:
  - Writes a temporary minimal config before official install
  - Continues setup even if official installer returns a warning
- Re-run status view:
  - Service active/enabled
  - Current inbound protocols and ports
  - Last install profile
  - Share links file location

## Clone and Run (Alternative)

```bash
git clone https://github.com/Kpowered/xray-install-script.git
cd xray-install-script
sudo bash xray-install.sh
```
