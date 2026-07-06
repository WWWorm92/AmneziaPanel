# Amnezia Panel Portable

## What It Does

One-shot installer for a self-hosted panel stack on Debian/Ubuntu with:

- AmneziaWG
- WireGuard
- OpenVPN
- Hysteria 2
- VLESS Reality (Xray)
- SoftEther / SSTP
- EMQX
- Fail2Ban
- Web panel

## Usage

Run as root:

```bash
chmod +x install.sh
./install.sh
```

By default the installer is interactive and asks what to install.

For unattended mode use env flags:

```bash
NONINTERACTIVE=1 \
PANEL_PUBLIC_HOST=1.2.3.4 \
PANEL_USER=admin \
PANEL_PASS='strongpass' \
INSTALL_SOFTETHER=no \
INSTALL_EMQX=no \
./install.sh
```

Component flags:

- `INSTALL_PANEL_CORE=yes|no`
- `INSTALL_FAIL2BAN=yes|no`
- `INSTALL_AMNEZIAWG=yes|no`
- `INSTALL_WIREGUARD=yes|no`
- `INSTALL_OPENVPN=yes|no`
- `INSTALL_HYSTERIA=yes|no`
- `INSTALL_VLESS=yes|no`
- `INSTALL_SOFTETHER=yes|no`
- `INSTALL_EMQX=yes|no`
- `INSTALL_OFFICE_BACKUP=yes|no`

Optional backup/NAS bootstrap via SSTP:

```bash
OFFICE_SSTP_HOST=vpn.example.com \
OFFICE_SSTP_USER=backup \
OFFICE_SSTP_PASS='secret' \
OFFICE_NAS_SHARE='//10.0.0.10/Public' \
OFFICE_NAS_USER=backup \
OFFICE_NAS_PASS='secret' \
OFFICE_NAS_MOUNT=/mnt/office-nas \
./install.sh
```

Optional EMQX public allowlist:

```bash
EMQX_ALLOW_IPS='1.2.3.4/32,5.6.7.8/32' ./install.sh
```

## Bundle Files

- `install.sh`
- `uninstall.sh`
- `panel2.py`

Keep them in the same directory.

## Notes

- Current auto-install path is built for `apt` systems.
- `amneziawg-tools` auto-install is implemented for Ubuntu.
- Existing configs are preserved where possible.
- Office backup bootstrap is optional and requires explicit env variables.
- Panel navigation hides modules that were disabled at install time.

## Uninstall

Run as root:

```bash
chmod +x uninstall.sh
./uninstall.sh
```

It can:

- stop and disable services
- remove generated files
- optionally purge packages
