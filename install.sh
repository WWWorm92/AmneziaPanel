#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log() {
  printf '%s\n' "$*"
}

section() {
  printf '\n== %s ==\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_root() {
  [ "$(id -u)" -eq 0 ] || fail "Run this installer as root"
}

apt_supported() {
  command -v apt-get >/dev/null 2>&1
}

is_true() {
  case "${1:-}" in
    1|y|Y|yes|YES|true|TRUE|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

default_iface() {
  ip route show default 2>/dev/null | awk 'NR==1 {print $5; exit}'
}

detect_public_ip() {
  local ip
  ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -n1 || true)"
  if [ -n "$ip" ]; then
    printf '%s\n' "$ip"
    return
  fi
  hostname -I 2>/dev/null | awk '{print $1}'
}

random_b64() {
  openssl rand -base64 24 | tr -d '=+/\n' | cut -c1-24
}

prompt_yes_no() {
  local var_name="$1"
  local prompt="$2"
  local default_value="$3"
  local answer current
  current="${!var_name:-$default_value}"
  if [ ! -t 0 ] || is_true "${NONINTERACTIVE:-}"; then
    printf -v "$var_name" '%s' "$current"
    return
  fi
  if is_true "$current"; then
    read -r -p "$prompt [Y/n]: " answer || true
    case "$answer" in
      n|N|no|NO) current="no" ;;
      *) current="yes" ;;
    esac
  else
    read -r -p "$prompt [y/N]: " answer || true
    case "$answer" in
      y|Y|yes|YES) current="yes" ;;
      *) current="no" ;;
    esac
  fi
  printf -v "$var_name" '%s' "$current"
}

prompt_value() {
  local var_name="$1"
  local prompt="$2"
  local default_value="$3"
  local answer current
  current="${!var_name:-$default_value}"
  if [ ! -t 0 ] || is_true "${NONINTERACTIVE:-}"; then
    printf -v "$var_name" '%s' "$current"
    return
  fi
  read -r -p "$prompt [$current]: " answer || true
  if [ -n "$answer" ]; then
    current="$answer"
  fi
  printf -v "$var_name" '%s' "$current"
}

print_plan() {
  section "Install Plan"
  log "Panel core:        ${INSTALL_PANEL_CORE}"
  log "Fail2Ban:          ${INSTALL_FAIL2BAN}"
  log "AmneziaWG:         ${INSTALL_AMNEZIAWG}"
  log "WireGuard:         ${INSTALL_WIREGUARD}"
  log "OpenVPN:           ${INSTALL_OPENVPN}"
  log "Hysteria 2:        ${INSTALL_HYSTERIA}"
  log "VLESS / Xray:      ${INSTALL_VLESS}"
  log "SoftEther / SSTP:  ${INSTALL_SOFTETHER}"
  log "EMQX:              ${INSTALL_EMQX}"
  log "Office backup:     ${INSTALL_OFFICE_BACKUP}"
}

configure_components() {
  local public_ip
  public_ip="${PANEL_PUBLIC_HOST:-$(detect_public_ip)}"

  : "${INSTALL_PANEL_CORE:=yes}"
  : "${INSTALL_FAIL2BAN:=yes}"
  : "${INSTALL_AMNEZIAWG:=yes}"
  : "${INSTALL_WIREGUARD:=yes}"
  : "${INSTALL_OPENVPN:=yes}"
  : "${INSTALL_HYSTERIA:=yes}"
  : "${INSTALL_VLESS:=yes}"
  : "${INSTALL_SOFTETHER:=yes}"
  : "${INSTALL_EMQX:=yes}"
  : "${INSTALL_OFFICE_BACKUP:=no}"

  : "${PANEL_PUBLIC_HOST:=$public_ip}"
  : "${PANEL_USER:=amnezia}"
  : "${PANEL_PASS:=$(random_b64)}"
  : "${PANEL_PORT:=8088}"
  : "${PANEL_IFACE:=awg0}"
  : "${PANEL_ENDPOINT:=${PANEL_PUBLIC_HOST}:443}"
  : "${PANEL_IPHONE_ENDPOINT:=${PANEL_PUBLIC_HOST}:443}"
  : "${PANEL_MTU:=1280}"
  : "${PANEL_SERVER_IP:=10.66.67.1}"
  : "${PANEL_SUBNET:=10.66.67.0/24}"
  : "${PANEL_WG_IFACE:=wg0}"
  : "${PANEL_WG_ENDPOINT:=${PANEL_PUBLIC_HOST}:51820}"
  : "${PANEL_WG_SUBNET:=10.77.67.0/24}"
  : "${PANEL_WG_SERVER_IP:=10.77.67.1}"
  : "${PANEL_SSTP_ADMIN_PORT:=5555}"
  : "${PANEL_SSTP_ADMIN_PASS:=SoftEther-$(random_b64)}"
  : "${PANEL_SSTP_HUB:=SSTP}"
  : "${PANEL_SSTP_HUB_PASS:=SSTP-$(random_b64)}"
  : "${PANEL_SSTP_PORT:=8443}"
  : "${PANEL_SSTP_USER:=sstpuser}"
  : "${EMQX_ALLOW_IPS:=}"

  if [ -t 0 ] && ! is_true "${NONINTERACTIVE:-}"; then
    section "Component Selection"
    prompt_yes_no INSTALL_PANEL_CORE "Install web panel core" "yes"
    prompt_yes_no INSTALL_FAIL2BAN "Install Fail2Ban" "yes"
    prompt_yes_no INSTALL_AMNEZIAWG "Install AmneziaWG" "yes"
    prompt_yes_no INSTALL_WIREGUARD "Install WireGuard" "yes"
    prompt_yes_no INSTALL_OPENVPN "Install OpenVPN" "yes"
    prompt_yes_no INSTALL_HYSTERIA "Install Hysteria 2" "yes"
    prompt_yes_no INSTALL_VLESS "Install VLESS / Xray" "yes"
    prompt_yes_no INSTALL_SOFTETHER "Install SoftEther / SSTP" "yes"
    prompt_yes_no INSTALL_EMQX "Install EMQX" "yes"
    prompt_yes_no INSTALL_OFFICE_BACKUP "Configure office SSTP/NAS backup" "no"

    section "Base Settings"
    prompt_value PANEL_PUBLIC_HOST "Public host/IP" "$PANEL_PUBLIC_HOST"
    prompt_value PANEL_USER "Panel admin user" "$PANEL_USER"
    prompt_value PANEL_PASS "Panel admin password" "$PANEL_PASS"
    prompt_value PANEL_PORT "Panel port" "$PANEL_PORT"
    if is_true "$INSTALL_EMQX"; then
      prompt_value EMQX_ALLOW_IPS "EMQX allowlist (comma-separated CIDRs, blank for VPN-only)" "$EMQX_ALLOW_IPS"
    fi
    if is_true "$INSTALL_OFFICE_BACKUP"; then
      section "Office Backup Settings"
      prompt_value OFFICE_SSTP_HOST "Office SSTP host" "${OFFICE_SSTP_HOST:-}"
      prompt_value OFFICE_SSTP_USER "Office SSTP user" "${OFFICE_SSTP_USER:-}"
      prompt_value OFFICE_SSTP_PASS "Office SSTP password" "${OFFICE_SSTP_PASS:-}"
      prompt_value OFFICE_NAS_SHARE "Office NAS share (//host/share)" "${OFFICE_NAS_SHARE:-}"
      prompt_value OFFICE_NAS_USER "Office NAS user" "${OFFICE_NAS_USER:-${OFFICE_SSTP_USER:-}}"
      prompt_value OFFICE_NAS_PASS "Office NAS password" "${OFFICE_NAS_PASS:-${OFFICE_SSTP_PASS:-}}"
      prompt_value OFFICE_NAS_MOUNT "Office NAS mount point" "${OFFICE_NAS_MOUNT:-/mnt/office-nas}"
      prompt_value OFFICE_NAS_ROUTE_IP "NAS route IP (optional)" "${OFFICE_NAS_ROUTE_IP:-}"
    fi
  fi

  print_plan
}

collect_packages() {
  local packages=()
  packages+=(python3 openssl qrencode iproute2 procps util-linux coreutils rsync tar ca-certificates curl nftables iptables jq unzip cifs-utils)

  if is_true "$INSTALL_PANEL_CORE"; then
    packages+=(cron openssh-server)
  fi
  if is_true "$INSTALL_FAIL2BAN"; then
    packages+=(fail2ban)
  fi
  if is_true "$INSTALL_WIREGUARD"; then
    packages+=(wireguard-tools)
  fi
  if is_true "$INSTALL_OPENVPN"; then
    packages+=(openvpn easy-rsa)
  fi
  if is_true "$INSTALL_SOFTETHER"; then
    packages+=(softether-vpnserver softether-vpncmd)
  fi
  if is_true "$INSTALL_OFFICE_BACKUP"; then
    packages+=(sstp-client)
  fi

  printf '%s\n' "${packages[@]}" | awk '!seen[$0]++'
}

install_packages() {
  local package_list
  package_list="$(collect_packages | xargs)"
  export DEBIAN_FRONTEND=noninteractive
  section "Installing Packages"
  apt-get update
  apt-get install -y $package_list
}

ensure_amnezia_repo() {
  if ! is_true "$INSTALL_AMNEZIAWG"; then
    return
  fi
  if command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1; then
    return
  fi
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ]; then
    fail "Automatic amneziawg-tools install is currently implemented for Ubuntu only"
  fi
  section "Installing AmneziaWG Tools"
  apt-get install -y software-properties-common gnupg
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update
  apt-get install -y amneziawg-tools
}

ensure_emqx_repo() {
  if ! is_true "$INSTALL_EMQX"; then
    return
  fi
  if dpkg -s emqx-enterprise >/dev/null 2>&1; then
    return
  fi
  section "Adding EMQX Repository"
  curl -fsSL https://packagecloud.io/install/repositories/emqx/emqx-enterprise5/script.deb.sh | bash
  apt-get update
}

install_xray() {
  if ! is_true "$INSTALL_VLESS"; then
    return
  fi
  section "Installing Xray"
  local tmpdir=/tmp/opencode/xray-install
  mkdir -p "$tmpdir"
  if [ ! -x /usr/local/bin/xray ]; then
    curl -fsSL --retry 5 --retry-delay 2 https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip -o "$tmpdir/xray.zip"
    rm -rf "$tmpdir/xray"
    unzip -oq "$tmpdir/xray.zip" -d "$tmpdir/xray"
    install -m 0755 "$tmpdir/xray/xray" /usr/local/bin/xray
  fi
}

install_hysteria() {
  if ! is_true "$INSTALL_HYSTERIA"; then
    return
  fi
  section "Installing Hysteria"
  if [ ! -x /usr/local/bin/hysteria ]; then
    curl -fsSL --retry 5 --retry-delay 2 https://github.com/apernet/hysteria/releases/download/app/v2.9.2/hysteria-linux-amd64 -o /usr/local/bin/hysteria
    chmod 0755 /usr/local/bin/hysteria
  fi
}

ensure_dirs() {
  install -d -m 0755 /opt/amnezia-panel /var/lib/amnezia-panel /var/lib/amnezia-panel/profiles /var/backups/server-panel
  install -d -m 0755 /etc/amnezia/amneziawg /etc/wireguard /etc/hysteria /etc/xray /etc/openvpn/server /etc/openvpn/easy-rsa /var/log/openvpn/server
}

install_panel_files() {
  if ! is_true "$INSTALL_PANEL_CORE"; then
    return
  fi
  section "Installing Panel Files"
  [ -f "$SCRIPT_DIR/panel2.py" ] || fail "panel2.py not found next to installer"
  install -m 0644 "$SCRIPT_DIR/panel2.py" /opt/amnezia-panel/panel2.py
}

ensure_env() {
  if ! is_true "$INSTALL_PANEL_CORE"; then
    return
  fi
  if [ ! -f /etc/amnezia-panel.env ]; then
    section "Writing Panel Environment"
    cat > /etc/amnezia-panel.env <<EOF
PANEL_USER=${PANEL_USER}
PANEL_PASS=${PANEL_PASS}
PANEL_HOST=0.0.0.0
PANEL_PORT=${PANEL_PORT}
PANEL_IFACE=${PANEL_IFACE}
PANEL_ENDPOINT=${PANEL_ENDPOINT}
PANEL_IPHONE_ENDPOINT=${PANEL_IPHONE_ENDPOINT}
PANEL_MTU=${PANEL_MTU}
PANEL_SERVER_IP=${PANEL_SERVER_IP}
PANEL_SUBNET=${PANEL_SUBNET}
PANEL_WG_IFACE=${PANEL_WG_IFACE}
PANEL_WG_ENDPOINT=${PANEL_WG_ENDPOINT}
PANEL_WG_SUBNET=${PANEL_WG_SUBNET}
PANEL_WG_SERVER_IP=${PANEL_WG_SERVER_IP}
PANEL_SSTP_HOST=127.0.0.1
PANEL_SSTP_ADMIN_PORT=${PANEL_SSTP_ADMIN_PORT}
PANEL_SSTP_ADMIN_PASS=${PANEL_SSTP_ADMIN_PASS}
PANEL_SSTP_HUB=${PANEL_SSTP_HUB}
PANEL_SSTP_HUB_PASS=${PANEL_SSTP_HUB_PASS}
PANEL_SSTP_PORT=${PANEL_SSTP_PORT}
PANEL_SSTP_USER=${PANEL_SSTP_USER}
EOF
    chmod 0600 /etc/amnezia-panel.env
  fi
}

load_env() {
  if ! is_true "$INSTALL_PANEL_CORE"; then
    return
  fi
  set -a
  # shellcheck disable=SC1091
  . /etc/amnezia-panel.env
  set +a
}

write_sysctl() {
  section "Enabling IP Forwarding"
  cat > /etc/sysctl.d/99-amnezia-panel.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

ensure_panel_users() {
  if ! is_true "$INSTALL_PANEL_CORE"; then
    return
  fi
  if [ ! -f /var/lib/amnezia-panel/panel_users.json ]; then
    cat > /var/lib/amnezia-panel/panel_users.json <<EOF
[
  {
    "username": "${PANEL_USER}",
    "password": "${PANEL_PASS}",
    "is_admin": true,
    "totp_enabled": false,
    "totp_secret": ""
  }
]
EOF
  fi
}

ensure_state_files() {
  [ -f /var/lib/amnezia-panel/state.json ] || printf '{"clients": []}\n' > /var/lib/amnezia-panel/state.json
  [ -f /var/lib/amnezia-panel/wireguard_clients.json ] || printf '[]\n' > /var/lib/amnezia-panel/wireguard_clients.json
  [ -f /var/lib/amnezia-panel/openvpn_clients.json ] || printf '[]\n' > /var/lib/amnezia-panel/openvpn_clients.json
  [ -f /var/lib/amnezia-panel/hysteria_clients.json ] || printf '[]\n' > /var/lib/amnezia-panel/hysteria_clients.json
  [ -f /var/lib/amnezia-panel/vless_clients.json ] || printf '[]\n' > /var/lib/amnezia-panel/vless_clients.json
}

firewall_exec_lines() {
  local protocol port
  while IFS=: read -r protocol port; do
    [ -n "$protocol" ] || continue
    printf "  /usr/sbin/iptables -w 5 -C INPUT -p %s --dport %s -j ACCEPT 2>/dev/null || /usr/sbin/iptables -w 5 -I INPUT 1 -p %s --dport %s -j ACCEPT; \\\n" "$protocol" "$port" "$protocol" "$port"
  done
}

firewall_stop_lines() {
  local protocol port
  while IFS=: read -r protocol port; do
    [ -n "$protocol" ] || continue
    printf "  /usr/sbin/iptables -w 5 -D INPUT -p %s --dport %s -j ACCEPT 2>/dev/null || true; \\\n" "$protocol" "$port"
  done
}

selected_panel_ports() {
  printf '%s\n' 'tcp:22'
  if is_true "$INSTALL_PANEL_CORE"; then
    printf '%s\n' "tcp:${PANEL_PORT}"
  fi
  if is_true "$INSTALL_AMNEZIAWG"; then
    printf '%s\n' 'udp:443'
  fi
  if is_true "$INSTALL_WIREGUARD"; then
    printf '%s\n' 'udp:51820'
  fi
  if is_true "$INSTALL_OPENVPN"; then
    printf '%s\n' 'udp:1194'
  fi
  if is_true "$INSTALL_HYSTERIA"; then
    printf '%s\n' 'udp:8448'
  fi
  if is_true "$INSTALL_VLESS"; then
    printf '%s\n' 'tcp:8449'
  fi
  if is_true "$INSTALL_SOFTETHER"; then
    printf '%s\n' "tcp:${PANEL_SSTP_PORT}"
    printf '%s\n' "tcp:${PANEL_SSTP_ADMIN_PORT}"
  fi
}

write_service_units() {
  section "Writing Service Units"

  if is_true "$INSTALL_PANEL_CORE"; then
    cat > /etc/systemd/system/amnezia-panel.service <<'EOF'
[Unit]
Description=AmneziaWG Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/amnezia-panel.env
ExecStart=/usr/bin/python3 /opt/amnezia-panel/panel2.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_AMNEZIAWG"; then
    cat > /etc/systemd/system/awg-quick@.service <<'EOF'
[Unit]
Description=AmneziaWG via awg-quick for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
PartOf=awg-quick.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/awg-quick up %i
ExecStop=/usr/bin/awg-quick down %i
ExecReload=/usr/bin/awg-quick save %i
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_VLESS"; then
    cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray VLESS Reality
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c /etc/xray/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_HYSTERIA"; then
    cat > /etc/systemd/system/hysteria2.service <<'EOF'
[Unit]
Description=Hysteria 2 Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_OPENVPN"; then
    cat > /etc/systemd/system/openvpn-iptables.service <<EOF
[Unit]
Description=OpenVPN NAT rules
After=network-online.target openvpn-server@server.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o ${WAN_IFACE} -j MASQUERADE || /usr/sbin/iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ${WAN_IFACE} -j MASQUERADE'
ExecStop=/usr/sbin/iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o ${WAN_IFACE} -j MASQUERADE

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_PANEL_CORE"; then
    local start_rules stop_rules
    start_rules="$(selected_panel_ports | firewall_exec_lines)"
    stop_rules="$(selected_panel_ports | firewall_stop_lines)"
    cat > /etc/systemd/system/amnezia-panel-firewall.service <<EOF
[Unit]
Description=Open selected panel stack ports
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '\
${start_rules%\\\n}'
ExecStop=/bin/sh -c '\
${stop_rules%\\\n}'

[Install]
WantedBy=multi-user.target
EOF
  fi

  if is_true "$INSTALL_PANEL_CORE"; then
    cat > /etc/systemd/system/server-panel-backup.service <<'EOF'
[Unit]
Description=Server Panel Backup

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/amnezia-panel/panel2.py --run-backup
EOF

    cat > /etc/systemd/system/server-panel-backup.timer <<'EOF'
[Unit]
Description=Server Panel Backup Timer

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
  fi
}

ensure_fail2ban() {
  if ! is_true "$INSTALL_FAIL2BAN"; then
    return
  fi
  section "Configuring Fail2Ban"
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
EOF
}

generate_awg_server() {
  if ! is_true "$INSTALL_AMNEZIAWG"; then
    return
  fi
  section "Configuring AmneziaWG"
  if [ ! -f /etc/amnezia/amneziawg/awg0.key ]; then
    umask 077
    awg genkey > /etc/amnezia/amneziawg/awg0.key
  fi
  if [ ! -f /etc/amnezia/amneziawg/awg0.pub ]; then
    awg pubkey < /etc/amnezia/amneziawg/awg0.key > /etc/amnezia/amneziawg/awg0.pub
  fi
  if [ ! -f /etc/amnezia/amneziawg/awg0.conf ]; then
    cat > /etc/amnezia/amneziawg/awg0.conf <<EOF
[Interface]
Address = ${PANEL_SERVER_IP}/24
ListenPort = 443
PrivateKey = $(tr -d '\n' < /etc/amnezia/amneziawg/awg0.key)
Jc = 4
Jmin = 8
Jmax = 80
S1 = 16
S2 = 16
S3 = 16
S4 = 8
H1 = 1000-1099
H2 = 1100-1199
H3 = 1200-1299
H4 = 1300-1399
I1 = <b 0x0800000001><rc 8><t><r 50>
PostUp = iptables -t nat -A POSTROUTING -s ${PANEL_SUBNET} -o ${WAN_IFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${PANEL_SUBNET} -o ${WAN_IFACE} -j MASQUERADE
EOF
    chmod 600 /etc/amnezia/amneziawg/awg0.conf
  fi
  ln -sf /etc/amnezia/amneziawg/awg0.conf /etc/wireguard/awg0.conf
}

generate_wg_server() {
  if ! is_true "$INSTALL_WIREGUARD"; then
    return
  fi
  section "Configuring WireGuard"
  if [ ! -f /etc/wireguard/wg0.key ]; then
    umask 077
    wg genkey > /etc/wireguard/wg0.key
  fi
  if [ ! -f /etc/wireguard/wg0.pub ]; then
    wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub
  fi
  if [ ! -f /etc/wireguard/wg0.conf ]; then
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${PANEL_WG_SERVER_IP}/24
ListenPort = 51820
PrivateKey = $(tr -d '\n' < /etc/wireguard/wg0.key)
SaveConfig = true
Table = auto
PostUp = iptables -t nat -A POSTROUTING -s ${PANEL_WG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s ${PANEL_WG_SUBNET} -o ${WAN_IFACE} -j MASQUERADE
EOF
    chmod 600 /etc/wireguard/wg0.conf
  fi
}

ensure_hysteria_config() {
  if ! is_true "$INSTALL_HYSTERIA"; then
    return
  fi
  section "Configuring Hysteria"
  if [ ! -f /etc/hysteria/server.crt ] || [ ! -f /etc/hysteria/server.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=${PANEL_PUBLIC_HOST}"
    chmod 600 /etc/hysteria/server.key
  fi
  if [ ! -f /etc/hysteria/config.yaml ]; then
    cat > /etc/hysteria/config.yaml <<EOF
listen: :8448

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: userpass
  userpass:
    __internal__: $(openssl rand -hex 16)

masquerade:
  type: proxy
  proxy:
    url: https://www.cloudflare.com/
    rewriteHost: true
EOF
  fi
}

ensure_xray_config() {
  if ! is_true "$INSTALL_VLESS"; then
    return
  fi
  section "Configuring VLESS / Xray"
  local keypair private_key public_key
  if [ ! -f /etc/xray/reality.key ] || [ ! -f /etc/xray/reality.pub ]; then
    keypair="$(xray x25519)"
    private_key="$(printf '%s\n' "$keypair" | awk -F': ' '/^PrivateKey:/ {print $2; exit}')"
    public_key="$(printf '%s\n' "$keypair" | awk -F': ' '/^Password \(PublicKey\):/ {print $2; exit}')"
    [ -n "$private_key" ] || fail "Could not generate Xray private key"
    [ -n "$public_key" ] || fail "Could not generate Xray public key"
    printf '%s\n' "$private_key" > /etc/xray/reality.key
    printf '%s\n' "$public_key" > /etc/xray/reality.pub
    chmod 600 /etc/xray/reality.key
  fi
  if [ ! -f /etc/xray/config.json ]; then
    cat > /etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 8449,
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": [
            "www.cloudflare.com"
          ],
          "privateKey": "$(tr -d '\n' < /etc/xray/reality.key)",
          "shortIds": [
            "d51bff7d"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
  fi
}

setup_openvpn() {
  if ! is_true "$INSTALL_OPENVPN"; then
    return
  fi
  section "Configuring OpenVPN"
  if [ ! -f /etc/openvpn/server/server.conf ]; then
    cat > /etc/openvpn/server/server.conf <<'EOF'
port 1194
proto udp
dev tun
user nobody
group nogroup
persist-key
persist-tun
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/server/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
tls-version-min 1.2
tls-server
cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
ca /etc/openvpn/server/pki/ca.crt
cert /etc/openvpn/server/pki/issued/server.crt
key /etc/openvpn/server/pki/private/server.key
dh /etc/openvpn/server/pki/dh.pem
tls-crypt /etc/openvpn/server/ta.key
crl-verify /etc/openvpn/server/pki/crl.pem
verb 3
EOF
  fi
  if [ ! -f /etc/openvpn/server/ta.key ]; then
    openvpn --genkey secret /etc/openvpn/server/ta.key
  fi
  if [ ! -f /etc/openvpn/server/pki/ca.crt ]; then
    rm -rf /etc/openvpn/easy-rsa/pki
    cp -a /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    (cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa init-pki)
    (cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa build-ca nopass)
    (cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-dh)
    (cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass)
    (cd /etc/openvpn/easy-rsa && EASYRSA_BATCH=1 ./easyrsa gen-crl)
    cp -a /etc/openvpn/easy-rsa/pki /etc/openvpn/server/
    chmod 600 /etc/openvpn/server/pki/private/server.key
  fi
}

setup_softether() {
  if ! is_true "$INSTALL_SOFTETHER"; then
    return
  fi
  section "Configuring SoftEther / SSTP"
  if ! systemctl cat softether-vpnserver.service >/dev/null 2>&1; then
    warn "softether-vpnserver.service not found after package install"
    return
  fi
  systemctl enable --now softether-vpnserver.service >/dev/null 2>&1 || true
  local vpncmd
  vpncmd="$(command -v vpncmd || true)"
  [ -n "$vpncmd" ] || { warn "vpncmd not found"; return; }
  cat > /tmp/opencode/softether-server.txt <<EOF
ServerPasswordSet /PASSWORD:${PANEL_SSTP_ADMIN_PASS}
ListenerCreate ${PANEL_SSTP_ADMIN_PORT}
ListenerCreate ${PANEL_SSTP_PORT}
SstpEnable yes
HubCreate ${PANEL_SSTP_HUB} /PASSWORD:${PANEL_SSTP_HUB_PASS}
EOF
  "$vpncmd" localhost /SERVER /IN:/tmp/opencode/softether-server.txt >/dev/null 2>&1 || true
  cat > /tmp/opencode/softether-hub.txt <<EOF
SecureNatEnable
UserCreate ${PANEL_SSTP_USER} /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet ${PANEL_SSTP_USER} /PASSWORD:${PANEL_SSTP_HUB_PASS}
EOF
  "$vpncmd" localhost /SERVER "/HUB:${PANEL_SSTP_HUB}" "/PASSWORD:${PANEL_SSTP_HUB_PASS}" /IN:/tmp/opencode/softether-hub.txt >/dev/null 2>&1 || true
}

setup_emqx() {
  if ! is_true "$INSTALL_EMQX"; then
    return
  fi
  section "Installing and Configuring EMQX"
  apt-get install -y emqx-enterprise
  local allow_lines=""
  local ip oldifs
  if [ -n "$EMQX_ALLOW_IPS" ]; then
    oldifs="$IFS"
    IFS=','
    for ip in $EMQX_ALLOW_IPS; do
      ip="$(printf '%s' "$ip" | xargs)"
      [ -n "$ip" ] || continue
      allow_lines="${allow_lines}  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -s ${ip} -j RETURN; \\
"
    done
    IFS="$oldifs"
  fi
  cat > /etc/systemd/system/emqx-firewall.service <<EOF
[Unit]
Description=Restrict EMQX access to approved sources
After=network-online.target
Before=emqx.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '\
  /usr/sbin/iptables -w 5 -N EMQX_ACCESS 2>/dev/null || true; \
  /usr/sbin/iptables -w 5 -F EMQX_ACCESS; \
  /usr/sbin/iptables -w 5 -C INPUT -p tcp -m multiport --dports 1883,8883,8083,8084,18083,4370,5370 -j EMQX_ACCESS 2>/dev/null || /usr/sbin/iptables -w 5 -I INPUT 1 -p tcp -m multiport --dports 1883,8883,8083,8084,18083,4370,5370 -j EMQX_ACCESS; \
  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -s 127.0.0.0/8 -j RETURN; \
${allow_lines}  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -s ${PANEL_SUBNET} -j RETURN; \
  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -s ${PANEL_WG_SUBNET} -j RETURN; \
  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -s 10.8.0.0/24 -j RETURN; \
  /usr/sbin/iptables -w 5 -A EMQX_ACCESS -j REJECT'
ExecStop=/bin/sh -c '\
  /usr/sbin/iptables -w 5 -D INPUT -p tcp -m multiport --dports 1883,8883,8083,8084,18083,4370,5370 -j EMQX_ACCESS 2>/dev/null || true; \
  /usr/sbin/iptables -w 5 -F EMQX_ACCESS 2>/dev/null || true; \
  /usr/sbin/iptables -w 5 -X EMQX_ACCESS 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
}

setup_optional_office_backup() {
  if ! is_true "$INSTALL_OFFICE_BACKUP"; then
    return
  fi
  is_true "$INSTALL_PANEL_CORE" || fail "Office backup bootstrap requires panel core"
  [ -n "${OFFICE_SSTP_HOST:-}" ] || fail "OFFICE_SSTP_HOST is required for office backup"
  [ -n "${OFFICE_SSTP_USER:-}" ] || fail "OFFICE_SSTP_USER is required for office backup"
  [ -n "${OFFICE_SSTP_PASS:-}" ] || fail "OFFICE_SSTP_PASS is required for office backup"
  [ -n "${OFFICE_NAS_SHARE:-}" ] || fail "OFFICE_NAS_SHARE is required for office backup"

  section "Configuring Office SSTP/NAS Backup"
  local route_ip mount_point nas_host creds_file
  mount_point="${OFFICE_NAS_MOUNT:-/mnt/office-nas}"
  nas_host="$(printf '%s' "$OFFICE_NAS_SHARE" | sed 's#^//##' | cut -d/ -f1)"
  route_ip="${OFFICE_NAS_ROUTE_IP:-$nas_host}"
  creds_file=/etc/samba/credentials-office-nas

  install -d -m 0755 /etc/samba "$mount_point"
  cat > "$creds_file" <<EOF
username=${OFFICE_NAS_USER:-${OFFICE_SSTP_USER}}
password=${OFFICE_NAS_PASS:-${OFFICE_SSTP_PASS}}
EOF
  chmod 600 "$creds_file"

  cat > /etc/systemd/system/office-sstp.service <<EOF
[Unit]
Description=Office SSTP client for NAS-only route
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/sstpc --cert-warn --tls-ext --user ${OFFICE_SSTP_USER} --password ${OFFICE_SSTP_PASS} --save-server-route ${OFFICE_SSTP_HOST} noauth refuse-eap refuse-pap refuse-chap nodefaultroute noipdefault ipparam office-sstp
ExecStartPost=/bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do /usr/sbin/ip link show ppp0 >/dev/null 2>&1 && /usr/sbin/ip route replace ${route_ip}/32 dev ppp0 && exit 0; sleep 1; done; exit 1'
ExecStopPost=/usr/sbin/ip route del ${route_ip}/32 dev ppp0 2>/dev/null || true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/office-sstp-firewall.service <<EOF
[Unit]
Description=Block forwarded VPN-client access to office NAS
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/iptables -C FORWARD -d ${route_ip}/32 -j REJECT 2>/dev/null || /usr/sbin/iptables -I FORWARD 1 -d ${route_ip}/32 -j REJECT; /usr/sbin/iptables -C FORWARD -s ${route_ip}/32 -j REJECT 2>/dev/null || /usr/sbin/iptables -I FORWARD 1 -s ${route_ip}/32 -j REJECT'
ExecStop=/bin/sh -c '/usr/sbin/iptables -D FORWARD -d ${route_ip}/32 -j REJECT 2>/dev/null || true; /usr/sbin/iptables -D FORWARD -s ${route_ip}/32 -j REJECT 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

  if ! grep -Fq "${OFFICE_NAS_SHARE} ${mount_point} cifs" /etc/fstab; then
    printf '%s\n' "${OFFICE_NAS_SHARE} ${mount_point} cifs credentials=${creds_file},vers=3.0,iocharset=utf8,_netdev,nofail,x-systemd.requires=office-sstp.service,x-systemd.after=office-sstp.service 0 0" >> /etc/fstab
  fi
}

enable_unit_if_exists() {
  local unit="$1"
  if systemctl cat "$unit" >/dev/null 2>&1; then
    systemctl enable --now "$unit" >/dev/null 2>&1 || true
    log "enabled: $unit"
  fi
}

start_selected_units() {
  section "Enabling Services"
  systemctl daemon-reload
  if is_true "$INSTALL_PANEL_CORE"; then
    enable_unit_if_exists ssh.service
    enable_unit_if_exists ssh.socket
    enable_unit_if_exists cron.service
    enable_unit_if_exists amnezia-panel-firewall.service
    enable_unit_if_exists amnezia-panel.service
    enable_unit_if_exists server-panel-backup.timer
  fi
  if is_true "$INSTALL_FAIL2BAN"; then
    enable_unit_if_exists fail2ban.service
  fi
  if is_true "$INSTALL_AMNEZIAWG"; then
    enable_unit_if_exists awg-quick@awg0.service
  fi
  if is_true "$INSTALL_WIREGUARD"; then
    enable_unit_if_exists wg-quick@wg0.service
  fi
  if is_true "$INSTALL_OPENVPN"; then
    enable_unit_if_exists openvpn-server@server.service
    enable_unit_if_exists openvpn-iptables.service
  fi
  if is_true "$INSTALL_HYSTERIA"; then
    enable_unit_if_exists hysteria2.service
  fi
  if is_true "$INSTALL_VLESS"; then
    enable_unit_if_exists xray.service
  fi
  if is_true "$INSTALL_SOFTETHER"; then
    enable_unit_if_exists softether-vpnserver.service
  fi
  if is_true "$INSTALL_EMQX"; then
    enable_unit_if_exists emqx-firewall.service
    enable_unit_if_exists emqx.service
  fi
  if is_true "$INSTALL_OFFICE_BACKUP"; then
    enable_unit_if_exists office-sstp.service
    enable_unit_if_exists office-sstp-firewall.service
  fi
}

print_summary() {
  section "Summary"
  log "Panel URL:          http://${PANEL_PUBLIC_HOST}:${PANEL_PORT}"
  log "Panel user:         ${PANEL_USER}"
  log "Panel password:     ${PANEL_PASS}"
  if is_true "$INSTALL_AMNEZIAWG"; then
    log "AmneziaWG:          udp/${PANEL_ENDPOINT##*:} on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_WIREGUARD"; then
    log "WireGuard:          udp/${PANEL_WG_ENDPOINT##*:} on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_OPENVPN"; then
    log "OpenVPN:            udp/1194 on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_HYSTERIA"; then
    log "Hysteria:           udp/8448 on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_VLESS"; then
    log "VLESS Reality:      tcp/8449 on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_SOFTETHER"; then
    log "SoftEther / SSTP:   tcp/${PANEL_SSTP_PORT} on ${PANEL_PUBLIC_HOST}"
  fi
  if is_true "$INSTALL_EMQX"; then
    log "EMQX dashboard:     http://${PANEL_PUBLIC_HOST}:18083"
  fi
}

main() {
  need_root
  apt_supported || fail "This installer currently supports Debian/Ubuntu with apt"
  WAN_IFACE="$(default_iface)"
  [ -n "$WAN_IFACE" ] || WAN_IFACE="eth0"

  configure_components
  install_packages
  ensure_amnezia_repo
  ensure_emqx_repo
  install_xray
  install_hysteria
  ensure_dirs
  install_panel_files
  ensure_env
  load_env
  write_sysctl
  ensure_panel_users
  ensure_state_files
  write_service_units
  ensure_fail2ban
  generate_awg_server
  generate_wg_server
  ensure_hysteria_config
  ensure_xray_config
  setup_openvpn
  setup_softether
  setup_emqx
  setup_optional_office_backup
  start_selected_units
  print_summary
}

main "$@"
