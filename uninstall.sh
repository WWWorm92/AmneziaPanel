#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_root() {
  [ "$(id -u)" -eq 0 ] || fail "Run this uninstaller as root"
}

is_true() {
  case "${1:-}" in
    1|y|Y|yes|YES|true|TRUE|on|ON) return 0 ;;
    *) return 1 ;;
  esac
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

stop_disable() {
  local unit="$1"
  if systemctl cat "$unit" >/dev/null 2>&1; then
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    log "disabled: $unit"
  fi
}

remove_path() {
  local target="$1"
  if [ -e "$target" ] || [ -L "$target" ]; then
    rm -rf "$target"
    log "removed: $target"
  fi
}

remove_packages() {
  if ! is_true "$REMOVE_PACKAGES"; then
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get remove -y --purge \
    fail2ban \
    openvpn \
    easy-rsa \
    wireguard-tools \
    softether-vpnserver \
    softether-vpncmd \
    emqx-enterprise \
    sstp-client || true
  apt-get autoremove -y || true
}

main() {
  need_root

  : "${REMOVE_DATA:=no}"
  : "${REMOVE_PACKAGES:=no}"
  : "${REMOVE_EMQX_DATA:=no}"

  prompt_yes_no REMOVE_DATA "Remove panel state, profiles and generated VPN configs" "no"
  prompt_yes_no REMOVE_PACKAGES "Remove installed packages too" "no"
  prompt_yes_no REMOVE_EMQX_DATA "Remove EMQX data directory" "no"

  stop_disable amnezia-panel.service
  stop_disable amnezia-panel-firewall.service
  stop_disable awg-quick@awg0.service
  stop_disable wg-quick@wg0.service
  stop_disable openvpn-server@server.service
  stop_disable openvpn-iptables.service
  stop_disable hysteria2.service
  stop_disable xray.service
  stop_disable softether-vpnserver.service
  stop_disable office-sstp.service
  stop_disable office-sstp-firewall.service
  stop_disable server-panel-backup.timer
  stop_disable emqx-firewall.service
  stop_disable emqx.service

  remove_path /etc/systemd/system/amnezia-panel.service
  remove_path /etc/systemd/system/amnezia-panel-firewall.service
  remove_path /etc/systemd/system/awg-quick@.service
  remove_path /etc/systemd/system/openvpn-iptables.service
  remove_path /etc/systemd/system/hysteria2.service
  remove_path /etc/systemd/system/xray.service
  remove_path /etc/systemd/system/office-sstp.service
  remove_path /etc/systemd/system/office-sstp-firewall.service
  remove_path /etc/systemd/system/server-panel-backup.service
  remove_path /etc/systemd/system/server-panel-backup.timer
  remove_path /etc/systemd/system/emqx-firewall.service
  remove_path /etc/sysctl.d/99-amnezia-panel.conf

  if is_true "$REMOVE_DATA"; then
    remove_path /opt/amnezia-panel
    remove_path /var/lib/amnezia-panel
    remove_path /var/backups/server-panel
    remove_path /etc/amnezia-panel.env
    remove_path /etc/amnezia/amneziawg/awg0.conf
    remove_path /etc/amnezia/amneziawg/awg0.key
    remove_path /etc/amnezia/amneziawg/awg0.pub
    remove_path /etc/wireguard/awg0.conf
    remove_path /etc/wireguard/wg0.conf
    remove_path /etc/wireguard/wg0.key
    remove_path /etc/wireguard/wg0.pub
    remove_path /etc/hysteria
    remove_path /etc/xray
    remove_path /etc/openvpn/server
    remove_path /etc/openvpn/easy-rsa
    if is_true "$REMOVE_EMQX_DATA"; then
      remove_path /var/lib/emqx
      remove_path /etc/emqx
    fi
  fi

  remove_packages

  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true

  log "Done."
}

main "$@"
