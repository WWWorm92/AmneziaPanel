#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import pwd
import re
import shutil
import secrets
import subprocess
import shlex
import sys
import time
import tempfile
import threading
import uuid
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse, quote


CFG = {
    "iface": os.environ.get("PANEL_IFACE", "awg0"),
    "endpoint": os.environ.get("PANEL_ENDPOINT", "185.188.181.150:1234"),
    "server_ip": os.environ.get("PANEL_SERVER_IP", "10.66.67.1"),
    "subnet": os.environ.get("PANEL_SUBNET", "10.66.67.0/24"),
    "auth_user": os.environ.get("PANEL_USER", "amnezia"),
    "auth_pass": os.environ.get("PANEL_PASS", ""),
    "state_dir": Path(os.environ.get("PANEL_STATE_DIR", "/var/lib/amnezia-panel")),
    "profile_dir": Path(os.environ.get("PANEL_PROFILE_DIR", "/var/lib/amnezia-panel/profiles")),
    "softether_host": os.environ.get("PANEL_SSTP_HOST", "127.0.0.1"),
    "softether_port": os.environ.get("PANEL_SSTP_ADMIN_PORT", "5555"),
    "softether_admin_password": os.environ.get("PANEL_SSTP_ADMIN_PASS", "SoftEther-Admin-2026!"),
    "softether_hub": os.environ.get("PANEL_SSTP_HUB", "SSTP"),
    "softether_hub_password": os.environ.get("PANEL_SSTP_HUB_PASS", "SSTP_Hub_2026!"),
    "softether_listener_port": os.environ.get("PANEL_SSTP_PORT", "8443"),
    "softether_default_user": os.environ.get("PANEL_SSTP_USER", "sstpuser"),
}

CFG["state_file"] = CFG["state_dir"] / "state.json"
CFG["panel_users_file"] = CFG["state_dir"] / "panel_users.json"
CFG["ssh_issued_keys_file"] = CFG["state_dir"] / "ssh_issued_keys.json"
CFG["hysteria_clients_file"] = CFG["state_dir"] / "hysteria_clients.json"
CFG["vless_clients_file"] = CFG["state_dir"] / "vless_clients.json"
CFG["openvpn_clients_file"] = CFG["state_dir"] / "openvpn_clients.json"
CFG["wireguard_clients_file"] = CFG["state_dir"] / "wireguard_clients.json"
CFG["audit_file"] = CFG["state_dir"] / "audit.log"
CFG["settings_file"] = CFG["state_dir"] / "settings.json"
CFG["backup_settings_file"] = CFG["state_dir"] / "backup_settings.json"
CFG["backup_dir"] = Path(os.environ.get("PANEL_BACKUP_DIR", "/var/backups/server-panel"))
CFG["server_pubkey"] = os.environ.get("PANEL_SERVER_PUBKEY", "")
CFG["wireguard_iface"] = os.environ.get("PANEL_WG_IFACE", "wg0")
CFG["wireguard_endpoint"] = os.environ.get("PANEL_WG_ENDPOINT", "185.188.181.150:51820")
CFG["wireguard_subnet"] = os.environ.get("PANEL_WG_SUBNET", "10.77.67.0/24")
CFG["wireguard_server_ip"] = os.environ.get("PANEL_WG_SERVER_IP", "10.77.67.1")
CFG["wireguard_server_key"] = Path(os.environ.get("PANEL_WG_SERVER_KEY", "/etc/wireguard/wg0.key"))
CFG["wireguard_server_pub"] = Path(os.environ.get("PANEL_WG_SERVER_PUB", "/etc/wireguard/wg0.pub"))
CFG["template_i1"] = os.environ.get("PANEL_I1", "<b 0x0800000001><rc 8><t><r 50>")
CFG["template_jc"] = os.environ.get("PANEL_JC", "4")
CFG["template_jmin"] = os.environ.get("PANEL_JMIN", "8")
CFG["template_jmax"] = os.environ.get("PANEL_JMAX", "80")
CFG["template_s1"] = os.environ.get("PANEL_S1", "16")
CFG["template_s2"] = os.environ.get("PANEL_S2", "16")
CFG["template_s3"] = os.environ.get("PANEL_S3", "16")
CFG["template_s4"] = os.environ.get("PANEL_S4", "8")
CFG["template_h1"] = os.environ.get("PANEL_H1", "1000-1099")
CFG["template_h2"] = os.environ.get("PANEL_H2", "1100-1199")
CFG["template_h3"] = os.environ.get("PANEL_H3", "1200-1299")
CFG["template_h4"] = os.environ.get("PANEL_H4", "1300-1399")
CFG["template_mtu"] = os.environ.get("PANEL_MTU", "1280")
CFG["iphone_endpoint"] = os.environ.get("PANEL_IPHONE_ENDPOINT", "netherwww.ru:1234")

SESSION_COOKIE = os.environ.get("PANEL_SESSION_COOKIE", "amnezia_panel_session")
PENDING_2FA_COOKIE = os.environ.get("PANEL_PENDING_2FA_COOKIE", "amnezia_panel_2fa")
SESSION_TTL = int(os.environ.get("PANEL_SESSION_TTL", "43200"))
PANEL_VERSION = "2026-06-04c"

NAV_ITEMS = [
    ("home", "/", "dashboard", "Обзор"),
    ("system", "/system", "system", "Система"),
    ("amnezia", "/amnezia", "amnezia", "Amnezia"),
    ("wireguard", "/wireguard", "wireguard", "WireGuard"),
    ("openvpn", "/openvpn", "openvpn", "OpenVPN"),
    ("hysteria", "/hysteria", "hysteria", "Hysteria"),
    ("vless", "/vless", "vless", "VLESS"),
    ("services", "/services", "services", "Сервисы"),
    ("server-users", "/server-users", "users", "SSH и ОС"),
    ("storage", "/storage", "server", "Диски"),
    ("processes", "/processes", "chart", "Процессы"),
    ("logs", "/logs", "configs", "Логи"),
    ("sstp", "/sstp", "sstp", "SSTP"),
    ("tasks", "/tasks", "services", "Задачи"),
    ("domains", "/domains", "shield", "Домены"),
    ("fail2ban", "/fail2ban", "shield", "Fail2Ban"),
    ("audit", "/audit", "system", "Аудит"),
    ("panel-users", "/panel-users", "users", "Пользователи панели"),
    ("configs", "/configs", "configs", "Конфиги"),
    ("firewall", "/firewall", "firewall", "Фаервол"),
]

NAV_GROUPS = [
    ("Основное", ["home", "system"]),
    ("VPN", ["amnezia", "wireguard", "openvpn", "hysteria", "vless"]),
    ("Сервер", ["services", "server-users", "storage", "processes", "logs", "tasks"]),
    ("Сеть", ["sstp", "domains", "firewall"]),
    ("Администрирование", ["fail2ban", "audit", "panel-users", "configs"]),
]

NAV_FEATURES = {
    "amnezia": "amneziawg",
    "wireguard": "wireguard",
    "openvpn": "openvpn",
    "hysteria": "hysteria",
    "vless": "vless",
    "sstp": "sstp",
    "fail2ban": "fail2ban",
}


def icon(name):
    icons = {
        "login": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M10 17l5-5-5-5'/><path d='M15 12H3'/><path d='M21 4v16'/></svg>",
        "menu": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 7h16'/><path d='M4 12h16'/><path d='M4 17h16'/></svg>",
        "dashboard": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 11h6v9H4z'/><path d='M14 4h6v16h-6z'/><path d='M4 4h6v5H4z'/></svg>",
        "clients": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M17 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2'/><circle cx='10' cy='7' r='4'/><path d='M23 21v-2a4 4 0 0 0-3-3.87'/><path d='M16 3.13a4 4 0 0 1 0 7.75'/></svg>",
        "amnezia": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l6 3v6l-6 3-6-3V6z'/><path d='M12 12V21'/><path d='M6 6l6 3 6-3'/><path d='M9 9l3 1.5L15 9'/></svg>",
        "wireguard": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l7 4v5c0 4-2.8 7.6-7 9-4.2-1.4-7-5-7-9V7z'/><path d='M8.5 11h7'/><path d='M10 8.5l2 2 2-2'/><path d='M10 13.5l2-2 2 2'/></svg>",
        "openvpn": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M6 18h12'/><path d='M8 18V9a4 4 0 0 1 8 0v9'/><path d='M9 12h6'/><path d='M12 15v3'/><path d='M10.5 18v-1.5a1.5 1.5 0 0 1 3 0V18'/></svg>",
        "hysteria": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M13 3L5 14h6l-1 7 9-12h-6z'/><path d='M4 10h3'/><path d='M17 14h3'/><path d='M7 6h2'/></svg>",
        "vless": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M6 6h4v4H6z'/><path d='M14 6h4v4h-4z'/><path d='M6 14h4v4H6z'/><path d='M14 14h4v4h-4z'/><path d='M10 8h4M10 16h4M8 10v4M16 10v4'/></svg>",
        "users": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M17 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2'/><circle cx='10' cy='7' r='4'/><path d='M16 11h6'/><path d='M19 8v6'/></svg>",
        "services": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 7h16'/><path d='M4 12h16'/><path d='M4 17h16'/><path d='M7 7v10'/></svg>",
        "sstp": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 15a4 4 0 0 1 4-4h1.5A4.5 4.5 0 0 1 17 8.5 4 4 0 0 1 20 12a4 4 0 0 1-4 4H8'/><path d='M9 15l-2-2 2-2'/><path d='M15 15l2-2-2-2'/></svg>",
        "configs": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'/><path d='M14 2v6h6'/><path d='M8 13h8'/><path d='M8 17h8'/></svg>",
        "firewall": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 2l8 4v6c0 5-3.5 9.7-8 10-4.5-.3-8-5-8-10V6z'/><path d='M8 12h8'/><path d='M10 8h4'/></svg>",
        "system": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='4' y='4' width='16' height='16' rx='3'/><path d='M8 8h8'/><path d='M8 12h8'/><path d='M8 16h5'/></svg>",
        "qr": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z'/><path d='M14 14h3v3h-3z'/><path d='M18 14h2v2'/><path d='M14 18h6'/></svg>",
        "logout": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M10 17l5-5-5-5'/><path d='M15 12H3'/><path d='M21 3v18'/></svg>",
        "search": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><circle cx='11' cy='11' r='7'/><path d='M20 20l-3.5-3.5'/></svg>",
        "server": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='4' width='18' height='6' rx='2'/><rect x='3' y='14' width='18' height='6' rx='2'/><path d='M7 7h.01M7 17h.01'/><path d='M11 7h6M11 17h6'/></svg>",
        "shield": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M12 2l8 4v6c0 5-3.5 9.7-8 10-4.5-.3-8-5-8-10V6z'/><path d='M9 12l2 2 4-4'/></svg>",
        "chart": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><path d='M4 19h16'/><path d='M7 16V9'/><path d='M12 16V5'/><path d='M17 16v-7'/></svg>",
        "memory": "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='7' width='18' height='10' rx='2'/><path d='M6 7v10'/><path d='M10 7v10'/><path d='M14 7v10'/><path d='M18 7v10'/></svg>",
    }
    return icons.get(name, icons["dashboard"])


DEFAULT_SETTINGS = {
    "features": {
        "amneziawg": True,
        "wireguard": True,
        "openvpn": True,
        "hysteria": True,
        "vless": True,
        "sstp": True,
        "fail2ban": True,
        "emqx": True,
    },
    "network": {"speed_cap_mbps": 200},
    "downloads": {
        "AmneziaWG (старый)": "/etc/wireguard/wg0.conf",
        "AmneziaWG": "/etc/amnezia/amneziawg/awg0.conf",
        "OpenVPN сервер": "/etc/openvpn/server/server.conf",
        "Переменные панели": "/etc/amnezia-panel.env",
    },
    "services": {
        "awg": "awg-quick@awg0.service",
        "wireguard": "wg-quick@wg0.service",
        "openvpn": "openvpn-server@server.service",
        "hysteria2": "hysteria2.service",
        "xray": "xray.service",
        "office-sstp": "office-sstp.service",
        "softether": "softether-vpnserver.service",
        "panel": "amnezia-panel.service",
        "vpn-iptables": "vpn-iptables.service",
        "openvpn-iptables": "openvpn-iptables.service",
        "fail2ban": "fail2ban.service",
    },
    "service_labels": {
        "awg": "AmneziaWG",
        "wireguard": "WireGuard",
        "openvpn": "OpenVPN",
        "softether": "SoftEther / SSTP",
        "office-sstp": "Office SSTP",
        "panel": "Панель",
        "vpn-iptables": "Фаервол VPN",
        "openvpn-iptables": "Фаервол OpenVPN",
        "fail2ban": "Fail2Ban",
    },
    "backup_timer": {
        "service_unit": "server-panel-backup.service",
        "timer_unit": "server-panel-backup.timer",
    },
    "web_ports": ["80", "443", "8443"],
    "port_roles": {
        "22": ["SSH", "Админ-доступ к серверу"],
        "53": ["DNS", "Локальный DNS resolver systemd"],
        "443": ["MTProxy", "Публичный Telegram MTProto proxy"],
        "1194": ["OpenVPN", "VPN-подключения OpenVPN"],
        "51820": ["WireGuard", "VPN-подключения WireGuard"],
        "1234": ["AmneziaWG", "VPN-подключения AmneziaWG"],
        "5555": ["SoftEther CLI", "Админ-порт SoftEther VPN Server"],
        "8443": ["SSTP", "SSTP listener SoftEther VPN Server"],
        "4096": ["OpenCode", "Внутренний порт рабочего окружения"],
        "4370": ["EMQX cluster", "Служебный порт кластера EMQX/Erlang"],
        "5370": ["EMQX RPC", "Служебная связь EMQX"],
        "8083": ["MQTT WS", "MQTT WebSocket endpoint"],
        "8084": ["MQTT WSS", "MQTT WebSocket TLS endpoint"],
        "8088": ["Панель", "Веб-панель управления сервером"],
        "8883": ["MQTT TLS", "Защищённый MQTT broker"],
        "8888": ["MTProxy stats", "Локальная статистика MTProxy"],
        "1883": ["MQTT", "MQTT broker без TLS"],
        "18083": ["EMQX dashboard", "Панель управления EMQX"],
    },
}


def deep_merge(default, override):
    if isinstance(default, dict) and isinstance(override, dict):
        merged = dict(default)
        for key, value in override.items():
            merged[key] = deep_merge(merged.get(key), value) if key in merged else value
        return merged
    return override if override is not None else default


def load_settings():
    if CFG["settings_file"].exists():
        try:
            data = json.loads(CFG["settings_file"].read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return deep_merge(DEFAULT_SETTINGS, data)
        except Exception:
            pass
    return DEFAULT_SETTINGS


SETTINGS = load_settings()
KNOWN_DOWNLOADS = {label: Path(path) for label, path in SETTINGS.get("downloads", {}).items()}
SERVICE_MAP = dict(SETTINGS.get("services", {}))
SERVICE_LABELS = dict(SETTINGS.get("service_labels", {}))
SERVICE_MAP.setdefault("wireguard", "wg-quick@wg0.service")
SERVICE_LABELS.setdefault("wireguard", "WireGuard")


def feature_enabled(name):
    return bool((SETTINGS.get("features") or {}).get(name, True))


def nav_item_visible(key):
    feature = NAV_FEATURES.get(key)
    return feature_enabled(feature) if feature else True


def run(cmd, input_text=None):
    res = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or res.stdout.strip() or f"{cmd!r} failed")
    return res.stdout


def ensure_dirs():
    CFG["state_dir"].mkdir(parents=True, exist_ok=True)
    CFG["profile_dir"].mkdir(parents=True, exist_ok=True)
    if not CFG["settings_file"].exists():
        CFG["settings_file"].write_text(json.dumps(DEFAULT_SETTINGS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        ensure_wireguard_server_config()
    except Exception:
        pass


def load_state():
    if not CFG["state_file"].exists():
        return {"clients": []}
    try:
        return json.loads(CFG["state_file"].read_text())
    except Exception:
        return {"clients": []}


def save_state(state):
    CFG["state_file"].write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def load_panel_users():
    fallback = [{"username": CFG["auth_user"], "password": CFG["auth_pass"], "is_admin": True, "totp_enabled": False, "totp_secret": ""}]
    if not CFG["panel_users_file"].exists():
        return fallback
    try:
        data = json.loads(CFG["panel_users_file"].read_text())
    except Exception:
        return fallback
    users = []
    seen = set()
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username", "")).strip()
        password = str(item.get("password", ""))
        if username and password:
            if username in seen:
                continue
            seen.add(username)
            users.append({
                "username": username,
                "password": password,
                "is_admin": bool(item.get("is_admin", False)),
                "totp_enabled": bool(item.get("totp_enabled", False)),
                "totp_secret": str(item.get("totp_secret", "")).strip(),
            })
    if not users:
        return fallback
    if not any(u.get("is_admin") for u in users):
        users[0]["is_admin"] = True
    return users


def save_panel_users(users):
    CFG["panel_users_file"].write_text(json.dumps(users, indent=2, ensure_ascii=False) + "\n")


def load_ssh_issued_keys():
    items = load_json_list(CFG["ssh_issued_keys_file"])
    keys = []
    for item in items:
        if not isinstance(item, dict):
            continue
        username = str(item.get("username", "")).strip()
        public_key = str(item.get("public_key", "")).strip()
        private_key = str(item.get("private_key", "")).strip()
        if not username or not public_key or not private_key:
            continue
        keys.append({
            "username": username,
            "comment": str(item.get("comment", "")).strip(),
            "home": str(item.get("home", "")).strip(),
            "authorized_keys": str(item.get("authorized_keys", "")).strip(),
            "public_key": public_key,
            "private_key": private_key,
            "issued_at": str(item.get("issued_at", "")).strip(),
        })
    return keys


def save_ssh_issued_key(entry):
    keys = load_ssh_issued_keys()
    keys.append(entry)
    save_json_list(CFG["ssh_issued_keys_file"], keys)


def panel_usernames():
    return [u["username"] for u in load_panel_users()]


def primary_panel_user():
    users = load_panel_users()
    return users[0]["username"] if users else CFG["auth_user"]


def panel_user_by_name(username):
    username = (username or "").strip()
    for user in load_panel_users():
        if user["username"] == username:
            return user
    return None


def panel_user_is_admin(username):
    user = panel_user_by_name(username)
    return bool(user and user.get("is_admin"))


def upsert_panel_user(username, password=None, is_admin=None, old_username=None):
    username = (username or "").strip()
    if not username:
        raise RuntimeError("имя пользователя не задано")
    users = load_panel_users()
    target = None
    if old_username:
        for user in users:
            if user["username"] == old_username:
                target = user
                break
    if target is None:
        for user in users:
            if user["username"] == username:
                target = user
                break
    if target is None:
        if not password:
            raise RuntimeError("пароль не задан")
        target = {"username": username, "password": password, "is_admin": bool(is_admin), "totp_enabled": False, "totp_secret": ""}
        users.append(target)
    else:
        existing = panel_user_by_name(username)
        if existing and existing is not target:
            raise RuntimeError("пользователь уже существует")
        target["username"] = username
        if password:
            target["password"] = password
        if is_admin is not None:
            target["is_admin"] = bool(is_admin)
    if not any(u.get("is_admin") for u in users):
        target["is_admin"] = True
    save_panel_users(users)


def delete_panel_user(username):
    username = (username or "").strip()
    users = load_panel_users()
    kept = [u for u in users if u["username"] != username]
    if len(kept) == len(users):
        raise RuntimeError("user not found")
    if not kept:
        raise RuntimeError("нельзя удалить последнего пользователя")
    if not any(u.get("is_admin") for u in kept):
        kept[0]["is_admin"] = True
    save_panel_users(kept)


def reset_panel_users_from_env():
    save_panel_users([{"username": CFG["auth_user"], "password": CFG["auth_pass"], "is_admin": True, "totp_enabled": False, "totp_secret": ""}])


def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret, for_time=None, step=30):
    secret = (secret or "").strip().replace(" ", "").upper()
    if not secret:
        return ""
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def verify_totp(secret, code):
    code = re.sub(r"\s+", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return False
    now = time.time()
    for drift in (-30, 0, 30):
        if hmac.compare_digest(totp_code(secret, now + drift), code):
            return True
    return False


def totp_uri(username, secret):
    label = quote(f"Server:{username}", safe="")
    issuer = quote("Server Control Center", safe="")
    return f"otpauth://totp/{label}?secret={quote(secret)}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def set_panel_user_totp(username, action):
    users = load_panel_users()
    target = None
    for user in users:
        if user["username"] == username:
            target = user
            break
    if not target:
        raise RuntimeError("user not found")
    if action in {"enable", "regenerate"}:
        target["totp_secret"] = totp_new_secret()
        target["totp_enabled"] = True
    elif action == "disable":
        target["totp_enabled"] = False
        target["totp_secret"] = ""
    else:
        raise RuntimeError("invalid 2FA action")
    save_panel_users(users)
    audit_event("panel_user_2fa", f"{action} {username}")


REQUEST_CTX = threading.local()


def set_current_request_user(username=None):
    REQUEST_CTX.user = username


def current_request_user():
    return getattr(REQUEST_CTX, "user", None)


def authenticated_username(headers):
    header = headers.get("Authorization")
    if header and header.startswith("Basic "):
        try:
            raw = base64.b64decode(header.split(None, 1)[1]).decode()
        except Exception:
            raw = ""
        user, _, password = raw.partition(":")
        record = panel_user_by_name(user)
        if credentials_ok(user, password) and not (record and record.get("totp_enabled")):
            return user
    cookie = headers.get("Cookie")
    if cookie:
        cookie_jar = SimpleCookie()
        try:
            cookie_jar.load(cookie)
        except Exception:
            return None
        morsel = cookie_jar.get(SESSION_COOKIE)
        if morsel and verify_session_token(morsel.value):
            try:
                return morsel.value.split(".", 1)[0].split(":", 1)[0]
            except Exception:
                return None
    return None


def normalize_name(name):
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip())
    return name[:40].strip(".-_") or "client"


def next_ip(used_ips, subnet=None, server_ip=None):
    net = ipaddress.ip_network(subnet or CFG["subnet"], strict=False)
    for host in net.hosts():
        if str(host) == (server_ip or CFG["server_ip"]):
            continue
        if str(host) not in used_ips:
            return str(host)
    raise RuntimeError("No free addresses left in subnet")


def default_iface():
    try:
        out = run(["ip", "route", "show", "default"])
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def parse_awg_show():
    return parse_wg_show(CFG["iface"])


def parse_wg_show(iface):
    binary = "awg" if iface == CFG["iface"] else "wg"
    out = run([binary, "show", iface])
    server_pub = CFG["server_pubkey"]
    peers = []
    current = None
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("public key:") and not server_pub:
            server_pub = line.split(":", 1)[1].strip()
        elif line.startswith("peer: "):
            if current:
                peers.append(current)
            current = {"public_key": line.split("peer:", 1)[1].strip(), "allowed_ips": []}
        elif current and line.startswith("endpoint:"):
            current["endpoint"] = line.split(":", 1)[1].strip()
        elif current and line.startswith("allowed ips:"):
            current["allowed_ips"] = [x.strip() for x in line.split(":", 1)[1].split(",") if x.strip()]
        elif current and line.startswith("preshared key:"):
            current["preshared_key"] = line.split(":", 1)[1].strip()
        elif current and line.startswith("latest handshake:"):
            current["latest_handshake"] = line.split(":", 1)[1].strip()
        elif current and line.startswith("transfer:"):
            current["transfer"] = line.split(":", 1)[1].strip()
    if current:
        peers.append(current)
    return server_pub, peers


def ensure_wireguard_server_config():
    etc_dir = Path("/etc/wireguard")
    etc_dir.mkdir(parents=True, exist_ok=True)
    amnezia_dir = Path("/etc/amnezia/amneziawg")
    amnezia_dir.mkdir(parents=True, exist_ok=True)
    if not CFG["wireguard_server_key"].exists():
        priv = run(["awg", "genkey"]).strip()
        pub = run(["awg", "pubkey"], input_text=priv + "\n").strip()
        CFG["wireguard_server_key"].write_text(priv + "\n", encoding="utf-8")
        CFG["wireguard_server_pub"].write_text(pub + "\n", encoding="utf-8")
        os.chmod(CFG["wireguard_server_key"], 0o600)
    if not CFG["wireguard_server_pub"].exists():
        priv = CFG["wireguard_server_key"].read_text(encoding="utf-8").strip()
        pub = run(["awg", "pubkey"], input_text=priv + "\n").strip()
        CFG["wireguard_server_pub"].write_text(pub + "\n", encoding="utf-8")
    conf_text = None
    target_conf = amnezia_dir / f"{CFG['wireguard_iface']}.conf"
    if not target_conf.exists():
        server_priv = CFG["wireguard_server_key"].read_text(encoding="utf-8").strip()
        out_iface = default_iface()
        conf_text = f"""[Interface]\nAddress = {CFG['wireguard_server_ip']}/24\nListenPort = 51820\nPrivateKey = {server_priv}\nSaveConfig = true\nTable = auto\nPostUp = iptables -t nat -A POSTROUTING -s {CFG['wireguard_subnet']} -o {out_iface} -j MASQUERADE\nPostDown = iptables -t nat -D POSTROUTING -s {CFG['wireguard_subnet']} -o {out_iface} -j MASQUERADE\n"""
        target_conf.write_text(conf_text, encoding="utf-8")
        os.chmod(target_conf, 0o600)
    conf = etc_dir / f"{CFG['wireguard_iface']}.conf"
    if conf_text is not None or not conf.exists():
        conf.write_text(conf_text if conf_text is not None else target_conf.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(conf, 0o600)
    return target_conf


def load_wireguard_clients():
    clients = []
    for item in load_json_list(CFG["wireguard_clients_file"]):
        if not isinstance(item, dict):
            continue
        uuid_value = str(item.get("public_key") or item.get("pub") or "").strip()
        if uuid_value:
            clients.append({"name": str(item.get("name") or uuid_value[:12]).strip(), "private_key": str(item.get("private_key") or "").strip(), "public_key": uuid_value, "preshared_key": str(item.get("preshared_key") or "").strip(), "iphone": bool(item.get("iphone", False)), "ip": str(item.get("ip") or "").strip(), "enabled": bool(item.get("enabled", True))})
    return clients


def save_wireguard_clients(clients):
    save_json_list(CFG["wireguard_clients_file"], clients)


def wireguard_endpoint():
    _, _, port = (CFG["wireguard_endpoint"] or "127.0.0.1:51820").rpartition(":")
    return public_endpoint(port or "51820")


def wireguard_client_uri(client):
    server_pub = CFG["wireguard_server_pub"].read_text(encoding="utf-8").strip() if CFG["wireguard_server_pub"].exists() else ""
    host, _, port = wireguard_endpoint().rpartition(":")
    if not host:
        host = wireguard_endpoint()
        port = "51820"
    endpoint = f"{host}:{port}"
    return f"[Interface]\nPrivateKey = {client['private_key']}\nAddress = {client['ip']}/32\nDNS = 1.1.1.1, 1.0.0.1\n\n[Peer]\nPublicKey = {server_pub}\nPresharedKey = {client['preshared_key']}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n"


def add_wireguard_client(name, iphone=False):
    ensure_wireguard_server_config()
    state = load_wireguard_clients()
    _, peers = parse_wg_show(CFG["wireguard_iface"])
    used_ips = used_ips_from(peers, {"clients": state}, server_ip=CFG["wireguard_server_ip"])
    client_priv, client_pub, client_psk = gen_keypair()
    ip = next_ip(used_ips, subnet=CFG["wireguard_subnet"], server_ip=CFG["wireguard_server_ip"])
    client = {"name": normalize_name(name), "ip": ip, "private_key": client_priv, "public_key": client_pub, "preshared_key": client_psk, "iphone": bool(iphone), "enabled": True}
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(client_psk + "\n")
        psk_path = tmp.name
    try:
        run(["wg", "set", CFG["wireguard_iface"], "peer", client_pub, "preshared-key", psk_path, "allowed-ips", f"{ip}/32"])
    finally:
        try:
            os.unlink(psk_path)
        except FileNotFoundError:
            pass
    run(["wg-quick", "save", CFG["wireguard_iface"]])
    state.append(client)
    save_wireguard_clients(state)
    save_profile_text(client["name"], wireguard_client_uri(client))
    return client


def remove_wireguard_client(public_key):
    state = load_wireguard_clients()
    kept = []
    removed = None
    for client in state:
        if client["public_key"] == public_key:
            removed = client
            continue
        kept.append(client)
    if not removed:
        raise RuntimeError("client not found")
    run(["wg", "set", CFG["wireguard_iface"], "peer", public_key, "remove"])
    run(["wg-quick", "save", CFG["wireguard_iface"]])
    save_wireguard_clients(kept)
    profile = CFG["profile_dir"] / f"{removed['name']}.conf"
    if profile.exists():
        profile.unlink()


def toggle_wireguard_client(public_key, enabled):
    clients = load_wireguard_clients()
    target = None
    for client in clients:
        if client.get("public_key") == public_key:
            target = client
            break
    if not target:
        raise RuntimeError("client not found")
    if enabled:
        if not target.get("preshared_key") or not target.get("ip"):
            raise RuntimeError("client config incomplete")
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(target["preshared_key"] + "\n")
            psk_path = tmp.name
        try:
            run(["wg", "set", CFG["wireguard_iface"], "peer", public_key, "preshared-key", psk_path, "allowed-ips", f"{target['ip']}/32"])
        finally:
            try:
                os.unlink(psk_path)
            except Exception:
                pass
        run(["wg-quick", "save", CFG["wireguard_iface"]])
        target["enabled"] = True
        save_wireguard_clients(clients)
        save_profile_text(target["name"], wireguard_client_uri(target))
    else:
        try:
            run(["wg", "set", CFG["wireguard_iface"], "peer", public_key, "remove"])
            run(["wg-quick", "save", CFG["wireguard_iface"]])
        finally:
            target["enabled"] = False
            save_wireguard_clients(clients)
            delete_profile_file(target["name"])


def delete_profile_file(name):
    profile = CFG["profile_dir"] / f"{path_safe_name(name)}.conf"
    if profile.exists():
        profile.unlink()


def delete_profile_file_with_suffix(name, suffix=".conf"):
    profile = CFG["profile_dir"] / f"{path_safe_name(name)}{suffix}"
    if profile.exists():
        profile.unlink()


def remove_hysteria_client(username):
    clients = load_hysteria_clients()
    kept = [c for c in clients if c.get("username") != username]
    if len(kept) == len(clients):
        raise RuntimeError("client not found")
    save_hysteria_clients(kept)
    write_hysteria_config(kept)
    run(["systemctl", "restart", "hysteria2.service"])
    delete_profile_file_with_suffix(username, ".hysteria.conf")


def toggle_hysteria_client(username, enabled):
    clients = load_hysteria_clients()
    target = None
    for client in clients:
        if client.get("username") == username:
            target = client
            break
    if not target:
        raise RuntimeError("client not found")
    target["enabled"] = bool(enabled)
    save_hysteria_clients(clients)
    write_hysteria_config(clients)
    run(["systemctl", "restart", "hysteria2.service"])
    if enabled:
        save_profile_text_with_suffix(target["name"], hysteria_client_uri(target), ".hysteria.conf")
    else:
        delete_profile_file_with_suffix(username, ".hysteria.conf")


def openvpn_client_keys(name):
    base = path_safe_name(name)
    easy = Path("/etc/openvpn/easy-rsa")
    return easy, base


def revoke_openvpn_client(name):
    openvpn_revoke_only(name)
    clients = [c for c in load_openvpn_clients() if c.get("name") != path_safe_name(name)]
    save_openvpn_clients(clients)
    delete_profile_file_with_suffix(name, ".ovpn")


def toggle_openvpn_client(name, enabled):
    clients = load_openvpn_clients()
    base = path_safe_name(name)
    target = None
    for client in clients:
        if client.get("name") == base:
            target = client
            break
    if not target:
        raise RuntimeError("client not found")
    if enabled:
        cleanup_openvpn_client_artifacts(base)
        easy = Path("/etc/openvpn/easy-rsa")
        run(["bash", "-lc", f"cd {shlex.quote(str(easy))} && EASYRSA_BATCH=1 ./easyrsa build-client-full {shlex.quote(base)} nopass"])
        target["enabled"] = True
        save_openvpn_clients(clients)
        save_profile_text_with_suffix(base, openvpn_client_profile(base), ".ovpn")
    else:
        openvpn_revoke_only(base)
        target["enabled"] = False
        save_openvpn_clients(clients)
        delete_profile_file_with_suffix(base, ".ovpn")


def openvpn_revoke_client(name):
    easy, base = openvpn_client_keys(name)
    issued = Path(f"/etc/openvpn/server/pki/issued/{base}.crt")
    private = Path(f"/etc/openvpn/server/pki/private/{base}.key")
    req = Path(f"/etc/openvpn/server/pki/reqs/{base}.req")
    if issued.exists() or private.exists() or req.exists():
        try:
            run(["bash", "-lc", f"cd {shlex.quote(str(easy))} && EASYRSA_BATCH=1 ./easyrsa revoke {shlex.quote(base)} && EASYRSA_BATCH=1 ./easyrsa gen-crl && cp -a pki/crl.pem /etc/openvpn/server/pki/crl.pem && cp -a pki /etc/openvpn/server/"])
        except Exception:
            try:
                issued.unlink(missing_ok=True)
                private.unlink(missing_ok=True)
                req.unlink(missing_ok=True)
            except Exception:
                pass
    clients = [c for c in load_openvpn_clients() if c.get("name") != base]
    save_openvpn_clients(clients)
    delete_profile_file_with_suffix(base, ".ovpn")


def cleanup_openvpn_client_artifacts(base):
    for path in [
        Path(f"/etc/openvpn/easy-rsa/pki/reqs/{base}.req"),
        Path(f"/etc/openvpn/easy-rsa/pki/private/{base}.key"),
        Path(f"/etc/openvpn/easy-rsa/pki/issued/{base}.crt"),
        Path(f"/etc/openvpn/server/pki/reqs/{base}.req"),
        Path(f"/etc/openvpn/server/pki/private/{base}.key"),
        Path(f"/etc/openvpn/server/pki/issued/{base}.crt"),
    ]:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def remove_vless_client(uuid_value):
    clients = load_vless_clients()
    kept = [c for c in clients if c.get("uuid") != uuid_value]
    if len(kept) == len(clients):
        raise RuntimeError("client not found")
    save_vless_clients(kept)
    write_xray_config(kept)
    for client in clients:
        if client.get("uuid") == uuid_value:
            delete_profile_file(client.get("name", uuid_value))
            break


def toggle_vless_client(uuid_value, enabled):
    clients = load_vless_clients()
    target = None
    for client in clients:
        if client.get("uuid") == uuid_value:
            target = client
            break
    if not target:
        raise RuntimeError("client not found")
    target["enabled"] = bool(enabled)
    save_vless_clients(clients)
    write_xray_config(clients)
    if enabled:
        save_profile_text(target["name"], vless_client_uri(target))
    else:
        delete_profile_file(target.get("name", uuid_value))


def used_ips_from(peers, state, server_ip=None, ip_key="ip"):
    used = {server_ip or CFG["server_ip"]}
    for peer in peers:
        for ip in peer.get("allowed_ips", []):
            if "/" in ip:
                used.add(ip.split("/")[0])
    for client in state.get("clients", []):
        if ip_key in client and client[ip_key]:
            used.add(client[ip_key])
    return used


def gen_keypair():
    priv = run(["awg", "genkey"]).strip()
    pub = run(["awg", "pubkey"], input_text=priv + "\n").strip()
    psk = run(["awg", "genpsk"]).strip()
    return priv, pub, psk


def render_client_profile(client, server_pub):
    endpoint = CFG["iphone_endpoint"] if client.get("iphone") else CFG["endpoint"]
    endpoint = re.sub(r"^[^:]+", detect_public_host(), endpoint, count=1)
    mtu_line = f"MTU = {CFG['template_mtu']}\n" if client.get("iphone") else ""
    return f"""[Interface]\nAddress = {client['ip']}/32\nPrivateKey = {client['private_key']}\nDNS = 1.1.1.1, 1.0.0.1\n{mtu_line}Jc = {CFG['template_jc']}\nJmin = {CFG['template_jmin']}\nJmax = {CFG['template_jmax']}\nS1 = {CFG['template_s1']}\nS2 = {CFG['template_s2']}\nS3 = {CFG['template_s3']}\nS4 = {CFG['template_s4']}\nH1 = {CFG['template_h1']}\nH2 = {CFG['template_h2']}\nH3 = {CFG['template_h3']}\nH4 = {CFG['template_h4']}\nI1 = {CFG['template_i1']}\n\n[Peer]\nPublicKey = {server_pub}\nPresharedKey = {client['preshared_key']}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n"""


def save_client_profile(client, server_pub):
    path = CFG["profile_dir"] / f"{client['name']}.conf"
    path.write_text(render_client_profile(client, server_pub))
    os.chmod(path, 0o600)
    return path


def qr_svg(text):
    return run(["qrencode", "-t", "SVG", "-o", "-"], input_text=text)


def add_client(name, iphone=False):
    state = load_state()
    server_pub, peers = parse_awg_show()
    used_ips = used_ips_from(peers, state)
    client_priv, client_pub, client_psk = gen_keypair()
    ip = next_ip(used_ips, subnet=CFG["subnet"], server_ip=CFG["server_ip"])
    client = {
        "name": normalize_name(name),
        "ip": ip,
        "private_key": client_priv,
        "public_key": client_pub,
        "preshared_key": client_psk,
        "iphone": bool(iphone),
    }
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(client_psk + "\n")
        psk_path = tmp.name
    try:
        run([
            "awg",
            "set",
            CFG["iface"],
            "peer",
            client_pub,
            "preshared-key",
            psk_path,
            "allowed-ips",
            f"{ip}/32",
        ])
    finally:
        try:
            os.unlink(psk_path)
        except FileNotFoundError:
            pass
    run(["awg-quick", "save", CFG["iface"]])
    state.setdefault("clients", []).append(client)
    save_state(state)
    save_client_profile(client, server_pub)
    return client


def remove_client(public_key):
    state = load_state()
    kept = []
    removed = None
    for client in state.get("clients", []):
        if client["public_key"] == public_key:
            removed = client
            continue
        kept.append(client)
    if not removed:
        raise RuntimeError("client not found")
    run(["awg", "set", CFG["iface"], "peer", public_key, "remove"])
    run(["awg-quick", "save", CFG["iface"]])
    state["clients"] = kept
    save_state(state)
    profile = CFG["profile_dir"] / f"{removed['name']}.conf"
    if profile.exists():
        profile.unlink()


def load_json_list(path):
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_json_list(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def path_safe_name(name):
    return normalize_name(name or "client")


def stable_dom_id(prefix, value):
    digest = hashlib.sha1(str(value).encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def client_pill(text, tone="", attrs=""):
    cls = "status-pill" + (f" {tone}" if tone else "")
    return f"<span class='{cls}'{attrs}><span class='status-dot'></span><span class='status-text'>{html.escape(text)}</span></span>"


def toggle_form(action, return_to, field_name, field_value, button_text, tone=""):
    button_class = tone or ""
    class_attr = f" class='{button_class}'" if button_class else ""
    return f"""
    <form method='post' action='{html.escape(action)}'>
      <input type='hidden' name='return_to' value='{html.escape(return_to)}' />
      <input type='hidden' name='{html.escape(field_name)}' value='{html.escape(field_value)}' />
      <button type='submit'{class_attr}>{html.escape(button_text)}</button>
    </form>
    """


def warning_box_html(items):
    if not items:
        return ""
    chips = ''.join(f"<span class='rule-chip warn'>{html.escape(item)}</span>" for item in items)
    return f"<div class='section' style='margin-top:16px'><div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Предупреждения</h2><span class='badge'>{len(items)}</span></div><div class='rule-chips'>{chips}</div></div>"


def detect_public_host():
    for key in ("PANEL_PUBLIC_HOST", "PANEL_PUBLIC_IP"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    try:
        out = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
        for raw in out.splitlines():
            parts = raw.split()
            if "inet" in parts:
                addr = parts[parts.index("inet") + 1].split("/", 1)[0]
                if addr and not addr.startswith("127."):
                    return addr
    except Exception:
        pass
    try:
        out = run(["hostname", "-I"]).strip().split()
        for addr in out:
            if addr and not addr.startswith("127."):
                return addr
    except Exception:
        pass
    return (CFG.get("endpoint") or "127.0.0.1:443").split(":", 1)[0]


def public_endpoint(port=None):
    host = detect_public_host()
    if port is None:
        return host
    return f"{host}:{port}"


def server_host():
    return detect_public_host()


def openvpn_server_host_port():
    return detect_public_host(), "1194"


def hysteria_fingerprint():
    cert_path = Path("/etc/hysteria/server.crt")
    if not cert_path.exists():
        return ""
    try:
        out = run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert_path)])
        return out.split("=", 1)[-1].strip().replace(":", "")
    except Exception:
        return ""


def hysteria_server_name():
    override = os.environ.get("PANEL_HYSTERIA_SNI", "").strip()
    if override:
        return override
    cert_path = Path("/etc/hysteria/server.crt")
    if cert_path.exists():
        try:
            out = run(["openssl", "x509", "-noout", "-subject", "-in", str(cert_path)])
            match = re.search(r"CN\s*=\s*([^,\n/]+)", out)
            if match:
                return match.group(1).strip()
        except Exception:
            pass
    return detect_public_host()


def save_profile_text(name, text):
    return save_profile_text_with_suffix(name, text, ".conf")


def save_profile_text_with_suffix(name, text, suffix=".conf"):
    profile = CFG["profile_dir"] / f"{path_safe_name(name)}.conf"
    if suffix != ".conf":
        profile = CFG["profile_dir"] / f"{path_safe_name(name)}{suffix}"
    profile.write_text(text, encoding="utf-8")
    os.chmod(profile, 0o600)
    return profile


def hysteria_client_uri(client):
    port = os.environ.get("PANEL_HYSTERIA_PORT", "8448")
    auth = f"{quote(client['username'], safe='')}:{quote(client['password'], safe='')}"
    host = detect_public_host()
    sni = hysteria_server_name()
    return f"hysteria2://{auth}@{host}:{port}/?sni={quote(sni, safe='')}&insecure=1"


def hysteria_profile_action_links(name):
    qname = quote(f"{name}.hysteria.conf", safe="")
    return f"<a class='ghost' href='/download/{qname}'>Скачать</a>{qr_link(f'{name}.hysteria.conf')}"


def load_hysteria_clients():
    clients = []
    ignored_usernames = {"url", "rewriteHost"}
    for item in load_json_list(CFG["hysteria_clients_file"]):
        if isinstance(item, dict) and item.get("username") and item.get("password"):
            username = str(item["username"])
            if username.startswith("__internal__") or username in ignored_usernames:
                continue
            clients.append({"name": str(item.get("name") or username), "username": username, "password": str(item["password"]), "iphone": bool(item.get("iphone", False)), "enabled": bool(item.get("enabled", True))})
    return clients


def save_hysteria_clients(clients):
    save_json_list(CFG["hysteria_clients_file"], clients)


def write_hysteria_config(clients):
    userpass = ["    __internal__: 2b2e7f3d6c9a4f4f9c6b1fd8c6f7db11"]
    for client in clients:
        username = str(client.get("username") or "").strip()
        password = str(client.get("password") or "").strip()
        if not client.get("enabled", True):
            continue
        if username and password:
            userpass.append(f"    {username}: {password}")
    text = "\n".join([
        "listen: :8448",
        "",
        "tls:",
        "  cert: /etc/hysteria/server.crt",
        "  key: /etc/hysteria/server.key",
        "",
        "auth:",
        "  type: userpass",
        "  userpass:",
        *userpass,
        "",
        "masquerade:",
        "  type: proxy",
        "  proxy:",
        "    url: https://www.cloudflare.com/",
        "    rewriteHost: true",
        "",
    ])
    Path("/etc/hysteria/config.yaml").write_text(text, encoding="utf-8")


def add_hysteria_client(name, iphone=False):
    clients = load_hysteria_clients()
    username = path_safe_name(name)
    existing = {c["username"] for c in clients}
    if username in existing:
        idx = 2
        candidate = f"{username}{idx}"
        while candidate in existing:
            idx += 1
            candidate = f"{username}{idx}"
        username = candidate
    client = {"name": path_safe_name(name or username), "username": username, "password": secrets.token_urlsafe(18), "iphone": bool(iphone), "enabled": True}
    clients.append(client)
    save_hysteria_clients(clients)
    write_hysteria_config(clients)
    run(["systemctl", "restart", "hysteria2.service"])
    save_profile_text_with_suffix(client["name"], hysteria_client_uri(client), ".hysteria.conf")
    return client


def parse_xray_config():
    path = Path("/etc/xray/config.json")
    data = {"port": 8449, "dest": "www.cloudflare.com:443", "serverNames": ["www.cloudflare.com"], "shortIds": ["d51bff7d"], "flow": "xtls-rprx-vision"}
    if not path.exists():
        return data
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        inbound = (raw.get("inbounds") or [{}])[0]
        data["port"] = inbound.get("port", data["port"])
        reality = ((inbound.get("streamSettings") or {}).get("realitySettings") or {})
        data["dest"] = reality.get("dest", data["dest"])
        data["serverNames"] = reality.get("serverNames", data["serverNames"])
        data["shortIds"] = reality.get("shortIds", data["shortIds"])
        clients = ((inbound.get("settings") or {}).get("clients") or [])
        if clients:
            data["flow"] = clients[0].get("flow", data["flow"])
    except Exception:
        pass
    return data


def vless_client_uri(client, cfg=None):
    if not client:
        return ""
    cfg = cfg or parse_xray_config()
    public_key = read_text_safe("/etc/xray/reality.pub").strip() or "HzpJ-1jHvbTaTrcEnuxsCDPqccwIXNZucqhlo94aKl4"
    server_name = (cfg.get("serverNames") or ["www.cloudflare.com"])[0]
    short_id = (cfg.get("shortIds") or [""])[0]
    flow = cfg.get("flow") or "xtls-rprx-vision"
    host = detect_public_host()
    return (
        f"vless://{quote(client['uuid'], safe='')}@{host}:{cfg.get('port', 8449)}"
        f"?type=tcp&encryption=none&security=reality"
        f"&sni={quote(server_name, safe='')}&fp=chrome"
        f"&pbk={quote(public_key, safe='')}&sid={quote(short_id, safe='')}"
        f"&flow={quote(flow, safe='')}#{quote(client['name'], safe='')}"
    )


def load_vless_clients():
    clients = []
    for item in load_json_list(CFG["vless_clients_file"]):
        if not isinstance(item, dict):
            continue
        uuid_value = str(item.get("uuid") or item.get("username") or "").strip()
        if uuid_value:
            clients.append({"name": str(item.get("name") or uuid_value).strip(), "uuid": uuid_value, "iphone": bool(item.get("iphone", False)), "enabled": bool(item.get("enabled", True))})
    return clients


def save_vless_clients(clients):
    save_json_list(CFG["vless_clients_file"], clients)


def write_xray_config(clients):
    cfg = parse_xray_config()
    private_key = read_text_safe("/etc/xray/reality.key").strip()
    public_key = read_text_safe("/etc/xray/reality.pub").strip() or "HzpJ-1jHvbTaTrcEnuxsCDPqccwIXNZucqhlo94aKl4"
    payload = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "0.0.0.0", "port": cfg["port"], "protocol": "vless", "settings": {"decryption": "none", "clients": [{"id": c["uuid"], "email": c["name"], "flow": cfg["flow"]} for c in clients if c.get("enabled", True)]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": False, "dest": cfg["dest"], "xver": 0, "serverNames": cfg["serverNames"], "privateKey": private_key, "shortIds": cfg["shortIds"]}}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
    }
    Path("/etc/xray/config.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    save_vless_clients(clients)
    if clients:
        save_profile_text(clients[0]["name"], vless_client_uri(clients[0], cfg))


def add_vless_client(name, iphone=False):
    clients = load_vless_clients()
    client = {"name": path_safe_name(name or "client"), "uuid": str(uuid.uuid4()), "iphone": bool(iphone), "enabled": True}
    while any(c["uuid"] == client["uuid"] for c in clients):
        client["uuid"] = str(uuid.uuid4())
    clients.append(client)
    write_xray_config(clients)
    save_profile_text(client["name"], vless_client_uri(client))
    return client


def openvpn_client_profile(name):
    host, port = openvpn_server_host_port()
    ca = read_text_safe("/etc/openvpn/server/pki/ca.crt")
    cert = read_cert_pem(f"/etc/openvpn/server/pki/issued/{path_safe_name(name)}.crt") or read_cert_pem(f"/etc/openvpn/easy-rsa/pki/issued/{path_safe_name(name)}.crt")
    key = read_text_safe(f"/etc/openvpn/server/pki/private/{path_safe_name(name)}.key") or read_text_safe(f"/etc/openvpn/easy-rsa/pki/private/{path_safe_name(name)}.key")
    ta = read_text_safe("/etc/openvpn/server/ta.key")
    if cert and not cert.endswith("\n"):
        cert += "\n"
    if key and not key.endswith("\n"):
        key += "\n"
    if ta and not ta.endswith("\n"):
        ta += "\n"
    return f"""client
dev tun
proto udp
remote {host} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3

<ca>
{ca}</ca>
<cert>
{cert}</cert>
<key>
{key}</key>
<tls-crypt>
{ta}</tls-crypt>
"""


def load_openvpn_clients():
    clients = load_json_list(CFG["openvpn_clients_file"])
    if clients:
        sync_openvpn_profiles(clients)
        return clients
    issued = Path("/etc/openvpn/server/pki/issued")
    if issued.exists():
        for item in sorted(issued.glob("*.crt")):
            if item.stem != "server":
                clients.append({"name": item.stem, "iphone": False, "enabled": True})
        if clients:
            save_openvpn_clients(clients)
            sync_openvpn_profiles(clients)
    return clients


def save_openvpn_clients(clients):
    save_json_list(CFG["openvpn_clients_file"], clients)


def sync_openvpn_profiles(clients):
    for client in clients:
        name = client.get("name")
        if not name:
            continue
        if client.get("enabled", True):
            save_profile_text_with_suffix(name, openvpn_client_profile(name), ".ovpn")
        else:
            delete_profile_file_with_suffix(name, ".ovpn")


def add_openvpn_client(name, iphone=False):
    clients = load_openvpn_clients()
    base = path_safe_name(name or "client")
    if any(c.get("name") == base for c in clients):
        idx = 2
        candidate = f"{base}{idx}"
        while any(c.get("name") == candidate for c in clients):
            idx += 1
            candidate = f"{base}{idx}"
        base = candidate
    cleanup_openvpn_client_artifacts(base)
    easy = Path("/etc/openvpn/easy-rsa")
    run(["bash", "-lc", f"cd {shlex.quote(str(easy))} && EASYRSA_BATCH=1 ./easyrsa build-client-full {shlex.quote(base)} nopass"])
    save_openvpn_clients(clients + [{"name": base, "iphone": bool(iphone), "enabled": True}])
    save_profile_text_with_suffix(base, openvpn_client_profile(base), ".ovpn")
    return {"name": base, "iphone": bool(iphone)}


def credentials_ok(user, password):
    record = panel_user_by_name(user)
    return bool(record and record["password"] == password)


def login_credentials_ok(user, password, totp_value=""):
    record = panel_user_by_name(user)
    if not record or record["password"] != password:
        return False, "Invalid credentials"
    if record.get("totp_enabled"):
        if not verify_totp(record.get("totp_secret", ""), totp_value):
            return False, "Неверный код Google Authenticator"
    return True, ""


def auth_ok(header):
    if not header or not header.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(header.split(None, 1)[1]).decode()
    except Exception:
        return False
    user, _, password = raw.partition(":")
    return credentials_ok(user, password)


def session_key(username, password):
    return hashlib.sha256(f"{username}\0{password}".encode()).digest()


def make_session_token(username):
    ts = int(time.time())
    user = panel_user_by_name(username)
    if not user:
        raise RuntimeError("unknown panel user")
    payload = f"{username}:{ts}".encode()
    sig = hmac.new(session_key(username, user["password"]), payload, hashlib.sha256).hexdigest()
    return f"{username}:{ts}.{sig}"


def make_pending_2fa_token(username):
    ts = int(time.time())
    user = panel_user_by_name(username)
    if not user:
        raise RuntimeError("unknown panel user")
    payload = f"2fa:{username}:{ts}".encode()
    sig = hmac.new(session_key(username, user["password"]), payload, hashlib.sha256).hexdigest()
    return f"{username}:{ts}.{sig}"


def verify_pending_2fa_token(token, ttl=300):
    try:
        prefix, sig = token.split(".", 1)
        username, ts_text = prefix.split(":", 1)
        ts = int(ts_text)
    except Exception:
        return None
    now = int(time.time())
    if ts > now + 60 or now - ts > ttl:
        return None
    user = panel_user_by_name(username)
    if not user or not user.get("totp_enabled"):
        return None
    payload = f"2fa:{username}:{ts}".encode()
    expected = hmac.new(session_key(username, user["password"]), payload, hashlib.sha256).hexdigest()
    return username if hmac.compare_digest(expected, sig) else None


def pending_2fa_username(headers):
    cookie = headers.get("Cookie")
    if not cookie:
        return None
    cookie_jar = SimpleCookie()
    try:
        cookie_jar.load(cookie)
    except Exception:
        return None
    morsel = cookie_jar.get(PENDING_2FA_COOKIE)
    if not morsel:
        return None
    return verify_pending_2fa_token(morsel.value)


def verify_session_token(token):
    try:
        prefix, sig = token.split(".", 1)
        username, ts_text = prefix.split(":", 1)
        ts = int(ts_text)
    except Exception:
        return False
    now = int(time.time())
    if ts > now + 60:
        return False
    if now - ts > SESSION_TTL:
        return False
    user = panel_user_by_name(username)
    if not user:
        return False
    payload = f"{username}:{ts}".encode()
    expected = hmac.new(session_key(username, user["password"]), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def request_is_authed(headers):
    return authenticated_username(headers) is not None


def login_page(error="", next_path="/"):
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Вход в панель</title>
<style>
:root {{ color-scheme: dark; --bg:#111318; --panel:#1a1d24; --panel2:#202531; --line:#2d3441; --text:#edf2ff; --muted:#95a0b5; --green:#7c5cff; --green2:#4c7dff; --danger:#ff647c; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; min-height:100vh; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top, #1b2230 0, #111318 55%, #0c0e12 100%); color:var(--text); }}
.shell {{ min-height:100vh; display:grid; grid-template-columns: 88px 1fr; }}
.side {{ border-right:1px solid var(--line); background: rgba(11,13,18,.86); display:flex; flex-direction:column; align-items:center; padding:16px 0; gap:16px; }}
.logo {{ width:42px; height:42px; border-radius:14px; background: linear-gradient(135deg, var(--green), #0c8f70); display:grid; place-items:center; color:#07110d; box-shadow:0 0 0 1px rgba(24,211,155,.2), 0 10px 24px rgba(24,211,155,.14); overflow:hidden; }}
.logo svg {{ width:22px; height:22px; }}
.dot {{ width:28px; height:28px; border-radius:10px; background: #1d222c; border:1px solid #2f3746; }}
.main {{ display:flex; align-items:center; justify-content:center; padding:32px 20px; }}
.card {{ width:min(100%, 430px); background: linear-gradient(180deg, rgba(32,37,49,.95), rgba(24,27,35,.95)); border:1px solid var(--line); border-radius:28px; box-shadow: 0 30px 80px rgba(0,0,0,.45); padding:28px; }}
.brand {{ display:flex; align-items:center; gap:12px; margin-bottom:18px; }}
.brand-badge {{ width:18px; height:18px; border-radius:6px; background: var(--green); box-shadow:0 0 0 7px rgba(24,211,155,.14); }}
h1 {{ margin:0; font-size:30px; letter-spacing:-.03em; }}
.sub {{ margin:8px 0 22px; color:var(--muted); line-height:1.5; }}
.field {{ margin-bottom:14px; }}
label {{ display:block; margin:0 0 8px; color:#cfd6e4; font-size:13px; }}
input {{ width:100%; border:1px solid var(--line); border-radius:16px; background:#10141c; color:var(--text); padding:14px 15px; font-size:15px; outline:none; }}
input:focus {{ border-color: rgba(24,211,155,.65); box-shadow: 0 0 0 4px rgba(24,211,155,.12); }}
.row {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin:18px 0 0; }}
.btn {{ width:100%; border:0; border-radius:16px; background: linear-gradient(135deg, var(--green), var(--green2)); color:#07110d; font-weight:700; padding:14px 16px; font-size:15px; cursor:pointer; }}
.btn:hover {{ filter:brightness(1.04); }}
.hint {{ margin-top:14px; color:var(--muted); font-size:13px; text-align:center; }}
.error {{ margin:0 0 14px; color:var(--danger); background: rgba(255,100,124,.08); border:1px solid rgba(255,100,124,.22); border-radius:14px; padding:10px 12px; }}
@media (max-width: 700px) {{ .shell {{ grid-template-columns: 1fr; }} .side {{ display:none; }} .main {{ padding:18px; }} }}
</style></head><body>
<div class='shell'>
  <aside class='side'>
    <div class='logo'>{icon('login')}</div>
    <div class='dot'></div><div class='dot'></div><div class='dot'></div><div class='dot'></div>
  </aside>
  <main class='main'>
    <form class='card' method='post' action='/login'>
      <div class='brand'><div class='brand-badge'></div><div>Панель управления</div></div>
      <h1>Вход</h1>
      <p class='sub'>Авторизуйтесь, чтобы управлять сервером, VPN, прокси и клиентами.</p>
      {f"<div class='error'>{html.escape(error)}</div>" if error else ''}
      <input type='hidden' name='next' value='{html.escape(next_path)}' />
      <div class='field'>
        <label for='username'>Логин</label>
        <input id='username' name='username' autocomplete='username' required />
      </div>
      <div class='field'>
        <label for='password'>Пароль</label>
        <input id='password' name='password' type='password' autocomplete='current-password' required />
      </div>
      <div class='row'><button class='btn' type='submit'>Войти</button></div>
      <div class='hint'>Если включён 2FA, код будет запрошен следующим шагом.</div>
    </form>
  </main>
</div>
</body></html>"""


def totp_login_page(username, error="", next_path="/"):
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Google Authenticator</title>
<style>
:root {{ color-scheme: dark; --bg:#111318; --panel:#1a1d24; --line:#2d3441; --text:#edf2ff; --muted:#95a0b5; --green:#7c5cff; --green2:#4c7dff; --danger:#ff647c; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; min-height:100vh; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top, #1b2230 0, #111318 55%, #0c0e12 100%); color:var(--text); display:grid; place-items:center; padding:18px; }}
.card {{ width:min(100%, 430px); background: linear-gradient(180deg, rgba(32,37,49,.95), rgba(24,27,35,.95)); border:1px solid var(--line); border-radius:28px; box-shadow: 0 30px 80px rgba(0,0,0,.45); padding:28px; }}
.brand {{ display:flex; align-items:center; gap:12px; margin-bottom:18px; color:#dce4f2; }}
.brand-badge {{ width:18px; height:18px; border-radius:6px; background: linear-gradient(135deg, var(--green), var(--green2)); box-shadow:0 0 0 7px rgba(124,92,255,.14); }}
h1 {{ margin:0; font-size:30px; letter-spacing:-.03em; }}
.sub {{ margin:8px 0 22px; color:var(--muted); line-height:1.5; }}
label {{ display:block; margin:0 0 8px; color:#cfd6e4; font-size:13px; }}
input {{ width:100%; border:1px solid var(--line); border-radius:16px; background:#10141c; color:var(--text); padding:14px 15px; font-size:20px; letter-spacing:.18em; outline:none; }}
input:focus {{ border-color: rgba(124,92,255,.7); box-shadow: 0 0 0 4px rgba(124,92,255,.12); }}
.btn {{ width:100%; margin-top:18px; border:0; border-radius:16px; background: linear-gradient(135deg, var(--green), var(--green2)); color:#fff; font-weight:800; padding:14px 16px; font-size:15px; cursor:pointer; }}
.ghost {{ display:block; margin-top:12px; color:var(--muted); text-align:center; text-decoration:none; }}
.error {{ margin:0 0 14px; color:var(--danger); background: rgba(255,100,124,.08); border:1px solid rgba(255,100,124,.22); border-radius:14px; padding:10px 12px; }}
</style></head><body>
<form class='card' method='post' action='/login-2fa'>
  <div class='brand'><div class='brand-badge'></div><div>Второй фактор</div></div>
  <h1>Google Authenticator</h1>
  <p class='sub'>Введите 6-значный код для <strong>{html.escape(username)}</strong>.</p>
  {f"<div class='error'>{html.escape(error)}</div>" if error else ''}
  <input type='hidden' name='next' value='{html.escape(next_path)}' />
  <label for='totp'>Код из приложения</label>
  <input id='totp' name='totp' inputmode='numeric' maxlength='6' autocomplete='one-time-code' autofocus required />
  <button class='btn' type='submit'>Подтвердить</button>
  <a class='ghost' href='/login'>Вернуться ко входу</a>
</form>
</body></html>"""


def dashboard_css():
    return """
:root { color-scheme: dark; --bg:#11131a; --panel:#1a1e27; --panel2:#1f2430; --panel3:#252b38; --line:#31384a; --text:#eef3ff; --muted:#a0abc0; --green:#7c5cff; --green2:#4c7dff; --danger:#ff647c; }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: linear-gradient(180deg, #111318 0%, #0f1115 100%); color:var(--text); }
a { color: inherit; }
.app { min-height:100vh; display:grid; grid-template-columns: 96px 1fr; }
.sidebar { background: rgba(14,16,20,.96); border-right:1px solid var(--line); display:flex; flex-direction:column; align-items:center; padding:14px 0; gap:16px; position:sticky; top:0; height:100vh; overflow-y:auto; }
.brand { width:46px; height:46px; border-radius:16px; background: linear-gradient(135deg, var(--green), var(--green2)); display:grid; place-items:center; color:#f7f8ff; font-size:20px; font-weight:900; box-shadow:0 0 0 1px rgba(124,92,255,.18), 0 12px 24px rgba(76,125,255,.18); }
.brand svg { width:22px; height:22px; }
.navicon { width:54px; height:54px; border-radius:16px; border:1px solid transparent; color:#dbe3f5; display:grid; place-items:center; text-decoration:none; background:transparent; }
.navicon.active, .navicon:hover { background: linear-gradient(180deg, rgba(124,92,255,.2), rgba(76,125,255,.12)); border-color:rgba(124,92,255,.42); }
.navicon svg, .ico svg { width:20px; height:20px; }
.nav-group-title, .drawer-group-title { color:#77839a; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.12em; padding:14px 12px 6px; }
.logout-top { padding:9px 11px; min-height:34px; }
.sidebar-spacer { flex:1; }
.content { min-width:0; }
.topbar { display:flex; flex-direction:column; gap:12px; padding:16px 22px 14px 24px; border-bottom:1px solid var(--line); background: rgba(17,19,24,.92); position:sticky; top:0; backdrop-filter: blur(12px); z-index:10; }
.topbar-row { display:flex; align-items:center; justify-content:space-between; gap:16px; }
.title { font-size:22px; font-weight:800; letter-spacing:-.03em; }
.top-actions { display:flex; align-items:center; gap:12px; }
.menu-btn { display:none; align-items:center; justify-content:center; width:42px; height:42px; border-radius:14px; border:1px solid var(--line); background:#181d28; color:var(--text); cursor:pointer; }
.menu-btn:hover { border-color: rgba(124,92,255,.45); }
.ghost, .pillbtn, .btn, .danger { border:1px solid var(--line); background:#1f2530; color:var(--text); border-radius:14px; padding:11px 14px; text-decoration:none; font-size:14px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:8px; }
.pillbtn { background: linear-gradient(135deg, rgba(124,92,255,.18), rgba(76,125,255,.14)); border-color:rgba(124,92,255,.32); color:#eff0ff; }
.ghost:hover, .btn:hover, .pillbtn:hover, .danger:hover { filter: brightness(1.06); }
.ghost svg, .pillbtn svg, .btn svg, .danger svg, .menu-btn svg { width:18px; height:18px; flex:0 0 auto; }
.avatar { width:34px; height:34px; border-radius:999px; background: linear-gradient(135deg, var(--green), var(--green2)); display:grid; place-items:center; font-weight:800; color:#f8faff; }
.user { color:#dce4f2; font-weight:700; }
.page { padding:18px 22px 24px; }
.widgets { display:grid; grid-template-columns: 1.2fr 1fr 1fr; gap:14px; }
.widget, .section, .hero, .tablewrap { background: linear-gradient(180deg, var(--panel2), var(--panel)); border:1px solid var(--line); border-radius:18px; box-shadow: 0 8px 28px rgba(0,0,0,.2); }
.widget { padding:20px; min-height:110px; }
.widget-head { display:flex; align-items:center; gap:12px; }
.ico { width:34px; height:34px; border-radius:12px; display:grid; place-items:center; background: linear-gradient(135deg, rgba(124,92,255,.16), rgba(76,125,255,.12)); color:#c9bbff; border:1px solid rgba(124,92,255,.28); }
.ico svg { width:18px; height:18px; }
.widget .label { color:#b5c0d4; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
.widget .value { margin-top:16px; font-size:31px; font-weight:800; }
.widget .sub { margin-top:8px; color:var(--muted); font-size:13px; }
.hero { margin-top:16px; padding:18px; display:grid; grid-template-columns: 1.05fr 1fr; gap:18px; }
.hero-left { min-height:290px; display:flex; align-items:center; justify-content:center; background: radial-gradient(circle at top, rgba(124,92,255,.16), rgba(24,27,35,.92)); border:1px solid var(--line); border-radius:16px; }
.hex { width:164px; height:190px; background: linear-gradient(180deg, rgba(124,92,255,.88), rgba(76,125,255,.7)); clip-path: polygon(50% 0, 93% 25%, 93% 75%, 50% 100%, 7% 75%, 7% 25%); display:grid; place-items:center; box-shadow:0 0 0 14px rgba(124,92,255,.12); }
.hex:after { content:''; width:84px; height:96px; background: rgba(189,175,255,.65); clip-path: polygon(50% 0, 93% 25%, 93% 75%, 50% 100%, 7% 75%, 7% 25%); }
.hero-right { padding:6px 6px 0; }
.section-title { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:14px; }
.section-title h2 { margin:0; font-size:20px; }
.section-title a { color: var(--green); text-decoration:none; }
.monitor-grid { display:grid; grid-template-columns: 1.4fr 1fr; gap:14px; }
.monitor-card { padding:20px; border-radius:22px; border:1px solid var(--line); background: linear-gradient(180deg, #222837, #171b24); box-shadow: 0 12px 30px rgba(0,0,0,.22); }
.monitor-card .title-row { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:14px; }
.monitor-card h3 { margin:0; font-size:18px; }
.monitor-card .lead { color:var(--muted); font-size:13px; line-height:1.5; }
.monitor-kpis { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:12px; margin-top:16px; }
.kpi { padding:14px; border-radius:16px; background:#171b24; border:1px solid var(--line); }
.kpi span { display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
.kpi strong { font-size:18px; }
.status-line { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
.status-pill { display:inline-flex; align-items:center; gap:8px; padding:8px 10px; border-radius:999px; border:1px solid var(--line); background:#171b24; color:#dbe3f5; font-size:13px; }
.status-pill.good { border-color: rgba(76,125,255,.42); background: linear-gradient(135deg, rgba(124,92,255,.18), rgba(76,125,255,.12)); }
.status-pill.bad { border-color: rgba(255,100,124,.38); background: rgba(255,100,124,.08); }
.status-dot { width:8px; height:8px; border-radius:99px; background: currentColor; }
.sys-grid { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:14px; }
.sys-card { padding:18px; border-radius:18px; border:1px solid var(--line); background: linear-gradient(180deg, #202633, #171b23); }
.sys-card .label { color:#b5c0d4; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
.sys-card .value { margin-top:14px; font-size:28px; font-weight:800; }
.sys-card .sub { margin-top:8px; color:var(--muted); font-size:13px; }
.sys-hero { display:grid; grid-template-columns: minmax(0, 270px) minmax(0,1fr); gap:16px; align-items:stretch; }
.gauge-card { padding:14px; border-radius:22px; border:1px solid var(--line); background: linear-gradient(180deg, #232938, #171b23); position:relative; overflow:hidden; min-height: 320px; }
.gauge-card:before { content:''; position:absolute; inset:0; background: radial-gradient(circle at 50% 18%, rgba(124,92,255,.18), transparent 38%); pointer-events:none; }
.gauge-card > * { position:relative; }
.gauge-top { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:12px; }
.gauge-title { font-size:17px; font-weight:800; letter-spacing:-.03em; }
.gauge-sub { color:var(--muted); font-size:13px; margin-top:6px; }
.gauge-stage { display:grid; place-items:center; padding:0 0 4px; }
.gauge { width:170px; height:170px; position:relative; display:grid; place-items:center; }
.gauge-ring { width:100%; height:100%; border-radius:50%; background: radial-gradient(circle at center, rgba(17,19,24,.98) 0 54%, transparent 54.4%), conic-gradient(from -90deg, var(--gauge-color, #4c7dff) 0 var(--gauge-fill, 0%), rgba(255,255,255,.08) var(--gauge-fill, 0%) 100%); box-shadow: inset 0 0 0 1px rgba(255,255,255,.04), 0 10px 24px rgba(0,0,0,.26); transition: background .35s ease; }
.gauge-ring::after { content:''; position:absolute; inset:18px; border-radius:50%; background: linear-gradient(180deg, rgba(13,16,22,.98), rgba(17,19,24,.92)); box-shadow: inset 0 0 0 1px rgba(255,255,255,.03); }
.gauge-value { position:absolute; inset:0; display:grid; place-items:center; text-align:center; z-index:1; }
.gauge-value strong { display:block; font-size:36px; line-height:1; letter-spacing:-.05em; transition: color .35s ease, transform .35s ease; }
.gauge-value span { display:block; margin-top:6px; color:var(--muted); font-size:12px; }
.gauge-arc-label { position:absolute; bottom:-4px; left:50%; transform:translateX(-50%); color:var(--muted); font-size:12px; }
.gauge-hint { display:flex; justify-content:space-between; gap:10px; margin-top:12px; color:var(--muted); font-size:12px; }
.gauge-mini-grid { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:10px; margin-top:12px; }
.gauge-mini { padding:10px 12px; border-radius:14px; background:#171b24; border:1px solid var(--line); }
.gauge-mini span { display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; margin-bottom:6px; }
.gauge-mini strong { font-size:16px; }
.net-bar { height:10px; border-radius:999px; background:#121621; border:1px solid rgba(255,255,255,.05); overflow:hidden; }
.net-bar-fill { height:100%; border-radius:999px; transition: width .6s ease, background .35s ease; }
.metric-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:14px; }
.metric-card { padding:14px; border-radius:22px; border:1px solid var(--line); background:#171b24; min-height:232px; position:relative; overflow:hidden; }
.metric-card:before { content:''; position:absolute; inset:0; background: radial-gradient(circle at 50% 20%, color-mix(in srgb, var(--metric-color, #4c7dff) 22%, transparent), transparent 42%); opacity:.95; pointer-events:none; }
.metric-card > * { position:relative; }
.metric-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:10px; }
.metric-title { color:#cdd6e8; font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { font-size:22px; font-weight:800; line-height:1.05; }
.metric-sub { margin-top:6px; color:var(--muted); font-size:13px; line-height:1.25; font-weight:700; }
.metric-ring-wrap { display:grid; place-items:center; margin-top:2px; }
.metric-ring { width:150px; height:150px; position:relative; border-radius:50%; background: radial-gradient(circle at center, rgba(15,17,24,.98) 0 58%, transparent 58.4%), conic-gradient(from -90deg, var(--metric-color, #4c7dff) 0 var(--metric-fill, 0%), rgba(255,255,255,.08) var(--metric-fill, 0%) 100%); box-shadow: inset 0 0 0 1px rgba(255,255,255,.04), 0 12px 26px rgba(0,0,0,.24); transition: background .35s ease, transform .35s ease; }
.metric-ring::after { content:''; position:absolute; inset:18px; border-radius:50%; background: linear-gradient(180deg, rgba(13,16,22,.98), rgba(17,19,24,.92)); box-shadow: inset 0 0 0 1px rgba(255,255,255,.03); }
.metric-ring-value { position:absolute; inset:0; display:grid; place-items:center; text-align:center; z-index:1; }
.metric-ring-value strong { display:block; font-size:22px; line-height:1; letter-spacing:-.05em; transition: color .35s ease; }
.metric-ring-value span { display:none; }
.metric-rail { height:11px; margin-top:10px; border-radius:999px; background:#10141b; border:1px solid rgba(255,255,255,.05); overflow:hidden; }
.metric-fill { height:100%; border-radius:999px; transition: width .6s ease, background .35s ease; }
.sys-summary { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:14px; }
.sys-summary .sys-card .value { font-size:26px; }
.sys-row { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:14px; margin-top:14px; }
.sys-pill { padding:14px 16px; border-radius:16px; border:1px solid var(--line); background:#191d25; }
.sys-pill span { display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
.sys-pill strong { font-size:18px; }
.client-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:14px; }
.client-card { padding:18px; border-radius:18px; border:1px solid var(--line); background: linear-gradient(180deg, #202633, #171b23); }
.client-card .head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:12px; }
.client-card .name { font-size:18px; font-weight:800; letter-spacing:-.02em; }
.client-card .meta { display:grid; gap:10px; margin-top:12px; }
.client-card .meta .row { display:flex; justify-content:space-between; gap:14px; align-items:flex-start; font-size:14px; }
.client-card .meta .row span { color:var(--muted); }
.client-card .profile { margin-top:12px; padding:12px; border-radius:14px; background:#10141b; border:1px solid rgba(160,171,192,.12); display:grid; gap:8px; }
.client-card .profile .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
.client-card .profile code { color:#e7ecff; font-size:13px; line-height:1.5; }
.client-card .actions { margin-top:14px; }
.client-card .actions .ghost, .client-card .actions .danger { flex:1; }
.rule-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:14px; }
.rule-tile { padding:18px; border-radius:18px; border:1px solid var(--line); background: linear-gradient(180deg, #202633, #171b23); }
.rule-tile .label { color:#b5c0d4; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
.rule-tile .value { margin-top:14px; font-size:28px; font-weight:800; }
.rule-tile .sub { margin-top:8px; color:var(--muted); font-size:13px; }
.rule-chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
.rule-chip { display:inline-flex; align-items:center; padding:8px 10px; border-radius:999px; background:#171b24; border:1px solid var(--line); color:#dbe3f5; font-size:12px; }
.rule-chip.good { border-color: rgba(76,125,255,.42); background: linear-gradient(135deg, rgba(124,92,255,.18), rgba(76,125,255,.12)); }
.rule-chip.warn { border-color: rgba(255,200,87,.38); background: rgba(255,200,87,.08); }
.rule-chip.bad { border-color: rgba(255,100,124,.38); background: rgba(255,100,124,.08); }
.manage-grid { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:14px; }
.manage-card { padding:16px; border-radius:22px; border:1px solid rgba(160,171,192,.18); background:linear-gradient(180deg, rgba(32,38,53,.92), rgba(17,21,31,.92)); }
.manage-card .manage-head { display:flex; justify-content:space-between; gap:10px; align-items:flex-start; margin-bottom:12px; }
.manage-card strong { font-size:18px; overflow-wrap:anywhere; }
.manage-card .sub { color:var(--muted); font-size:13px; line-height:1.45; }
.issued-key { margin-top:14px; border:1px solid rgba(160,171,192,.18); border-radius:20px; background:rgba(10,13,22,.45); overflow:hidden; }
.issued-key > summary { list-style:none; cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px 16px; }
.issued-key > summary::-webkit-details-marker { display:none; }
.issued-key > summary strong { font-size:16px; }
.issued-key-body { padding:0 16px 16px; }
.progress { height:10px; border-radius:999px; background:#10141b; border:1px solid rgba(255,255,255,.05); overflow:hidden; margin-top:12px; }
.progress span { display:block; height:100%; border-radius:999px; background:linear-gradient(90deg, #7c5cff, #12d6ff); }
.stats { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:16px 30px; }
.stat { min-width:0; }
.stat .k { color:var(--muted); margin-right:8px; }
.stat .v { font-weight:700; }
.bar { height:16px; width:110px; background:#38404f; border-radius:6px; display:inline-block; vertical-align:middle; overflow:hidden; }
.bar > span { display:block; height:100%; width:24%; background: linear-gradient(90deg, var(--green), #26ecd4); }
.section { margin-top:18px; padding:18px; }
.section h3 { margin:0 0 14px; font-size:18px; }
.muted { color:var(--muted); }
.notice { color:#7ff0c8; }
.error { color:var(--danger); }
.toolbar { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
input, select { width:100%; background:#10141b; color:var(--text); border:1px solid var(--line); border-radius:14px; padding:13px 14px; font-size:14px; outline:none; }
input:focus, select:focus { border-color: rgba(24,211,155,.7); box-shadow: 0 0 0 4px rgba(24,211,155,.11); }
.grid2 { display:grid; grid-template-columns: 1fr auto; gap:12px; align-items:center; }
.quick-grid { display:grid; grid-template-columns: repeat(5, minmax(0,1fr)); gap:12px; }
.tile-link { display:flex; flex-direction:column; gap:8px; text-decoration:none; color:var(--text); padding:16px; border-radius:18px; border:1px solid var(--line); background: linear-gradient(180deg, #202633, #171b23); min-height:130px; }
.tile-link strong { font-size:16px; }
.tile-link span:last-child { color:var(--muted); font-size:13px; }
.tile-link:hover { border-color:rgba(124,92,255,.4); transform: translateY(-1px); }
.kv-grid { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:12px; }
.kv { padding:14px 16px; border-radius:16px; border:1px solid var(--line); background:#191d25; display:flex; justify-content:space-between; gap:12px; align-items:center; }
.kv span { color:var(--muted); }
.kv strong { font-size:15px; text-align:right; }
table { width:100%; min-width: 720px; border-collapse: separate; border-spacing:0; overflow:hidden; border-radius:16px; border:1px solid var(--line); }
th, td { padding:12px 14px; text-align:left; vertical-align:top; border-bottom:1px solid var(--line); }
th { background:#232935; color:#dbe4f4; font-size:12px; letter-spacing:.08em; text-transform:uppercase; }
td { background:#191d25; }
tr:last-child td { border-bottom:0; }
.actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.danger { background:#3a1723; border-color:#6f3045; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
code { color:#b4c0ff; word-break:break-all; }
pre { margin:0; padding:14px; border-radius:16px; background:#0e1117; border:1px solid var(--line); overflow:auto; max-height:420px; }
.tablewrap { overflow:auto; border-radius:16px; }
.mobile-drawer, .drawer-backdrop { display:none; }
.dual { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:16px; }
.mini { color:var(--muted); font-size:13px; }
.login-cta { color:var(--muted); margin-top:8px; }
.badge { display:inline-flex; align-items:center; gap:8px; padding:8px 11px; border-radius:999px; background: linear-gradient(135deg, rgba(124,92,255,.16), rgba(76,125,255,.12)); border:1px solid rgba(124,92,255,.3); color:#ece8ff; font-size:13px; }
.legacy { padding:4px 8px; border-radius:999px; background:#243038; border:1px solid #34414e; font-size:12px; color:#d3dded; }
.qr-modal-backdrop { position:fixed; inset:0; background:rgba(4,6,10,.72); z-index:55; }
.qr-modal { position:fixed; inset:0; z-index:56; display:grid; place-items:center; padding:18px; }
.qr-modal-card { width:min(92vw, 560px); background: linear-gradient(180deg, #222837, #171b24); border:1px solid var(--line); border-radius:24px; box-shadow: 0 30px 90px rgba(0,0,0,.55); padding:18px; }
.qr-modal-body { display:grid; place-items:center; padding:10px 6px 6px; }
.qr-modal-body img { width:min(82vw, 420px); height:auto; background:#fff; border-radius:18px; padding:12px; }
.qr-modal[hidden], .qr-modal-backdrop[hidden] { display:none !important; }
@media (max-width: 1200px) { .quick-grid { grid-template-columns: repeat(3, minmax(0,1fr)); } }
@media (max-width: 1100px) { .widgets { grid-template-columns: 1fr 1fr; } .hero { grid-template-columns: 1fr; } .kv-grid { grid-template-columns: 1fr; } .monitor-grid, .client-grid, .rule-grid, .sys-grid, .sys-summary, .sys-row { grid-template-columns: 1fr 1fr; } .sys-hero { grid-template-columns: 1fr; } }
@media (max-width: 780px) { .app { grid-template-columns: 1fr; } .sidebar { display:none; } .menu-btn { display:inline-flex; } .topbar { padding:12px 14px 8px; z-index:20; } .topbar-row { gap:10px; align-items:flex-start; } .title { font-size:20px; } .user { display:none; } .widgets, .dual, .monitor-grid, .client-grid, .rule-grid, .sys-grid { grid-template-columns: 1fr; } .hero { grid-template-columns:1fr; padding:12px; } .hero-left { min-height:160px; } .page { padding:10px 10px 16px; } .quick-grid { grid-template-columns: 1fr; } .widget { padding:14px; } .section { padding:14px; } .monitor-card { padding:16px; } .monitor-kpis { grid-template-columns: 1fr; } .kpi { padding:12px; } .section-title { align-items:flex-start; flex-direction:column; } .actions { flex-direction:column; align-items:stretch; } .actions form, .actions a, .actions button { width:100%; } .grid2 { grid-template-columns:1fr; } .tablewrap { margin:0 -2px; } .client-card .actions { display:grid; grid-template-columns:1fr 1fr 1fr; } .client-card .actions .ghost, .client-card .actions .danger { width:100%; } .mobile-drawer { display:block; position:fixed; top:0; left:0; width:min(84vw, 320px); height:100vh; background: linear-gradient(180deg, #161a23, #11141a); border-right:1px solid var(--line); box-shadow: 22px 0 60px rgba(0,0,0,.45); transform: translateX(-102%); transition: transform .2s ease; z-index:40; } body.drawer-open .mobile-drawer { transform: translateX(0); } .drawer-backdrop { display:block; position:fixed; inset:0; background: rgba(5,7,12,.56); opacity:0; pointer-events:none; transition: opacity .2s ease; z-index:35; } body.drawer-open .drawer-backdrop { opacity:1; pointer-events:auto; } .drawer-panel { height:100%; display:flex; flex-direction:column; padding:16px; gap:14px; } .drawer-header { display:flex; align-items:center; justify-content:space-between; gap:10px; } .drawer-title { display:flex; align-items:center; gap:12px; font-weight:800; } .drawer-links { display:grid; gap:8px; } .drawer-link { display:flex; align-items:center; gap:12px; padding:12px 14px; border-radius:16px; border:1px solid var(--line); text-decoration:none; color:var(--text); background:#171b24; } .drawer-link.active { background: linear-gradient(135deg, rgba(124,92,255,.22), rgba(76,125,255,.16)); border-color: rgba(124,92,255,.42); } .drawer-link svg { width:18px; height:18px; } .drawer-footer { margin-top:auto; display:grid; gap:10px; } }
/* Modern compact redesign layer */
body { background: radial-gradient(circle at 15% -10%, rgba(124,92,255,.22), transparent 34%), radial-gradient(circle at 88% 8%, rgba(76,125,255,.18), transparent 32%), linear-gradient(180deg, #090b12 0%, #111520 55%, #090b12 100%); }
.app { grid-template-columns: 86px minmax(0,1fr); }
.content { min-height:100vh; }
.page { max-width:1180px; margin:0 auto; padding:20px; }
.topbar { border-bottom:1px solid rgba(255,255,255,.07); background: rgba(9,11,18,.72); box-shadow: 0 12px 34px rgba(0,0,0,.24); }
.title { font-size:24px; }
.sidebar { background: rgba(8,10,16,.74); backdrop-filter: blur(18px); border-right:1px solid rgba(255,255,255,.07); }
.navicon { color:#aeb9d3; }
.navicon.active { color:#fff; box-shadow: inset 0 0 0 1px rgba(124,92,255,.26), 0 12px 26px rgba(76,125,255,.1); }
.brand, .avatar { background: linear-gradient(135deg, #7c5cff 0%, #4c7dff 52%, #12d6ff 100%); }
.section, .monitor-card, .client-card, .sys-card, .rule-tile, .tile-link, .widget, .hero, .tablewrap { background: linear-gradient(180deg, rgba(32,38,53,.92), rgba(17,21,31,.92)); border-color: rgba(160,171,192,.18); box-shadow: 0 16px 50px rgba(0,0,0,.22); }
.section { border-radius:24px; }
.monitor-card { border-radius:26px; min-height:0; position:relative; overflow:hidden; }
.monitor-card:before { content:''; position:absolute; inset:0; background: radial-gradient(circle at 88% 0%, rgba(124,92,255,.2), transparent 34%); pointer-events:none; }
.monitor-card > * { position:relative; }
.monitor-card h3 { font-size:24px; letter-spacing:-.04em; }
.monitor-card .lead { font-size:14px; color:#b0bbd0; }
.monitor-kpis { grid-template-columns: repeat(3, minmax(0,1fr)); }
.kpi { background: rgba(10,13,22,.45); border-color: rgba(160,171,192,.18); }
.kpi strong { font-size:22px; letter-spacing:-.03em; }
.status-pill, .badge, .rule-chip { background: rgba(17,22,34,.72); border-color: rgba(160,171,192,.2); }
.status-pill.good, .rule-chip.good { color:#e9e5ff; background: linear-gradient(135deg, rgba(124,92,255,.28), rgba(76,125,255,.14)); border-color: rgba(124,92,255,.42); }
.status-pill.bad, .rule-chip.bad { color:#ffd9df; background: rgba(255,100,124,.1); border-color: rgba(255,100,124,.34); }
.sys-grid { gap:12px; }
.sys-card, .rule-tile, .client-card { border-radius:22px; padding:16px; }
.sys-card .value, .rule-tile .value { font-size:34px; letter-spacing:-.05em; }
.client-card .name { font-size:20px; }
.client-card .meta { background: rgba(9,12,20,.32); border:1px solid rgba(160,171,192,.12); border-radius:16px; padding:12px; }
.client-card .meta .row strong { min-width:0; text-align:right; overflow-wrap:anywhere; }
.quick-grid { grid-template-columns: repeat(4, minmax(0,1fr)); }
.tile-link { min-height:105px; }
.section-title h2 { font-size:22px; letter-spacing:-.04em; }
.ghost, .pillbtn, .btn, .danger, button { min-height:42px; }
@media (max-width: 780px) {
  .page { padding:10px; }
  .topbar { border-radius:0 0 22px 22px; }
  .topbar-row { align-items:center; }
  .title { font-size:22px; }
  .monitor-grid { gap:10px; }
  .monitor-card, .section, .client-card, .sys-card, .rule-tile { border-radius:20px; padding:14px; }
  .monitor-card h3 { font-size:22px; }
  .monitor-card .lead { display:none; }
  .monitor-kpis { display:flex; overflow-x:auto; gap:10px; margin-top:12px; padding-bottom:2px; scrollbar-width:none; }
  .monitor-kpis::-webkit-scrollbar { display:none; }
  .kpi { min-width:136px; }
  .status-line { margin-top:10px; }
  .sys-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
  .sys-card .value, .rule-tile .value { font-size:30px; }
  .client-grid { gap:10px; }
  .client-card .meta { gap:7px; padding:10px; }
  .client-card .meta .row { font-size:13px; }
  .quick-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
  .tile-link { min-height:92px; padding:12px; }
}
/* Mobile hardening: never let cards push the viewport sideways. */
html, body { width:100%; max-width:100%; overflow-x:hidden; }
*, *:before, *:after { min-width:0; }
.app, .content, .page { max-width:100vw; overflow-x:hidden; }
.monitor-card, .client-card, .sys-card, .rule-tile, .section, .widget, .tile-link, .kpi, .kv { min-width:0; overflow:hidden; }
.kpi strong, .status-pill, .badge, .client-card .meta .row strong, .sys-card .sub, .rule-chip, code { overflow-wrap:anywhere; word-break:break-word; }
.monitor-kpis, .status-line, .rule-chips, .actions { max-width:100%; }
@media (max-width: 900px) {
  .app { display:block; }
  .content { width:100%; }
  .page { width:100%; padding:10px; }
  .topbar { width:100%; }
  .topbar-row { display:grid; grid-template-columns:42px minmax(0,1fr) 42px; align-items:center; gap:10px; }
  .title { font-size:22px; line-height:1.1; overflow-wrap:anywhere; }
  .top-actions { justify-content:flex-end; }
  .monitor-grid, .client-grid, .rule-grid, .sys-grid, .widgets, .dual, .quick-grid { grid-template-columns:1fr; }
  .monitor-card, .client-card, .sys-card, .rule-tile, .section { padding:14px; border-radius:20px; }
  .monitor-kpis { display:grid; grid-template-columns:1fr; overflow:visible; }
  .kpi { min-width:0; }
  .status-pill { max-width:100%; }
  .client-card .head { flex-direction:column; align-items:flex-start; }
  .client-card .actions { display:grid; grid-template-columns:1fr; }
  .sys-grid { gap:10px; }
}
/* Concept redesign: product-like control center, not a pile of boxes. */
@media (min-width: 901px) {
  .app { display:grid; grid-template-columns:260px minmax(0,1fr); }
  .sidebar { align-items:stretch; padding:18px 14px; gap:8px; }
  .side-brand { display:flex; align-items:center; gap:12px; padding:6px 8px 18px; }
  .side-brand strong { display:block; font-size:18px; letter-spacing:-.03em; }
  .side-brand span { display:block; color:var(--muted); font-size:12px; margin-top:2px; }
  .navicon { width:100%; height:auto; min-height:48px; display:flex; justify-content:flex-start; gap:12px; padding:12px 14px; border-radius:16px; }
  .navicon span { display:inline; font-weight:700; }
  .sidebar > .brand { display:none; }
  .sidebar > .navicon:last-child { margin-top:auto; }
}
.ops-hero { display:grid; grid-template-columns:minmax(0,1.45fr) minmax(280px,.75fr); gap:16px; padding:22px; border:1px solid rgba(160,171,192,.18); border-radius:28px; background: radial-gradient(circle at 18% 8%, rgba(124,92,255,.28), transparent 36%), linear-gradient(135deg, rgba(29,36,57,.96), rgba(13,17,29,.96)); box-shadow:0 22px 70px rgba(0,0,0,.28); }
.ops-hero.summary-only { grid-template-columns:1fr; }
.ops-eyebrow { display:inline-flex; padding:8px 11px; border-radius:999px; background:rgba(124,92,255,.16); border:1px solid rgba(124,92,255,.28); color:#d9d2ff; font-size:12px; text-transform:uppercase; letter-spacing:.12em; }
.ops-headline h1 { margin:18px 0 10px; font-size:44px; line-height:.98; letter-spacing:-.06em; max-width:680px; }
.ops-headline p { margin:0; color:#afbad0; font-size:16px; line-height:1.55; max-width:640px; }
.ops-actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:22px; }
.ops-health { display:grid; gap:10px; align-content:center; }
.summary-cards { grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:18px; }
.ops-health-row { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:14px; border-radius:18px; border:1px solid rgba(160,171,192,.16); background:rgba(9,12,20,.38); }
.ops-health-row span { color:#aeb9d3; }
.ops-health-row strong { text-align:right; overflow-wrap:anywhere; }
.ops-health-row strong.good { color:#c8d4ff; }
.ops-health-row strong.bad { color:#ff9aad; }
.ops-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:14px; }
.ops-card { padding:18px; border-radius:22px; border:1px solid rgba(160,171,192,.16); background:linear-gradient(180deg, rgba(31,38,55,.9), rgba(15,19,29,.9)); }
.ops-card.primary { background:linear-gradient(135deg, rgba(124,92,255,.32), rgba(76,125,255,.14)); border-color:rgba(124,92,255,.36); }
.ops-card span { display:block; color:#aeb9d3; font-size:12px; letter-spacing:.1em; text-transform:uppercase; }
.ops-card strong { display:block; margin-top:12px; font-size:34px; line-height:1; letter-spacing:-.06em; }
.ops-card em { display:block; margin-top:8px; color:#9ca8bd; font-style:normal; font-size:13px; overflow-wrap:anywhere; }
.ops-split { display:grid; grid-template-columns:1.15fr .85fr; gap:14px; margin-top:14px; }
.ops-panel { padding:18px; border-radius:24px; border:1px solid rgba(160,171,192,.16); background:linear-gradient(180deg, rgba(31,38,55,.9), rgba(15,19,29,.9)); box-shadow:0 14px 44px rgba(0,0,0,.2); }
.ops-panel-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px; }
.ops-panel-head h2 { margin:0; font-size:22px; letter-spacing:-.04em; }
.ops-panel-head a, .ops-panel-head span { color:#aeb9d3; text-decoration:none; font-size:13px; }
.ops-clients { display:grid; gap:8px; }
.ops-client { display:grid; grid-template-columns:12px minmax(0,1fr) auto; gap:10px; align-items:center; padding:12px; border-radius:16px; border:1px solid rgba(160,171,192,.12); background:rgba(9,12,20,.32); text-decoration:none; }
.ops-client strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.ops-client em { color:#cfd7ea; font-style:normal; font-size:13px; }
.ops-client small { grid-column:2 / 4; color:#8d99ad; }
.status-dot.good { background:#7c5cff; }
.status-dot.bad { background:#ff647c; }
.ops-shortcuts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
.ops-shortcuts a { min-height:84px; display:flex; flex-direction:column; justify-content:space-between; padding:14px; border-radius:18px; border:1px solid rgba(160,171,192,.14); background:rgba(9,12,20,.34); text-decoration:none; }
.ops-shortcuts svg { width:22px; height:22px; color:#bfb4ff; }
.ops-shortcuts span { font-weight:800; }
.ops-empty { padding:16px; border-radius:16px; background:rgba(9,12,20,.32); color:#aeb9d3; }
@media (max-width:900px) {
  .side-brand { display:none; }
  .ops-hero, .ops-split, .ops-grid { grid-template-columns:1fr; }
  .summary-cards { grid-template-columns:1fr; }
  .manage-grid { grid-template-columns:1fr; }
  .logout-top { padding:9px; font-size:0; }
  .logout-top svg { margin:0; }
  .ops-hero { padding:16px; border-radius:22px; }
  .ops-headline h1 { font-size:34px; }
  .ops-headline p { font-size:14px; }
  .ops-actions { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; }
  .ops-actions a { padding-left:8px; padding-right:8px; }
  .ops-grid { gap:10px; }
  .ops-card strong { font-size:30px; }
  .ops-panel { padding:14px; border-radius:20px; }
  .ops-shortcuts { grid-template-columns:1fr 1fr; }
}
@media (max-width:900px) {
  .mobile-drawer { overflow-y:auto; -webkit-overflow-scrolling:touch; overscroll-behavior:contain; }
  .drawer-panel { min-height:100%; height:auto; max-height:none; overflow:visible; }
  .drawer-links { overflow:visible; padding-bottom:24px; }
  .topbar-row { grid-template-columns:42px minmax(0,1fr) auto; }
  .top-actions { min-width:0; max-width:88px; overflow:hidden; gap:6px; justify-content:flex-end; }
  .top-actions .avatar { width:38px; height:38px; flex:0 0 38px; }
  .top-actions .user { display:none; }
  .top-actions .logout-top { display:inline-flex; width:38px; height:38px; min-height:38px; padding:0; font-size:0; flex:0 0 38px; }
  .top-actions .logout-top svg { width:18px; height:18px; }
  .metric-grid { grid-template-columns:1fr; gap:10px; }
  .metric-card { min-height:190px; padding:12px; }
  .metric-ring { width:124px; height:124px; }
  .metric-ring::after { inset:15px; }
  .metric-ring-value strong { font-size:21px; }
  .metric-sub { font-size:12px; text-align:center; margin-top:4px; }
}
@media (min-width:520px) and (max-width:900px) {
  .metric-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
    """


def service_status(name):
    unit = SERVICE_MAP[name]
    active_res = subprocess.run(["systemctl", "is-active", unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    active = (active_res.stdout or active_res.stderr or "unknown").strip() or "unknown"
    enabled_res = subprocess.run(["systemctl", "is-enabled", unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    enabled = (enabled_res.stdout or enabled_res.stderr or "unknown").strip() or "unknown"
    if name == "awg" and active in {"inactive", "failed", "unknown"}:
        try:
            if run(["awg", "show", CFG["iface"]]).strip():
                active = "active"
        except Exception:
            pass
    return {"name": name, "unit": unit, "active": active, "enabled": enabled}


def service_action(name, action):
    unit = SERVICE_MAP[name]
    if action not in {"start", "stop", "restart", "reload", "enable", "disable"}:
        raise RuntimeError("invalid action")
    if action in {"enable", "disable"}:
        run(["systemctl", action, unit])
        return
    run(["systemctl", action, unit])


def softether_cmd(*cmds, hub=False):
    in_path = None
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as fh:
        for cmd in cmds:
            fh.write(cmd.rstrip() + "\n")
        in_path = fh.name
    try:
        candidates = [shutil.which("vpncmd"), "/usr/local/vpnserver/vpncmd", "/opt/SoftEtherVPNServer/vpncmd", "/usr/local/bin/vpncmd"]
        vpncmd = next((p for p in candidates if p and Path(p).exists()), None)
        if not vpncmd:
            raise RuntimeError("vpncmd не найден: установи SoftEther VPN Server или добавь vpncmd в PATH")
        args = [vpncmd, f"{CFG['softether_host']}:{CFG['softether_port']}", "/SERVER"]
        if hub:
            args.append(f"/HUB:{CFG['softether_hub']}")
            args.append(f"/PASSWORD:{CFG['softether_hub_password']}")
        else:
            args.append(f"/PASSWORD:{CFG['softether_admin_password']}")
        args.append(f"/IN:{in_path}")
        return run(args)
    finally:
        try:
            Path(in_path).unlink(missing_ok=True)
        except Exception:
            pass


def softether_user_list():
    text = softether_cmd("UserList", hub=True)
    users = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("-") or line.startswith("Item ") or line.startswith("The command completed"):
            continue
        if "|" not in line:
            continue
        key, value = [part.strip() for part in line.split("|", 1)]
        if key == "User Name":
            if current:
                users.append(current)
            current = {"name": value}
            continue
        if current is None:
            continue
        if key == "Full Name":
            current["full_name"] = value
        elif key == "Group Name":
            current["group_name"] = value
        elif key == "Description":
            current["description"] = value
        elif key == "Auth Method":
            current["auth_method"] = value
        elif key == "Num Logins":
            current["num_logins"] = value
        elif key == "Last Login":
            current["last_login"] = value
        elif key == "Expiration Date":
            current["expiration_date"] = value
    if current:
        users.append(current)
    return users


def softether_user_create(username, password, full_name="", note=""):
    if not username.strip():
        raise RuntimeError("имя пользователя не задано")
    if not password:
        raise RuntimeError("пароль не задан")
    cmds = [
        f"UserCreate {username.strip()} /GROUP:none /REALNAME:{full_name.strip() or 'none'} /NOTE:{note.strip() or 'none'}",
        f"UserPasswordSet {username.strip()} /PASSWORD:{password}",
    ]
    return softether_cmd(*cmds, hub=True)


def softether_user_delete(username):
    if not username.strip():
        raise RuntimeError("имя пользователя не задано")
    return softether_cmd(f"UserDelete {username.strip()}", hub=True)


def softether_snapshot():
    config = Path("/var/lib/softether/vpn_server.config")
    text = config.read_text(encoding="utf-8", errors="ignore") if config.exists() else ""
    listeners = [CFG["softether_port"], CFG["softether_listener_port"]]
    return {
        "config_exists": config.exists(),
        "sstp_enabled": "declare SSTP" in text and "bool Enabled true" in text,
        "secure_nat": "declare SecureNAT" in text,
        "listeners": listeners,
    }


def system_snapshot():
    return {
        "hostname": run(["hostnamectl", "--static"]).strip(),
        "uptime": run(["uptime", "-p"]).strip(),
        "load": run(["uptime"]).strip(),
        "disk": run(["df", "-h", "/"]).strip(),
        "memory": run(["free", "-h"]).strip(),
        "interfaces": run(["ip", "-br", "addr"]).strip(),
        "routes": run(["ip", "route"]).strip(),
        "sockets": run(["ss", "-ltnup"]).strip(),
    }


def firewall_snapshot():
    def safe(cmd):
        try:
            return run(cmd).strip()
        except Exception:
            return ""

    nft = safe(["nft", "list", "ruleset"])
    ip4_filter = safe(["iptables", "-S"])
    ip4_nat = safe(["iptables", "-t", "nat", "-S"])
    ip6_filter = safe(["ip6tables", "-S"])
    ip6_nat = safe(["ip6tables", "-t", "nat", "-S"])

    def nonempty_lines(text):
        return [line for line in text.splitlines() if line.strip()]

    def collect_iptables(text):
        chains = []
        rules = []
        for line in nonempty_lines(text):
            if line.startswith("-P "):
                chains.append(line)
            elif line.startswith("-A "):
                rules.append(line)
        return chains, rules

    nft_tables = []
    nft_chains = []
    nft_rules = []
    for line in nonempty_lines(nft):
        stripped = line.strip()
        if stripped.startswith("table "):
            nft_tables.append(stripped)
        elif stripped.startswith("chain "):
            nft_chains.append(stripped)
        elif any(stripped.startswith(prefix) for prefix in ("counter ", "accept", "drop", "masquerade", "dnat", "snat", "jump ", "goto ", "return")):
            nft_rules.append(stripped)

    ip4_filter_chains, ip4_filter_rules = collect_iptables(ip4_filter)
    ip4_nat_chains, ip4_nat_rules = collect_iptables(ip4_nat)
    ip6_filter_chains, ip6_filter_rules = collect_iptables(ip6_filter)
    ip6_nat_chains, ip6_nat_rules = collect_iptables(ip6_nat)

    backend = "nftables" if nft else ("iptables" if any((ip4_filter, ip4_nat, ip6_filter, ip6_nat)) else "unknown")
    return {
        "backend": backend,
        "nft": {
            "tables": nft_tables,
            "chains": nft_chains,
            "rules": nft_rules,
        },
        "iptables": {
            "filter_chains": ip4_filter_chains,
            "filter_rules": ip4_filter_rules,
            "nat_chains": ip4_nat_chains,
            "nat_rules": ip4_nat_rules,
        },
        "ip6tables": {
            "filter_chains": ip6_filter_chains,
            "filter_rules": ip6_filter_rules,
            "nat_chains": ip6_nat_chains,
            "nat_rules": ip6_nat_rules,
        },
        "summary": {
            "nft_tables": len(nft_tables),
            "nft_chains": len(nft_chains),
            "nft_rules": len(nft_rules),
            "ip4_rules": len(ip4_filter_rules) + len(ip4_nat_rules),
            "ip6_rules": len(ip6_filter_rules) + len(ip6_nat_rules),
        },
    }


def parse_kv_lines(text, sep=":"):
    items = []
    for line in text.splitlines():
        if sep in line:
            k, v = line.split(sep, 1)
            items.append((k.strip(), v.strip()))
    return items


def network_default_iface():
    try:
        out = run(["ip", "route", "show", "default"]).strip().splitlines()
        for line in out:
            m = re.search(r"\bdev\s+(\S+)", line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "eth0"


def read_proc_net_dev():
    data = Path("/proc/net/dev").read_text().splitlines()[2:]
    stats = {}
    for line in data:
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        fields = rest.split()
        if len(fields) >= 16:
            stats[iface.strip()] = {"rx": int(fields[0]), "tx": int(fields[8])}
    return stats


def read_proc_cpu():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = [int(x) for x in fields]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return total, idle


def format_bytes(value):
    value = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024


def collect_metrics():
    cpu_count = os.cpu_count() or 1
    load1, load5, load15 = os.getloadavg()
    cpu_total_1, cpu_idle_1 = read_proc_cpu()
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            mem[k] = int(v.strip().split()[0]) * 1024
    mem_total = mem.get("MemTotal", 0)
    mem_available = mem.get("MemAvailable", 0)
    mem_used = max(mem_total - mem_available, 0)
    disk = run(["df", "-B1", "/"]).splitlines()
    disk_used = disk_total = 0
    disk_pct = "0%"
    if len(disk) >= 2:
        parts = disk[1].split()
        if len(parts) >= 5:
            disk_total = int(parts[1])
            disk_used = int(parts[2])
            disk_pct = parts[4]
    iface = network_default_iface()
    dev1 = read_proc_net_dev().get(iface, {"rx": 0, "tx": 0})
    time.sleep(0.2)
    cpu_total_2, cpu_idle_2 = read_proc_cpu()
    dev2 = read_proc_net_dev().get(iface, {"rx": 0, "tx": 0})
    cpu_total_delta = max(cpu_total_2 - cpu_total_1, 1)
    cpu_idle_delta = max(cpu_idle_2 - cpu_idle_1, 0)
    cpu_pct = max(0.0, min(100.0, (cpu_total_delta - cpu_idle_delta) / cpu_total_delta * 100.0))
    rx_rate = max(dev2["rx"] - dev1["rx"], 0) * 5
    tx_rate = max(dev2["tx"] - dev1["tx"], 0) * 5
    return {
        "cpu_count": cpu_count,
        "cpu_pct": cpu_pct,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_pct": (mem_used / mem_total * 100) if mem_total else 0,
        "disk_used": disk_used,
        "disk_total": disk_total,
        "disk_pct": disk_pct,
        "iface": iface,
        "rx_rate": rx_rate,
        "tx_rate": tx_rate,
        "rx_total": dev2["rx"],
        "tx_total": dev2["tx"],
    }


def system_payload():
    snapshot = system_snapshot()
    metrics = collect_metrics()
    return {
        "snapshot": snapshot,
        "metrics": metrics,
    }


def safe_run(cmd):
    try:
        return run(cmd).strip()
    except Exception as exc:
        return f"Ошибка: {exc}"


def audit_event(action, detail=""):
    try:
        CFG["audit_file"].parent.mkdir(parents=True, exist_ok=True)
        user = current_request_user() or "system"
        ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
        line = f"{ts}\t{user}\t{action}\t{detail}\n"
        with CFG["audit_file"].open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


def os_users_snapshot():
    users = []
    shells = {"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/usr/bin/fish"}
    for raw in Path("/etc/passwd").read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_num = int(uid)
        except ValueError:
            uid_num = 99999
        if uid_num >= 1000 or name == "root" or shell in shells:
            users.append({"name": name, "uid": uid, "gid": gid, "home": home, "shell": shell, "gecos": gecos})
    sudoers = safe_run(["getent", "group", "sudo"])
    sshd = safe_run(["systemctl", "is-active", "ssh.service"])
    if sshd.startswith("Ошибка"):
        sshd = safe_run(["systemctl", "is-active", "sshd.service"])
    auth_log = Path("/var/log/auth.log")
    recent_auth = ""
    if auth_log.exists():
        recent_auth = "\n".join(auth_log.read_text(encoding="utf-8", errors="ignore").splitlines()[-18:])
    else:
        recent_auth = safe_run(["journalctl", "-u", "ssh", "-n", "18", "--no-pager"])
    return {"users": users, "sudoers": sudoers, "sshd": sshd, "recent_auth": recent_auth}


def storage_snapshot():
    mounts = safe_run(["timeout", "2", "df", "-hT"])
    inodes = safe_run(["timeout", "2", "df", "-ih"])
    block = safe_run(["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS"])
    disks = []
    for line in safe_run(["timeout", "2", "df", "-B1", "-T"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 7:
            pct = int(parts[5].rstrip("%") or "0")
            disks.append({"fs": parts[0], "type": parts[1], "total": int(parts[2]), "used": int(parts[3]), "avail": int(parts[4]), "pct": pct, "mount": parts[6]})
    backups = []
    for path in [CFG["backup_dir"], Path("/var/backups"), CFG["state_dir"], CFG["profile_dir"]]:
        if not path.exists():
            continue
        for item in sorted(path.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)[:12]:
            try:
                backups.append({"name": item.name, "path": str(item), "size": item.stat().st_size, "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(item.stat().st_mtime))})
            except Exception:
                pass
    return {"mounts": mounts, "inodes": inodes, "block": block, "disks": disks, "backups": backups[:18]}


def process_snapshot():
    top_cpu = safe_run(["ps", "-eo", "pid,user,pcpu,pmem,comm,args", "--sort=-pcpu"])
    top_mem = safe_run(["ps", "-eo", "pid,user,pcpu,pmem,comm,args", "--sort=-pmem"])
    processes = []
    for line in top_cpu.splitlines()[1:25]:
        parts = line.split(None, 5)
        if len(parts) >= 6:
            processes.append({"pid": parts[0], "user": parts[1], "cpu": parts[2], "mem": parts[3], "comm": parts[4], "args": parts[5]})
    return {"top_cpu": "\n".join(top_cpu.splitlines()[:18]), "top_mem": "\n".join(top_mem.splitlines()[:18]), "processes": processes}


def signal_process(pid, signal_name):
    pid = str(pid or "").strip()
    if not re.fullmatch(r"\d+", pid):
        raise RuntimeError("неверный PID")
    if int(pid) <= 1:
        raise RuntimeError("нельзя управлять системным PID")
    signals = {"term": "TERM", "kill": "KILL", "hup": "HUP"}
    sig = signals.get(signal_name)
    if not sig:
        raise RuntimeError("неверный сигнал")
    run(["kill", f"-{sig}", pid])
    audit_event("process_signal", f"{sig} {pid}")


def create_backup(scope=None):
    settings = load_backup_settings()
    scope = scope or settings.get("scope", "critical")
    work_dir = CFG["backup_dir"]
    target_dir = Path(settings.get("target_path") or str(CFG["backup_dir"]))
    if settings.get("target_type") == "local":
        work_dir = target_dir
    work_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    scope = scope if scope in {"critical", "system"} else "critical"
    target = work_dir / f"{scope}-{ts}.tar.gz"
    if scope == "critical":
        paths = ["/etc", str(CFG["state_dir"]), "/opt/amnezia-panel", "/etc/systemd/system"]
        existing = [p for p in paths if Path(p).exists()]
        run(["tar", "-czf", str(target), *existing])
    else:
        run(["tar", "-czf", str(target), "--one-file-system", "--exclude=/proc", "--exclude=/sys", "--exclude=/dev", "--exclude=/run", "--exclude=/tmp", "--exclude=/var/tmp", "--exclude=/mnt", "--exclude=/media", "--exclude=/var/backups/server-panel", f"--exclude={str(work_dir)}", "/"])
    if settings.get("target_type") == "rsync":
        destination = settings.get("rsync_target", "").strip()
        if not destination:
            raise RuntimeError("rsync назначение не задано")
        run(["rsync", "-av", str(target), destination])
    audit_event("backup_create", f"{scope} {target} target={settings.get('target_type')}")
    return target


def path_has_active_mount(path):
    path = Path(path).resolve()
    mounts = set()
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                mounts.add(Path(parts[1]).resolve())
    except Exception:
        return False
    for parent in [path, *path.parents]:
        if parent == Path("/"):
            return False
        if parent in mounts:
            return True
    return False


def ssh_settings_snapshot():
    config = safe_run(["sshd", "-T"])
    wanted = {"passwordauthentication", "pubkeyauthentication", "permitrootlogin", "authorizedkeysfile", "port"}
    settings = {}
    for line in config.splitlines():
        key, _, value = line.partition(" ")
        if key in wanted:
            settings[key] = value.strip()
    override = Path("/etc/ssh/sshd_config.d/99-server-panel.conf")
    return {"settings": settings, "override": override, "override_text": override.read_text(encoding="utf-8", errors="ignore") if override.exists() else ""}


def issue_ssh_key(username, comment=""):
    username = (username or "").strip()
    if not username:
        raise RuntimeError("пользователь не задан")
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        raise RuntimeError("пользователь не найден")
    home = Path(account.pw_dir)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(ssh_dir, account.pw_uid, account.pw_gid)
    os.chmod(ssh_dir, 0o700)

    key_name = f"{username}-panel-{time.strftime('%Y%m%d-%H%M%S')}"
    with tempfile.TemporaryDirectory(prefix="sshkey-", dir="/tmp") as tmpdir:
        key_path = Path(tmpdir) / key_name
        key_comment = comment.strip() or f"{username}@{detect_public_host()}"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", key_comment, "-f", str(key_path)])
        private_key = key_path.read_text(encoding="utf-8")
        public_key = key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()

    authorized_keys = ssh_dir / "authorized_keys"
    existing = authorized_keys.read_text(encoding="utf-8", errors="ignore") if authorized_keys.exists() else ""
    if public_key not in existing:
        with authorized_keys.open("a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write(public_key + "\n")
    os.chown(authorized_keys, account.pw_uid, account.pw_gid)
    os.chmod(authorized_keys, 0o600)
    return {
        "username": username,
        "home": str(home),
        "authorized_keys": str(authorized_keys),
        "public_key": public_key,
        "private_key": private_key,
        "comment": comment.strip() or f"{username}@{detect_public_host()}",
        "issued_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def update_ssh_settings(password_auth, pubkey_auth, permit_root):
    allowed_bool = {"yes", "no"}
    allowed_root = {"yes", "no", "prohibit-password", "forced-commands-only"}
    if password_auth not in allowed_bool or pubkey_auth not in allowed_bool or permit_root not in allowed_root:
        raise RuntimeError("неверные SSH настройки")
    path = Path("/etc/ssh/sshd_config.d/99-server-panel.conf")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join([
        "# Managed by Server control center",
        f"PasswordAuthentication {password_auth}",
        f"PubkeyAuthentication {pubkey_auth}",
        f"PermitRootLogin {permit_root}",
        "",
    ])
    path.write_text(text, encoding="utf-8")
    run(["sshd", "-t"])
    try:
        run(["systemctl", "reload", "ssh.service"])
    except Exception:
        run(["systemctl", "reload", "sshd.service"])
    audit_event("ssh_settings", f"password={password_auth} pubkey={pubkey_auth} root={permit_root}")


def logs_snapshot(unit=""):
    unit = re.sub(r"[^a-zA-Z0-9@_.-]", "", unit or "")
    units = ["amnezia-panel.service", "ssh.service", "awg-quick@awg0.service", "openvpn-server@server.service", "softether-vpnserver.service", "emqx.service"]
    if unit:
        logs = safe_run(["journalctl", "-u", unit, "-n", "80", "--no-pager"])
    else:
        logs = safe_run(["journalctl", "-n", "100", "--no-pager"])
    failed = safe_run(["systemctl", "--failed", "--no-pager"])
    return {"units": units, "active_unit": unit, "logs": logs, "failed": failed}


def telemt_snapshot():
    container = "telemt"
    compose_dir = Path("/opt/telemt-docker")
    config_path = compose_dir / "telemt.toml"
    links_path = Path("/root/telemt-proxy-links.txt")
    primary_link_path = Path("/root/telemt-proxy-link.txt")
    direct_link_path = Path("/root/telemt-proxy-link-ip.txt")
    service = {"name": "telemt", "unit": "docker container telemt", "active": "inactive", "enabled": "n/a"}
    try:
        running = safe_run(["docker", "inspect", "-f", "{{.State.Running}}", container]).strip().lower()
        if running == "true":
            service["active"] = "active"
    except Exception:
        pass
    access = {"ip": "-", "port": "443", "tg_url": "", "tme_url": "", "tme_qrcode": ""}
    if links_path.exists():
        text = links_path.read_text(encoding="utf-8", errors="ignore")
        tg_urls = re.findall(r"https://t\.me/proxy\?server=[^\s]+", text)
        tg_scheme_urls = re.findall(r"tg://proxy\?server=[^\s]+", text)
        if tg_urls:
            access["tme_url"] = tg_urls[0]
            access["tg_url"] = tg_scheme_urls[0] if tg_scheme_urls else tg_urls[0]
            access["ip"] = re.search(r"server=([^&\s]+)", tg_urls[0]).group(1) if re.search(r"server=([^&\s]+)", tg_urls[0]) else "-"
    if not access["tme_url"] and primary_link_path.exists():
        access["tme_url"] = primary_link_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not access["tg_url"] and direct_link_path.exists():
        direct_text = direct_link_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"tg://proxy\?server=[^\s]+", direct_text)
        if match:
            access["tg_url"] = match.group(0)
    if config_path.exists():
        try:
            cfg_text = config_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            cfg_text = ""
    else:
        cfg_text = ""
    logs = safe_run(["docker", "logs", "--tail", "80", container])
    if not logs:
        logs = safe_run(["docker", "compose", "-f", str(compose_dir / "docker-compose.yml"), "logs", "--tail", "80", "telemt"])
    return {
        "service": service,
        "config_path": str(config_path),
        "config_exists": config_path.exists(),
        "config_text": cfg_text,
        "access": access,
        "logs": logs,
    }


def mtproto_status_payload():
    data = telemt_snapshot()
    logs = data.get("logs") or ""
    recent_problem = ""
    for line in reversed(logs.splitlines()):
        lowered = line.lower()
        if "operation was canceled" in lowered:
            continue
        if '"level":"warn"' in lowered or '"level":"error"' in lowered or ' error ' in lowered:
            recent_problem = line.strip()
            break
    return {
        "service": data.get("service", {}).get("active", "unknown"),
        "has_error": bool(recent_problem),
        "error": recent_problem,
    }


def tasks_snapshot():
    system_timers = safe_run(["systemctl", "list-timers", "--all", "--no-pager"])
    root_cron = safe_run(["crontab", "-l"])
    cron_files = []
    for path in [Path("/etc/crontab"), Path("/etc/cron.d")]:
        if path.is_file():
            cron_files.append({"name": str(path), "text": path.read_text(encoding="utf-8", errors="ignore")})
        elif path.is_dir():
            for item in sorted(path.iterdir()):
                if item.is_file():
                    cron_files.append({"name": str(item), "text": item.read_text(encoding="utf-8", errors="ignore")})
    return {"timers": system_timers, "root_cron": root_cron, "cron_files": cron_files[:10]}


def domains_snapshot():
    certs = []
    live = Path("/etc/letsencrypt/live")
    if live.exists():
        for domain in sorted(live.iterdir()):
            fullchain = domain / "fullchain.pem"
            if fullchain.exists():
                dates = safe_run(["openssl", "x509", "-in", str(fullchain), "-noout", "-dates", "-subject"])
                certs.append({"domain": domain.name, "path": str(fullchain), "dates": dates})
    nginx_sites = safe_run(["bash", "-lc", "ls /etc/nginx/sites-enabled 2>/dev/null || true"])
    apache_sites = safe_run(["bash", "-lc", "ls /etc/apache2/sites-enabled 2>/dev/null || true"])
    listeners = []
    web_ports = {str(p) for p in SETTINGS.get("web_ports", ["80", "443", "8443"])}
    for line in system_snapshot()["sockets"].splitlines()[1:]:
        if any(f":{port} " in line for port in web_ports):
            listeners.append(line)
    return {"certs": certs, "nginx_sites": nginx_sites, "apache_sites": apache_sites, "listeners": listeners}


def audit_snapshot():
    entries = []
    if CFG["audit_file"].exists():
        entries = CFG["audit_file"].read_text(encoding="utf-8", errors="ignore").splitlines()[-120:]
    logins = safe_run(["last", "-n", "20"])
    failed = safe_run(["lastb", "-n", "20"])
    return {"entries": entries, "logins": logins, "failed": failed}


def fail2ban_snapshot():
    status = service_status("fail2ban") if "fail2ban" in SERVICE_MAP else {"active": "unknown", "enabled": "unknown", "unit": "fail2ban.service"}
    overall = safe_run(["fail2ban-client", "status"])
    jails = []
    match = re.search(r"Jail list:\s*(.+)", overall)
    if match:
        jails = [x.strip() for x in match.group(1).split(",") if x.strip()]
    details = []
    for jail in jails:
        text = safe_run(["fail2ban-client", "status", jail])
        banned = []
        total_failed = current_failed = total_banned = current_banned = "0"
        for line in text.splitlines():
            clean = line.replace("|-", "").replace("`-", "").strip()
            if clean.startswith("Currently failed:"):
                current_failed = clean.split(":", 1)[1].strip()
            elif clean.startswith("Total failed:"):
                total_failed = clean.split(":", 1)[1].strip()
            elif clean.startswith("Currently banned:"):
                current_banned = clean.split(":", 1)[1].strip()
            elif clean.startswith("Total banned:"):
                total_banned = clean.split(":", 1)[1].strip()
            elif "Banned IP list:" in clean:
                banned = [x.strip() for x in clean.split(":", 1)[1].split() if x.strip()]
        details.append({"name": jail, "text": text, "banned": banned, "current_failed": current_failed, "total_failed": total_failed, "current_banned": current_banned, "total_banned": total_banned})
    logs = safe_run(["journalctl", "-u", "fail2ban.service", "-n", "80", "--no-pager"])
    return {"service": status, "overall": overall, "jails": details, "logs": logs}


def fail2ban_unban(jail, ip):
    jail = re.sub(r"[^a-zA-Z0-9_.-]", "", jail or "")
    ip = (ip or "").strip()
    if not jail or not ip:
        raise RuntimeError("jail или IP не задан")
    run(["fail2ban-client", "set", jail, "unbanip", ip])
    audit_event("fail2ban_unban", f"{jail} {ip}")


def default_backup_settings():
    return {
        "target_type": "local",
        "target_path": str(CFG["backup_dir"]),
        "rsync_target": "",
        "scope": "critical",
        "schedule_enabled": False,
        "schedule": "daily",
        "custom_calendar": "",
    }


def load_backup_settings():
    settings = default_backup_settings()
    if CFG["backup_settings_file"].exists():
        try:
            data = json.loads(CFG["backup_settings_file"].read_text(encoding="utf-8"))
            if isinstance(data, dict):
                settings.update({k: data.get(k, v) for k, v in settings.items()})
        except Exception:
            pass
    if settings["target_type"] not in {"local", "rsync"}:
        settings["target_type"] = "local"
    if settings["scope"] not in {"critical", "system"}:
        settings["scope"] = "critical"
    if settings["schedule"] not in {"hourly", "daily", "weekly", "monthly", "custom"}:
        settings["schedule"] = "daily"
    return settings


def save_backup_settings(settings):
    CFG["backup_settings_file"].write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def backup_on_calendar(settings):
    if settings.get("schedule") == "hourly":
        return "hourly"
    if settings.get("schedule") == "weekly":
        return "weekly"
    if settings.get("schedule") == "monthly":
        return "monthly"
    if settings.get("schedule") == "custom" and settings.get("custom_calendar", "").strip():
        return settings["custom_calendar"].strip()
    return "daily"


def configure_backup_timer(settings):
    backup_units = SETTINGS.get("backup_timer", {})
    service_unit = backup_units.get("service_unit", "server-panel-backup.service")
    timer_unit = backup_units.get("timer_unit", "server-panel-backup.timer")
    service_path = Path("/etc/systemd/system") / service_unit
    timer_path = Path("/etc/systemd/system") / timer_unit
    service_text = """[Unit]
Description=Server Panel Backup

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/amnezia-panel/panel2.py --run-backup
"""
    timer_text = f"""[Unit]
Description=Server Panel Backup Timer

[Timer]
OnCalendar={backup_on_calendar(settings)}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""
    service_path.write_text(service_text, encoding="utf-8")
    timer_path.write_text(timer_text, encoding="utf-8")
    run(["systemctl", "daemon-reload"])
    if settings.get("schedule_enabled"):
        run(["systemctl", "enable", "--now", timer_unit])
    else:
        subprocess.run(["systemctl", "disable", "--now", timer_unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def backup_timer_status():
    timer_unit = SETTINGS.get("backup_timer", {}).get("timer_unit", "server-panel-backup.timer")
    active_res = subprocess.run(["systemctl", "is-active", timer_unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    enabled_res = subprocess.run(["systemctl", "is-enabled", timer_unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    active = (active_res.stdout or active_res.stderr or "unknown").strip()
    enabled = (enabled_res.stdout or enabled_res.stderr or "unknown").strip()
    next_runs = safe_run(["systemctl", "list-timers", timer_unit, "--no-pager"])
    return {"active": active, "enabled": enabled, "next": next_runs}


def update_backup_settings(form):
    settings = load_backup_settings()
    target_type = form.get("target_type", [settings["target_type"]])[0]
    target_path = form.get("target_path", [settings["target_path"]])[0].strip() or str(CFG["backup_dir"])
    rsync_target = form.get("rsync_target", [settings["rsync_target"]])[0].strip()
    scope = form.get("scope", [settings["scope"]])[0]
    schedule = form.get("schedule", [settings["schedule"]])[0]
    custom_calendar = form.get("custom_calendar", [settings["custom_calendar"]])[0].strip()
    schedule_enabled = form.get("schedule_enabled", [""])[0] == "on"
    if target_type not in {"local", "rsync"}:
        raise RuntimeError("неверный тип назначения")
    if scope not in {"critical", "system"}:
        raise RuntimeError("неверный профиль backup")
    if schedule not in {"hourly", "daily", "weekly", "monthly", "custom"}:
        raise RuntimeError("неверное расписание")
    if target_type == "rsync" and not rsync_target:
        raise RuntimeError("rsync назначение не задано")
    settings.update({
        "target_type": target_type,
        "target_path": target_path,
        "rsync_target": rsync_target,
        "scope": scope,
        "schedule_enabled": schedule_enabled,
        "schedule": schedule,
        "custom_calendar": custom_calendar,
    })
    save_backup_settings(settings)
    configure_backup_timer(settings)
    audit_event("backup_settings", f"{target_type} {scope} {backup_on_calendar(settings)} enabled={schedule_enabled}")
    return settings


def parse_handshake_age(text):
    if not text:
        return None
    text = text.strip().lower()
    if text == "never":
        return None
    total = 0
    matched = False
    for value, unit in re.findall(r"(\d+)\s+(second|minute|hour|day)s?", text):
        matched = True
        value = int(value)
        if unit == "second":
            total += value
        elif unit == "minute":
            total += value * 60
        elif unit == "hour":
            total += value * 3600
        elif unit == "day":
            total += value * 86400
    return total if matched else None


def peer_connection_state(peer, connected_after=300):
    handshake = peer.get("latest_handshake", "")
    age = parse_handshake_age(handshake)
    endpoint = (peer.get("endpoint") or "").strip()
    connected = age is not None and age <= connected_after
    if connected:
        status = "подключён"
        status_class = "good"
    else:
        status = "отключён"
        status_class = "bad"
    return {
        "status": status,
        "status_class": status_class,
        "age": age,
        "handshake": handshake or "нет рукопожатия",
        "endpoint": endpoint or "-",
        "last_seen": handshake or "-",
    }


def journal_text(unit, limit=4000):
    try:
        cmd = ["journalctl", "-u", unit, "-b", "--no-pager", "-o", "cat"]
        if limit:
            cmd.extend(["-n", str(limit)])
        return run(cmd)
    except Exception:
        return ""


def recent_journal_names(unit, patterns, since_days=30):
    try:
        text = run(["journalctl", "-u", unit, "-b", "--since", f"{since_days} days ago", "--no-pager", "-o", "cat"])
    except Exception:
        return set()
    names = set()
    for line in text.splitlines():
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                names.add(match.group(1).strip())
                break
    return names


def openvpn_client_states():
    states = {}
    for line in reversed(journal_text("openvpn-server@server.service").splitlines()):
        if not line.strip():
            continue
        name = None
        status = None
        match = re.search(r"\[([^\]]+)\]\s+Peer Connection Initiated\b", line)
        if match:
            name = match.group(1).strip()
            status = "подключён"
        else:
            match = re.search(
                r"^([^/]+)/[^:]+:\d+\s+(CC-EEN exit message received by peer|SIGTERM\[.*\] received, client-instance exiting|Inactivity timeout.*|TLS Error.*|AUTH_FAILED.*|Connection reset.*)",
                line,
                re.I,
            )
            if match:
                name = match.group(1).strip()
                status = "отключён"
        if name and name not in states:
            states[name] = status
    return states


def hysteria_client_states():
    states = {}
    for line in reversed(journal_text("hysteria2.service").splitlines()):
        match = re.search(r"client\s+(connected|disconnected)\s+\{.*\"id\":\s*\"([^\"]+)\"", line)
        if not match:
            continue
        client_id = match.group(2).strip()
        if client_id in states:
            continue
        states[client_id] = "подключён" if match.group(1) == "connected" else "отключён"
    return states


def xray_active_ips():
    try:
        text = run(["ss", "-Htn", "state", "established", "( sport = :8449 )"])
    except Exception:
        return set()
    ips = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            peer = parts[4].strip("[]")
            ip = peer.rsplit(":", 1)[0].strip()
            if ip:
                ips.add(ip)
    return ips


def xray_client_states():
    latest_ip_by_email = {}
    for line in journal_text("xray.service").splitlines():
        match = re.search(r"from\s+([0-9a-fA-F:.]+):\d+\s+accepted\b.*\bemail:\s*(\S+)", line)
        if match:
            latest_ip_by_email[match.group(2).strip()] = match.group(1).strip()
    active_ips = xray_active_ips()
    return {email: ("подключён" if ip in active_ips else "отключён") for email, ip in latest_ip_by_email.items()}


def host_from_hostport(value):
    value = str(value or "").strip()
    if not value:
        return "-"
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    match = re.match(r"^(.*):(\d+)$", value)
    if match:
        return match.group(1)
    return value


def openvpn_client_source_ips():
    mapping = {}
    for line in journal_text("openvpn-server@server.service").splitlines():
        match = re.search(r"\[([^\]]+)\]\s+Peer Connection Initiated with \[AF_INET\]([0-9a-fA-F:.]+):\d+", line)
        if match:
            mapping[match.group(1).strip()] = match.group(2).strip()
    return mapping


def hysteria_client_source_ips():
    mapping = {}
    for line in journal_text("hysteria2.service").splitlines():
        match = re.search(r'client\s+connected\s+\{.*"addr":\s*"([^"]+)".*"id":\s*"([^"]+)"', line)
        if match:
            mapping[match.group(2).strip()] = host_from_hostport(match.group(1))
            continue
        match = re.search(r'client\s+connected\s+\{.*"id":\s*"([^"]+)".*"addr":\s*"([^"]+)"', line)
        if match:
            mapping[match.group(1).strip()] = host_from_hostport(match.group(2))
    return mapping


def xray_client_source_ips():
    mapping = {}
    for line in journal_text("xray.service").splitlines():
        match = re.search(r"from\s+([0-9a-fA-F:.]+):\d+\s+accepted\b.*\bemail:\s*(\S+)", line)
        if match:
            mapping[match.group(2).strip()] = match.group(1).strip()
    return mapping


def duplicate_warning_items(clients, name_field="name", ip_field=None):
    warnings = []
    name_groups = {}
    for client in clients:
        name = str(client.get(name_field, "")).strip()
        if not name:
            continue
        name_groups.setdefault(name.lower(), []).append(name)
    for group in name_groups.values():
        if len(group) > 1:
            warnings.append(f"Дубликат имени: {', '.join(group)}")
    if ip_field:
        ip_groups = {}
        for client in clients:
            ip = str(client.get(ip_field, "")).strip()
            if not ip:
                continue
            ip_groups.setdefault(ip, []).append(str(client.get(name_field, ip)).strip())
        for ip, group in ip_groups.items():
            if len(group) > 1:
                warnings.append(f"Пересечение IP {ip}: {', '.join(group)}")
    return warnings


def wireguard_status_payload():
    try:
        _, peers = parse_wg_show(CFG["wireguard_iface"])
    except Exception:
        peers = []
    clients = load_wireguard_clients()
    peer_by_key = {peer.get("public_key"): peer for peer in peers}
    items = []
    connected = 0
    for client in clients:
        key = client.get("public_key") or client.get("name")
        enabled = client.get("enabled", True)
        peer = peer_by_key.get(client.get("public_key"))
        state = peer_connection_state(peer) if (peer and enabled) else {"status": "отключён", "status_class": "bad"}
        ip = host_from_hostport(peer.get("endpoint") if peer else "-")
        if state.get("status") == "подключён" and enabled:
            connected += 1
        items.append({"id": stable_dom_id("wg", key), "status": state.get("status", "отключён"), "tone": state.get("status_class", "bad") if enabled else "bad", "ip": ip})
    return {"count": connected, "total": len(clients), "clients": items}


def amnezia_status_payload():
    _, peers = client_rows()
    items = []
    connected = 0
    for peer in peers:
        status = peer.get("status", "отключён")
        ip = host_from_hostport(peer.get("endpoint"))
        if status == "подключён":
            connected += 1
        items.append({"id": stable_dom_id("awg", peer.get("public_key") or peer.get("name")), "status": status, "tone": peer.get("status_class", "bad"), "ip": ip})
    return {"count": connected, "total": len(peers), "clients": items}


def openvpn_status_payload():
    clients = load_openvpn_clients()
    states = openvpn_client_states()
    ips = openvpn_client_source_ips()
    ips = openvpn_client_source_ips()
    items = []
    connected = 0
    for client in clients:
        name = client.get("name", "client")
        enabled = client.get("enabled", True)
        status = "подключён" if enabled and states.get(name) == "подключён" else "отключён"
        ip = ips.get(name, "-")
        if status == "подключён":
            connected += 1
        items.append({"id": stable_dom_id("ovpn", name), "status": status, "tone": "good" if status == "подключён" else "bad", "ip": ip})
    return {"count": connected, "total": len(clients), "clients": items}


def hysteria_status_payload():
    clients = load_hysteria_clients()
    states = hysteria_client_states()
    ips = hysteria_client_source_ips()
    items = []
    connected = 0
    for client in clients:
        username = client.get("username", "client")
        enabled = client.get("enabled", True)
        status = "подключён" if enabled and states.get(username) == "подключён" else "отключён"
        ip = ips.get(username, "-")
        if status == "подключён":
            connected += 1
        items.append({"id": stable_dom_id("hysteria", username), "status": status, "tone": "good" if status == "подключён" else "bad", "ip": ip})
    return {"count": connected, "total": len(clients), "clients": items}


def vless_status_payload():
    clients = load_vless_clients()
    states = xray_client_states()
    ips = xray_client_source_ips()
    items = []
    connected = 0
    for client in clients:
        name = client.get("name", client.get("uuid", "client"))
        enabled = client.get("enabled", True)
        status = "подключён" if enabled and states.get(name) == "подключён" else "отключён"
        ip = ips.get(name, "-")
        if status == "подключён":
            connected += 1
        items.append({"id": stable_dom_id("vless", client.get("uuid") or name), "status": status, "tone": "good" if status == "подключён" else "bad", "ip": ip})
    return {"count": connected, "total": len(clients), "clients": items}


def openvpn_revoke_only(name):
    easy, base = openvpn_client_keys(name)
    issued = Path(f"/etc/openvpn/server/pki/issued/{base}.crt")
    private = Path(f"/etc/openvpn/server/pki/private/{base}.key")
    req = Path(f"/etc/openvpn/server/pki/reqs/{base}.req")
    if issued.exists() or private.exists() or req.exists():
        try:
            run(["bash", "-lc", f"cd {shlex.quote(str(easy))} && EASYRSA_BATCH=1 ./easyrsa revoke {shlex.quote(base)} && EASYRSA_BATCH=1 ./easyrsa gen-crl && cp -a pki/crl.pem /etc/openvpn/server/pki/crl.pem && cp -a pki /etc/openvpn/server/"])
        except Exception:
            try:
                issued.unlink(missing_ok=True)
                private.unlink(missing_ok=True)
                req.unlink(missing_ok=True)
            except Exception:
                pass


def client_rows():
    server_pub, peers = parse_awg_show()
    state = load_state()
    names = {c["public_key"]: c["name"] for c in state.get("clients", [])}
    managed = set(names.keys())
    rows = []
    for peer in peers:
        peer["name"] = names.get(peer["public_key"], peer["public_key"][:12])
        peer["managed"] = peer["public_key"] in managed
        peer.update(peer_connection_state(peer))
        rows.append(peer)
    return server_pub, rows


def build_shell(page_title, active_page, body_html, message="", error=""):
    notice_html = f"<div class='notice'>{html.escape(message)}</div>" if message else ""
    error_html = f"<div class='error'>{html.escape(error)}</div>" if error else ""
    user = current_request_user() or primary_panel_user()
    nav_by_key = {item[0]: item for item in NAV_ITEMS}
    sidebar_parts = []
    mobile_parts = []
    for group, keys in NAV_GROUPS:
        group_keys = [key for key in keys if nav_item_visible(key)]
        if not group_keys:
            continue
        sidebar_parts.append(f"<div class='nav-group-title'>{html.escape(group)}</div>")
        mobile_parts.append(f"<div class='drawer-group-title'>{html.escape(group)}</div>")
        for key in group_keys:
            _, href, icon_name, label = nav_by_key[key]
            sidebar_parts.append(f"<a class='navicon {'active' if active_page == key else ''}' href='{href}' title='{html.escape(label)}'>{icon(icon_name)}<span>{html.escape(label)}</span></a>")
            mobile_parts.append(f"<a class='drawer-link {'active' if active_page == key else ''}' href='{href}' onclick='toggleDrawer(false)'><span class='ico'>{icon(icon_name)}</span><span>{html.escape(label)}</span></a>")
    sidebar_nav = "".join(sidebar_parts)
    mobile_nav = "".join(mobile_parts)
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{html.escape(page_title)}</title>
<style>{dashboard_css()}</style></head><body>
<div class='drawer-backdrop' onclick='toggleDrawer(false)'></div>
<aside class='mobile-drawer' aria-label='Мобильное меню'>
    <div class='drawer-panel'>
    <div class='drawer-header'>
      <div class='drawer-title'><div class='brand'>{icon('dashboard')}</div><div>Панель</div></div>
      <button class='menu-btn' type='button' onclick='toggleDrawer(false)' aria-label='Закрыть меню'>{icon('menu')}</button>
    </div>
    <nav class='drawer-links'>
      {mobile_nav}
    </nav>
    <div class='drawer-footer'><div class='badge'>{html.escape(user)}</div></div>
  </div>
</aside>
<div class='app'>
  <aside class='sidebar'>
    <div class='side-brand'><div class='brand'>{icon('dashboard')}</div><div><strong>Server</strong><span>control center</span></div></div>
    {sidebar_nav}
  </aside>
  <div class='content'>
    <div class='topbar'>
      <div class='topbar-row'>
        <button class='menu-btn' type='button' onclick='toggleDrawer(true)' aria-label='Открыть меню'>{icon('menu')}</button>
        <div class='title'>{html.escape(page_title)}</div>
        <div class='top-actions'><span class='avatar'>{html.escape((user[:1] or 'A').upper())}</span><span class='user'>{html.escape(user)}</span><a class='ghost logout-top' href='/logout'>{icon('logout')} Выход</a></div>
      </div>
    </div>
    <div class='page'>
      {notice_html}
      {error_html}
      {body_html}
    </div>
  </div>
</div>
<div class='qr-modal-backdrop' id='qr-backdrop' hidden></div>
<div class='qr-modal' id='qr-modal' hidden>
  <div class='qr-modal-card'>
    <div class='section-title'><h2><span class='ico'>{icon('qr')}</span><span id='qr-modal-title'>QR</span></h2><button class='ghost' type='button' id='qr-modal-close'>Закрыть</button></div>
    <div class='qr-modal-body'><img id='qr-modal-img' alt='QR-код' /></div>
  </div>
</div>
<script>
function toggleDrawer(open) {{
  document.body.classList.toggle('drawer-open', open);
}}
const qrModal = document.getElementById('qr-modal');
const qrBackdrop = document.getElementById('qr-backdrop');
const qrModalImg = document.getElementById('qr-modal-img');
const qrModalTitle = document.getElementById('qr-modal-title');
const qrModalClose = document.getElementById('qr-modal-close');
function closeQrModal() {{
  qrModal.hidden = true;
  qrBackdrop.hidden = true;
  qrModalImg.src = '';
}}
function openQrImageModal(src, title) {{
  qrModalTitle.textContent = title || 'QR';
  qrModalImg.src = src;
  qrBackdrop.hidden = false;
  qrModal.hidden = false;
}}
function openQrModal(href, title) {{
  const url = new URL(href, window.location.origin);
  const svgPath = url.pathname.replace('/qr/', '/qrsvg/');
  openQrImageModal(svgPath, title);
}}
async function copyText(value) {{
  if (!value) return;
  try {{
    await navigator.clipboard.writeText(value);
  }} catch (e) {{
    const input = document.createElement('textarea');
    input.value = value;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    input.remove();
  }}
}}
document.addEventListener('click', function(e) {{
  const qr = e.target.closest('a.qr-link');
  if (qr) {{
    e.preventDefault();
    openQrModal(qr.getAttribute('href'), qr.dataset.profile || 'QR');
    return;
  }}
  const qrImg = e.target.closest('[data-qr-img]');
  if (qrImg) {{
    e.preventDefault();
    openQrImageModal(qrImg.getAttribute('data-qr-img'), qrImg.getAttribute('data-qr-title') || 'QR');
    return;
  }}
  const copyBtn = e.target.closest('[data-copy-text]');
  if (copyBtn) {{
    e.preventDefault();
    copyText(copyBtn.getAttribute('data-copy-text') || '');
    return;
  }}
  if (e.target === qrBackdrop) closeQrModal();
}});
qrBackdrop.addEventListener('click', closeQrModal);
qrModalClose.addEventListener('click', closeQrModal);
document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') toggleDrawer(false);
  if (e.key === 'Escape' && !qrModal.hidden) closeQrModal();
}});
function updateVpnStatus(root, payload) {{
  if (!root || !payload) return;
  const count = root.querySelector('[data-vpn-count]');
  if (count) count.textContent = payload.count + '/' + payload.total + ' подключены';
  (payload.clients || []).forEach(function(item) {{
    const pill = root.querySelector('[data-vpn-status-id="' + item.id + '"]');
    if (!pill) return;
    pill.className = 'status-pill' + (item.tone ? ' ' + item.tone : '');
    const text = pill.querySelector('.status-text');
    if (text) text.textContent = item.status;
    if (item.ip !== undefined) {{
      const ip = root.querySelector('[data-vpn-ip-id="' + item.id + '"]');
      if (ip) ip.textContent = item.ip || '-';
    }}
  }});
}}
function updateMtprotoStatus(root, payload) {{
  if (!root || !payload) return;
  const badge = root.querySelector('[data-mtproto-service]');
  if (badge) badge.textContent = payload.service || 'unknown';
  const box = root.querySelector('[data-mtproto-error-box]');
  const text = root.querySelector('[data-mtproto-error-text]');
  if (box && text) {{
    if (payload.has_error && payload.error) {{
      text.textContent = payload.error;
      box.hidden = false;
    }} else {{
      text.textContent = '';
      box.hidden = true;
    }}
  }}
}}
async function refreshVpnStatuses() {{
  const roots = document.querySelectorAll('[data-vpn-tab]');
  for (const root of roots) {{
    const tab = root.getAttribute('data-vpn-tab');
    if (!tab) continue;
    try {{
      const res = await fetch('/api/vpn-status?tab=' + encodeURIComponent(tab), {{ cache: 'no-store' }});
      if (!res.ok) continue;
      updateVpnStatus(root, await res.json());
    }} catch (e) {{}}
  }}
}}
if (document.querySelector('[data-vpn-tab]')) {{
  refreshVpnStatuses();
  setInterval(refreshVpnStatuses, 5000);
}}
async function refreshMtprotoStatus() {{
  const root = document.querySelector('[data-mtproto-root]');
  if (!root) return;
  try {{
    const res = await fetch('/api/mtproto-status', {{ cache: 'no-store' }});
    if (!res.ok) return;
    updateMtprotoStatus(root, await res.json());
  }} catch (e) {{}}
}}
if (document.querySelector('[data-mtproto-root]')) {{
  refreshMtprotoStatus();
  setInterval(refreshMtprotoStatus, 5000);
}}
</script>
</body></html>"""


def summary_cards(snapshot, metrics, services, peers, managed_count, legacy_count):
    status_map = {"active": "активен", "inactive": "неактивен", "failed": "ошибка", "unknown": "неизвестно"}
    service_map = {s["name"]: s for s in services}
    awg = service_map.get("awg", {"active": "unknown", "enabled": "unknown", "unit": ""})
    wireguard = service_map.get("wireguard", {"active": "unknown", "enabled": "unknown", "unit": ""})
    return f"""
    <section class='ops-hero summary-only'>
      <div class='ops-headline'>
        <span class='ops-eyebrow'>server control center</span>
        <h1>Краткая сводка</h1>
        <div class='ops-health summary-cards'>
          <div class='ops-health-row'><span>AmneziaWG</span><strong class='{'good' if awg['active'] == 'active' else 'bad'}'>{html.escape(status_map.get(awg['active'], awg['active']))}</strong></div>
          <div class='ops-health-row'><span>WireGuard</span><strong class='{'good' if wireguard['active'] == 'active' else 'bad'}'>{html.escape(status_map.get(wireguard['active'], wireguard['active']))}</strong></div>
          <div class='ops-health-row'><span>SSTP</span><strong class='{'good' if service_map.get('softether', {'active': 'unknown'})['active'] == 'active' else 'bad'}'>{html.escape(status_map.get(service_map.get('softether', {'active': 'unknown'})['active'], service_map.get('softether', {'active': 'unknown'})['active']))}</strong></div>
          <div class='ops-health-row'><span>Endpoint</span><strong>{html.escape(public_endpoint(CFG['endpoint'].split(':', 1)[1] if ':' in CFG['endpoint'] else '443'))}</strong></div>
        </div>
      </div>
    </section>
    """


def build_home():
    snapshot = system_snapshot()
    metrics = collect_metrics()
    services = [service_status(k) for k in ["awg", "wireguard", "openvpn", "softether", "panel", "vpn-iptables", "openvpn-iptables"] if k in SERVICE_MAP]
    _, peers = client_rows()
    managed_count = sum(1 for p in peers if p.get("managed"))
    legacy_count = len(peers) - managed_count
    return build_shell("Панель", "home", summary_cards(snapshot, metrics, services, peers, managed_count, legacy_count))


def build_system_page(message="", error=""):
    snapshot = system_snapshot()
    metrics = collect_metrics()
    interfaces = []
    for line in snapshot["interfaces"].splitlines():
        parts = line.split()
        if len(parts) >= 3:
            interfaces.append((parts[0], parts[1], parts[2]))
    interface_cards = ''.join(
        f"<div class='sys-card'><div class='label'>{html.escape(i)}</div><div class='value'>{html.escape(s)}</div><div class='sub'>{html.escape(a)}</div></div>"
        for i, s, a in interfaces
    ) or "<div class='sys-card'><div class='label'>Интерфейсы</div><div class='value'>-</div><div class='sub'>нет данных</div></div>"
    cpu_pct = min(metrics['cpu_pct'], 999.0)
    cpu_fill = f"{min(cpu_pct, 100):.1f}%"
    cpu_color = "#4c7dff" if cpu_pct < 50 else "#ffb84d" if cpu_pct < 80 else "#ff647c"
    net_mbps = (metrics['rx_rate'] + metrics['tx_rate']) * 8 / 1000000
    net_cap_mbps = float(SETTINGS.get("network", {}).get("speed_cap_mbps", 200) or 200)
    net_pct = min(net_mbps / net_cap_mbps * 100, 100.0)
    net_color = "#39d8c4" if net_pct < 50 else "#ffb84d" if net_pct < 80 else "#ff647c"
    net_display = f"{net_mbps:.1f} Mbps"
    mem_pct = float(metrics['mem_pct'])
    mem_color = "#4c7dff" if mem_pct < 50 else "#ffb84d" if mem_pct < 80 else "#ff647c"
    disk_pct_num = int(re.sub(r"[^0-9]", "", str(metrics['disk_pct'])) or "0")
    disk_color = "#4c7dff" if disk_pct_num < 50 else "#ffb84d" if disk_pct_num < 80 else "#ff647c"
    disk_used_gb = format_bytes(metrics['disk_used'])
    disk_total_gb = format_bytes(metrics['disk_total'])
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('system')}</span>Система</h2><span class='badge'>live</span></div>
      <div class='metric-grid'>
        <div class='metric-card' style='--metric-color:{cpu_color}'><div class='metric-head'><div class='metric-title'>CPU</div><span class='badge' id='sys-iface'>{html.escape(metrics['iface'])}</span></div><div class='metric-ring-wrap'><div class='metric-ring' id='cpu-ring' style='--metric-fill:{cpu_pct:.1f}%;'></div><div class='metric-ring-value'><strong id='cpu-value' style='color:{cpu_color}'>{cpu_pct:.0f}%</strong></div></div><div class='metric-sub' id='cpu-sub'>load {metrics['load1']:.2f} · cores {metrics['cpu_count']}</div></div>
        <div class='metric-card' style='--metric-color:{mem_color}'><div class='metric-head'><div class='metric-title'>Память</div><span class='badge'>live</span></div><div class='metric-ring-wrap'><div class='metric-ring' id='mem-ring' style='--metric-fill:{mem_pct:.1f}%; --metric-color:{mem_color};'></div><div class='metric-ring-value'><strong id='mem-value' style='color:{mem_color}'>{mem_pct:.0f}%</strong></div></div><div class='metric-sub' id='mem-sub'>{format_bytes(metrics['mem_used'])} / {format_bytes(metrics['mem_total'])}</div></div>
        <div class='metric-card' style='--metric-color:{disk_color}'><div class='metric-head'><div class='metric-title'>Диск</div><span class='badge'>live</span></div><div class='metric-ring-wrap'><div class='metric-ring' id='disk-ring' style='--metric-fill:{disk_pct_num:.1f}%; --metric-color:{disk_color};'></div><div class='metric-ring-value'><strong id='disk-value' style='color:{disk_color}'>{metrics['disk_pct']}</strong></div></div><div class='metric-sub' id='disk-sub'>{disk_used_gb} / {disk_total_gb}</div></div>
        <div class='metric-card' style='--metric-color:{net_color}'><div class='metric-head'><div class='metric-title'>Сеть</div><span class='badge'>{net_cap_mbps:.0f} Mbps</span></div><div class='metric-ring-wrap'><div class='metric-ring' id='net-ring' style='--metric-fill:{net_pct:.1f}%; --metric-color:{net_color};'></div><div class='metric-ring-value'><strong id='net-value' style='color:{net_color}'>{net_display}</strong></div></div><div class='metric-sub' id='net-sub'>RX {format_bytes(metrics['rx_rate'])}/с · TX {format_bytes(metrics['tx_rate'])}/с</div></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('server')}</span>Аптайм</h2><span class='badge'>{html.escape(metrics['iface'])}</span></div>
      <div class='kv-grid' id='uptime-grid'>
        <div class='kv'><span>Хост</span><strong id='host-value'>{html.escape(snapshot['hostname'])}</strong></div>
        <div class='kv'><span>Время работы</span><strong id='uptime-value'>{html.escape(snapshot['uptime'])}</strong></div>
        <div class='kv'><span>Load 1/5/15</span><strong id='load-value'>{metrics['load1']:.2f} / {metrics['load5']:.2f} / {metrics['load15']:.2f}</strong></div>
        <div class='kv'><span>CPU cores</span><strong id='cpu-count'>{metrics['cpu_count']}</strong></div>
      </div>
    </div>
    <script>
    const cpuRing = document.getElementById('cpu-ring');
    const memRing = document.getElementById('mem-ring');
    const diskRing = document.getElementById('disk-ring');
    const netRing = document.getElementById('net-ring');
    const cpuValue = document.getElementById('cpu-value');
    const cpuSub = document.getElementById('cpu-sub');
    const memValue = document.getElementById('mem-value');
    const memSub = document.getElementById('mem-sub');
    const diskValue = document.getElementById('disk-value');
    const diskSub = document.getElementById('disk-sub');
    const netValue = document.getElementById('net-value');
    const netSub = document.getElementById('net-sub');
    const uptimeValue = document.getElementById('uptime-value');
    const hostValue = document.getElementById('host-value');
    const loadValue = document.getElementById('load-value');
    const cpuCount = document.getElementById('cpu-count');
    const sysIface = document.getElementById('sys-iface');
    async function refreshSystem() {{
      try {{
        const res = await fetch('/api/system', {{ cache: 'no-store' }});
        if (!res.ok) return;
        const data = await res.json();
        const m = data.metrics;
        const s = data.snapshot;
        const cpu = Math.min(m.cpu_pct, 100);
        const cpuColor = cpu < 50 ? '#4c7dff' : cpu < 80 ? '#ffb84d' : '#ff647c';
        cpuRing.style.setProperty('--metric-fill', cpu.toFixed(1) + '%');
        cpuRing.style.setProperty('--metric-color', cpuColor);
        cpuValue.textContent = Math.round(cpu) + '%';
        cpuValue.style.color = cpuColor;
        cpuSub.textContent = 'load ' + m.load1.toFixed(2) + ' · cores ' + m.cpu_count;
        memValue.textContent = Math.round(m.mem_pct) + '%';
        memSub.textContent = formatBytes(m.mem_used) + ' / ' + formatBytes(m.mem_total);
        memRing.style.setProperty('--metric-fill', Math.min(m.mem_pct, 100).toFixed(1) + '%');
        memRing.style.setProperty('--metric-color', m.mem_pct < 50 ? '#4c7dff' : m.mem_pct < 80 ? '#ffb84d' : '#ff647c');
        diskValue.textContent = m.disk_pct;
        diskSub.textContent = formatBytes(m.disk_used) + ' / ' + formatBytes(m.disk_total);
        const diskVal = parseFloat(String(m.disk_pct).replace('%', '')) || 0;
        diskRing.style.setProperty('--metric-fill', Math.min(diskVal, 100).toFixed(1) + '%');
        diskRing.style.setProperty('--metric-color', diskVal < 50 ? '#4c7dff' : diskVal < 80 ? '#ffb84d' : '#ff647c');
        const netMbps = (m.rx_rate + m.tx_rate) * 8 / 1000000;
        const netCapMbps = {net_cap_mbps:.6f};
        const netPct = Math.min(netMbps / netCapMbps * 100, 100);
        const netColor = netPct < 50 ? '#39d8c4' : netPct < 80 ? '#ffb84d' : '#ff647c';
        netValue.textContent = netMbps.toFixed(1) + ' Mbps';
        netSub.textContent = 'RX ' + formatBytes(m.rx_rate) + '/с · TX ' + formatBytes(m.tx_rate) + '/с · ' + Math.round(netCapMbps) + ' Mbps cap';
        netRing.style.setProperty('--metric-fill', netPct.toFixed(1) + '%');
        netRing.style.setProperty('--metric-color', netColor);
        uptimeValue.textContent = s.uptime;
        hostValue.textContent = s.hostname;
        loadValue.textContent = m.load1.toFixed(2) + ' / ' + m.load5.toFixed(2) + ' / ' + m.load15.toFixed(2);
        cpuCount.textContent = m.cpu_count;
        sysIface.textContent = m.iface;
      }} catch (e) {{}}
    }}
    function formatBytes(bytes) {{
      const n = Number(bytes) || 0;
      const units = ['B','KB','MB','GB','TB'];
      let value = n;
      let idx = 0;
      while (value >= 1024 && idx < units.length - 1) {{ value /= 1024; idx++; }}
      return value.toFixed(value >= 10 || idx === 0 ? 0 : 1) + ' ' + units[idx];
    }}
    refreshSystem();
    setInterval(refreshSystem, 3000);
    </script>
    """
    return build_shell("Система", "system", body, message, error)


def build_clients_page(message="", error="", active_page="amnezia", page_title="Amnezia", path="/amnezia"):
    _, peers = client_rows()
    managed_count = sum(1 for p in peers if p.get("managed"))
    connected = sum(1 for p in peers if p.get("status") == "подключён")
    cards = []
    for peer in peers:
        name = html.escape(peer.get("name") or peer["public_key"][:12])
        pub = html.escape(peer["public_key"])
        ip = html.escape((peer.get("allowed_ips") or ["-"])[0])
        transfer = html.escape(peer.get("transfer", "-"))
        download_name = quote((peer.get("name") or peer["public_key"]) + ".conf", safe="")
        managed = peer.get("managed", False)
        status_class = "good" if peer.get("status") == "подключён" else "bad"
        status_text = html.escape(peer.get("status", "отключён"))
        status_id = stable_dom_id("awg", peer.get("public_key") or peer.get("name"))
        cards.append(f"""
        <div class='client-card'>
          <div class='head'>
            <div>
              <div class='name'>{name}</div>
              <div class='status-line' style='margin-top:8px'>
                <span class='status-pill {status_class}' data-vpn-status-id='{status_id}'><span class='status-dot'></span><span class='status-text'>{status_text}</span></span>
                {'<span class=\'status-pill\'><span class=\'status-dot\'></span>управляемый</span>' if managed else '<span class=\'status-pill\'><span class=\'status-dot\'></span>legacy</span>'}
              </div>
            </div>
            <span class='badge'><code>{ip}</code></span>
          </div>
          <div class='meta'>
            <div class='row'><span>IP подключения</span><strong data-vpn-ip-id='{status_id}'>{html.escape(host_from_hostport(peer.get('endpoint', '-')))}</strong></div>
            <div class='row'><span>Handshake</span><strong>{html.escape(peer.get('last_seen', '-'))}</strong></div>
            <div class='row'><span>Трафик</span><strong>{transfer}</strong></div>
            <div class='row'><span>Ключ</span><strong><code>{pub}</code></strong></div>
          </div>
          <div class='actions'>
            {f"<a class='ghost' href='/download/{download_name}'>Скачать</a>{qr_link(peer.get('name', peer['public_key']) + '.conf')}" if managed else ''}
            <form method='post' action='/delete'><input type='hidden' name='return_to' value='{html.escape(path)}' /><input type='hidden' name='public_key' value='{pub}' /><button class='danger' type='submit'>Удалить</button></form>
          </div>
        </div>
        """)
    body = f"""
    <div class='section vpn-page' data-vpn-tab='amnezia'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>AmneziaWG</h2><span class='badge' data-vpn-count>{connected}/{len(peers)} подключены</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-left' style='min-height:220px'><div class='hex'></div></div>
        <div class='hero-right'>
          <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Добавить клиента</h2><span class='badge'>{managed_count} управляемых</span></div>
          <form method='post' action='/add'><div class='grid2'><input name='name' placeholder='Имя клиента' autocomplete='off' /><label class='mini' style='display:flex;align-items:center;gap:10px;margin:0'><input type='checkbox' name='iphone' value='1' /> iPhone</label><input type='hidden' name='return_to' value='{html.escape(path)}' /><button type='submit' class='pillbtn'>Добавить</button></div></form>
          <p class='mini'>Карта клиента показывает статус подключения, IP и последнее рукопожатие.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Список клиентов</h2><span class='badge'>{len(peers)} всего</span></div>
      <div class='client-grid'>{''.join(cards) or '<div class="sys-card"><div class="label">Клиенты</div><div class="value">Нет</div><div class="sub">Пока не добавлены</div></div>'}</div>
    </div>
    """
    return build_shell(page_title, active_page, body, message, error)


def build_amnezia_page(message="", error=""):
    return build_clients_page(message, error, active_page="amnezia", page_title="Amnezia", path="/amnezia")


def build_wireguard_page(message="", error=""):
    ensure_wireguard_server_config()
    try:
        _, peers = parse_wg_show(CFG["wireguard_iface"])
    except Exception:
        peers = []
    clients = load_wireguard_clients()
    name_groups = {}
    ip_groups = {}
    for client in clients:
        name_groups.setdefault(str(client.get("name") or "").strip().lower(), []).append(client)
        ip_groups.setdefault(str(client.get("ip") or "").strip(), []).append(client)
    peer_by_key = {peer.get("public_key"): peer for peer in peers}
    managed_count = len(clients)
    connected = 0
    warnings = []
    cards = []
    for client in clients:
        peer = peer_by_key.get(client.get("public_key"))
        enabled = client.get("enabled", True)
        state = peer_connection_state(peer) if (peer and enabled) else {"status": "отключён", "status_class": "bad"}
        if state.get("status") == "подключён" and enabled:
            connected += 1
        client_alerts = []
        if len(name_groups.get(str(client.get("name") or "").strip().lower(), [])) > 1:
            client_alerts.append("дубль имени")
        if client.get("ip") and len(ip_groups.get(str(client.get("ip") or "").strip(), [])) > 1:
            client_alerts.append("дубль IP")
        if enabled and (state.get("status") != "подключён") and (state.get("age") is None or state.get("age") > 30 * 86400):
            client_alerts.append("старый")
        warnings.extend([f"WireGuard: {client['name']} - {item}" for item in client_alerts])
        pills = [client_pill(state.get("status", "отключён"), state.get("status_class", "bad"), attrs=f" data-vpn-status-id='{stable_dom_id('wg', client.get('public_key') or client.get('name'))}'")] 
        if not enabled:
            pills.append(client_pill("выключен", "bad"))
        else:
            pills.append(client_pill("активный профиль", "good"))
        if client.get("iphone"):
            pills.append(client_pill("iPhone"))
        if client_alerts:
            pills.append(client_pill("!", "bad"))
        rows = [
            client_row("IP подключения", f"<code data-vpn-ip-id='{stable_dom_id('wg', client.get('public_key') or client.get('name'))}'>{html.escape(host_from_hostport(peer.get('endpoint') if peer else '-'))}</code>"),
            client_row("IP", f"<code>{html.escape(client.get('ip', '-'))}</code>"),
            client_row("PublicKey", f"<code>{html.escape(client.get('public_key', '-'))}</code>"),
        ]
        actions = [toggle_form('/wireguard-toggle', '/wireguard', 'public_key', client['public_key'], 'Включить', 'pillbtn') if not enabled else toggle_form('/wireguard-toggle', '/wireguard', 'public_key', client['public_key'], 'Отключить', 'danger'), delete_form('/wireguard-delete', '/wireguard', 'public_key', client['public_key'])]
        if enabled:
            actions.append(f"<a class='ghost' href='/download/{quote(client['name'] + '.conf', safe='')}'>Скачать</a>{qr_link(client['name'] + '.conf')}")
        cards.append(client_card_html(client["name"], client["public_key"][:12], pills, rows, "CONFIG", wireguard_client_uri(client), ''.join(actions), "Стандартный WireGuard профиль, отдельный от AmneziaWG."))
    body = f"""
    <div class='section vpn-page' data-vpn-tab='wireguard'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>WireGuard</h2><span class='badge' data-vpn-count>{connected}/{len(clients)} подключены</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-left' style='min-height:220px'><div class='hex'></div></div>
        <div class='hero-right'>
          <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Добавить клиента</h2><span class='badge'>{managed_count} управляемых</span></div>
          {client_add_form('/wireguard-add', '/wireguard', 'Добавить клиент')}
          <p class='mini'>Отдельный backend на `wg0`, не смешан с AmneziaWG.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Список клиентов</h2><span class='badge'>{len(clients)} шт.</span></div>
      <div class='client-grid'>{''.join(cards) or '<div class="sys-card"><div class="label">Клиенты</div><div class="value">Нет</div><div class="sub">Пока не добавлены</div></div>'}</div>
    </div>
    {warning_box_html(warnings)}
    <div class='section' style='margin-top:16px'><div class='actions'><form method='post' action='/service'><input type='hidden' name='return_to' value='/wireguard' /><input type='hidden' name='name' value='wireguard' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить</button></form><a class='ghost' href='/services'>Все сервисы</a></div></div>
    """
    return build_shell("WireGuard", "wireguard", body, message, error)


def read_text_safe(path, default=""):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return default


def read_cert_pem(path):
    text = read_text_safe(path)
    if not text:
        return ""
    if "-----BEGIN CERTIFICATE-----" in text:
        match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
        if match:
            pem = match.group(0)
            return pem if pem.endswith("\n") else pem + "\n"
    try:
        pem = run(["openssl", "x509", "-in", str(path), "-outform", "PEM"])
        return pem if pem.endswith("\n") else pem + "\n"
    except Exception:
        return ""


def client_row(label, value_html):
    return f"<div class='row'><span>{html.escape(label)}</span><strong>{value_html}</strong></div>"


def profile_action_links(name):
    qname = quote(f"{name}.conf", safe="")
    return f"<a class='ghost' href='/download/{qname}'>Скачать</a>{qr_link(f'{name}.conf')}"


def client_add_form(action, return_to, button_text, placeholder="Имя клиента", checkbox_label="iPhone"):
    return f"""
    <form method='post' action='{html.escape(action)}'>
      <input type='hidden' name='return_to' value='{html.escape(return_to)}' />
      <div class='grid2'>
        <input name='name' placeholder='{html.escape(placeholder)}' autocomplete='off' />
        <label class='mini' style='display:flex;align-items:center;gap:10px;justify-self:end;margin:0'><input type='checkbox' name='iphone' value='1' /> {html.escape(checkbox_label)}</label>
      </div>
      <div class='actions' style='margin-top:12px'><button type='submit' class='pillbtn'>{html.escape(button_text)}</button></div>
    </form>
    """


def delete_form(action, return_to, field_name, field_value, button_text="Удалить"):
    return f"""
    <form method='post' action='{html.escape(action)}'>
      <input type='hidden' name='return_to' value='{html.escape(return_to)}' />
      <input type='hidden' name='{html.escape(field_name)}' value='{html.escape(field_value)}' />
      <button type='submit' class='danger'>{html.escape(button_text)}</button>
    </form>
    """


def qr_link(profile_name, label="QR"):
    qname = quote(profile_name, safe="")
    return f"<a class='ghost qr-link' href='/qr/{qname}' data-profile='{html.escape(profile_name)}'>{html.escape(label)}</a>"


def openvpn_profile_summary(name):
    host, port = openvpn_server_host_port()
    return f"client · proto udp · remote {host} {port} · tls-crypt · {name}.ovpn"


def client_card_html(name, top_badge, pills, rows, profile_label, profile_value, actions, note=""):
    badge_html = f"<span class='badge'><code>{html.escape(top_badge)}</code></span>" if top_badge else ""
    pills_html = ''.join(pills)
    rows_html = ''.join(rows)
    profile_html = f"<div class='profile'><span class='label'>{html.escape(profile_label)}</span><code>{html.escape(profile_value)}</code></div>" if profile_value else ""
    note_html = f"<p class='mini' style='margin-top:12px'>{html.escape(note)}</p>" if note else ""
    return f"""
    <div class='client-card'>
      <div class='head'>
        <div>
          <div class='name'>{html.escape(name)}</div>
          <div class='status-line' style='margin-top:8px'>{pills_html}</div>
        </div>
        {badge_html}
      </div>
      <div class='meta'>{rows_html}{profile_html}</div>
      <div class='actions'>{actions}</div>
      {note_html}
    </div>
    """


def sockets_for_port(port):
    return [line for line in system_snapshot()["sockets"].splitlines()[1:] if f":{port} " in line]


def build_openvpn_page(message="", error=""):
    svc = service_status("openvpn")
    sockets = sockets_for_port("1194")
    conf_text = read_text_safe("/etc/openvpn/server/server.conf")
    pki_state = "есть" if Path("/etc/openvpn/server/pki/issued/server.crt").exists() else "нет"
    clients = load_openvpn_clients()
    states = openvpn_client_states()
    ips = openvpn_client_source_ips()
    recent = recent_journal_names("openvpn-server@server.service", [r"\[([^\]]+)\]\s+Peer Connection Initiated\b", r"^([^/]+)/[^:]+:"])
    name_groups = {}
    for client in clients:
        name_groups.setdefault(str(client.get("name") or "").strip().lower(), []).append(client)
    connected = sum(1 for client in clients if client.get("enabled", True) and states.get(client.get("name")) == "подключён")
    warnings = []
    cards = []
    for client in clients:
        name = client.get("name", "client")
        enabled = client.get("enabled", True)
        status = states.get(name, "отключён") if enabled else "отключён"
        client_alerts = []
        if len(name_groups.get(str(name).strip().lower(), [])) > 1:
            client_alerts.append("дубль имени")
        if not enabled:
            client_alerts.append("выключен")
        elif status != "подключён" and name not in recent:
            client_alerts.append("старый")
        warnings.extend([f"OpenVPN: {name} - {item}" for item in client_alerts if item != "выключен"])
        pills = [client_pill(status, "good" if status == "подключён" else "bad", attrs=f" data-vpn-status-id='{stable_dom_id('ovpn', name)}'")]
        pills.append(client_pill("выключен" if not enabled else "активный профиль", "bad" if not enabled else "good"))
        if client.get("iphone"):
            pills.append(client_pill("iPhone"))
        if client_alerts:
            pills.append(client_pill("!", "bad"))
        host, port = openvpn_server_host_port()
        rows = [
            client_row("IP подключения", f"<code data-vpn-ip-id='{stable_dom_id('ovpn', name)}'>{html.escape(ips.get(name, '-'))}</code>"),
            client_row("Формат", "<code>ovpn</code>"),
            client_row("Файл", f"<code>{html.escape(name)}.ovpn</code>"),
        ]
        actions = toggle_form('/openvpn-toggle', '/openvpn', 'name', name, 'Включить', 'pillbtn') if not enabled else toggle_form('/openvpn-toggle', '/openvpn', 'name', name, 'Отключить', 'danger')
        actions += delete_form('/openvpn-delete', '/openvpn', 'name', name)
        if enabled:
            actions += f"<a class='ghost' href='/download/{quote(name + '.ovpn', safe='')}'>Скачать</a>{qr_link(name + '.ovpn')}"
        cards.append(client_card_html(name, name, pills, rows, "CONF", openvpn_profile_summary(name), actions, "Полный профиль можно скачать или открыть по QR."))
    body = f"""
    <div class='section vpn-page' data-vpn-tab='openvpn'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>OpenVPN</h2><span class='badge' data-vpn-count>{connected}/{len(clients)} подключены</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-left' style='min-height:220px'><div class='hex'></div></div>
        <div class='hero-right'>
          <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Добавить клиента</h2><span class='badge'>{len(clients)} профилей</span></div>
          {client_add_form('/openvpn-add', '/openvpn', 'Добавить клиент')}
          <p class='mini'>Генерируется полный `.ovpn` с сертификатами и ключами.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Список клиентов</h2><span class='badge'>{len(clients)} шт.</span></div>
      <div class='client-grid'>{''.join(cards) or '<div class="sys-card"><div class="label">Клиенты</div><div class="value">Нет</div><div class="sub">Пока не добавлены</div></div>'}</div>
    </div>
    {warning_box_html(warnings)}
    <div class='section' style='margin-top:16px'><div class='actions'><form method='post' action='/service'><input type='hidden' name='return_to' value='/openvpn' /><input type='hidden' name='name' value='openvpn' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить</button></form><a class='ghost' href='/services'>Все сервисы</a></div></div>
    """
    return build_shell("OpenVPN", "openvpn", body, message, error)


def build_hysteria_page(message="", error=""):
    svc = service_status("hysteria2")
    sockets = sockets_for_port("8448")
    conf_text = read_text_safe("/etc/hysteria/config.yaml")
    clients = load_hysteria_clients()
    states = hysteria_client_states()
    ips = hysteria_client_source_ips()
    recent = recent_journal_names("hysteria2.service", [r"client\s+(?:connected|disconnected)\s+\{.*\"id\":\s*\"([^\"]+)\""])
    name_groups = {}
    for client in clients:
        name_groups.setdefault(str(client.get("username") or "").strip().lower(), []).append(client)
    connected = sum(1 for client in clients if client.get("enabled", True) and states.get(client.get("username")) == "подключён")
    warnings = []
    cards = []
    for client in clients:
        name = client.get("name", client.get("username", "client"))
        username = client.get("username")
        enabled = client.get("enabled", True)
        status = states.get(username, "отключён") if enabled else "отключён"
        client_alerts = []
        if len(name_groups.get(str(username).strip().lower(), [])) > 1:
            client_alerts.append("дубль имени")
        if not enabled:
            client_alerts.append("выключен")
        elif status != "подключён" and username not in recent:
            client_alerts.append("старый")
        warnings.extend([f"Hysteria: {username} - {item}" for item in client_alerts if item != "выключен"])
        pills = [client_pill(status, "good" if status == "подключён" else "bad", attrs=f" data-vpn-status-id='{stable_dom_id('hysteria', username)}'")]
        pills.append(client_pill("выключен" if not enabled else "активный профиль", "bad" if not enabled else "good"))
        if client.get("iphone"):
            pills.append(client_pill("iPhone"))
        if client_alerts:
            pills.append(client_pill("!", "bad"))
        rows = [
            client_row("IP подключения", f"<code data-vpn-ip-id='{stable_dom_id('hysteria', username)}'>{html.escape(ips.get(username, '-'))}</code>"),
            client_row("Username", f"<code>{html.escape(username)}</code>"),
            client_row("Password", f"<code>{html.escape(client['password'])}</code>"),
        ]
        actions = toggle_form('/hysteria-toggle', '/hysteria', 'username', username, 'Включить', 'pillbtn') if not enabled else toggle_form('/hysteria-toggle', '/hysteria', 'username', username, 'Отключить', 'danger')
        actions += delete_form('/hysteria-delete', '/hysteria', 'username', username)
        if enabled:
            actions += hysteria_profile_action_links(name)
        cards.append(client_card_html(name, username, pills, rows, "URI", hysteria_client_uri(client), actions, "URI готов для Hiddify/Shadowrocket и других клиентов Hysteria 2."))
    body = f"""
    <div class='section vpn-page' data-vpn-tab='hysteria'>
      <div class='section-title'><h2><span class='ico'>{icon('hysteria')}</span>Hysteria</h2><span class='badge' data-vpn-count>{connected}/{len(clients)} подключены</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-left' style='min-height:220px'><div class='hex'></div></div>
        <div class='hero-right'>
          <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Добавить клиента</h2><span class='badge'>{len(clients)} профилей</span></div>
          {client_add_form('/hysteria-add', '/hysteria', 'Добавить клиент')}
          <p class='mini'>Генерируется URI для Hysteria 2 с паролем и SNI.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Список клиентов</h2><span class='badge'>{len(clients)} шт.</span></div>
      <div class='client-grid'>{''.join(cards) or '<div class="sys-card"><div class="label">Клиенты</div><div class="value">Нет</div><div class="sub">Пока не добавлены</div></div>'}</div>
    </div>
    {warning_box_html(warnings)}
    <div class='section' style='margin-top:16px'><div class='actions'><form method='post' action='/service'><input type='hidden' name='return_to' value='/hysteria' /><input type='hidden' name='name' value='hysteria2' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить</button></form><a class='ghost' href='/services'>Все сервисы</a></div></div>
    """
    return build_shell("Hysteria", "hysteria", body, message, error)


def build_vless_page(message="", error=""):
    svc = service_status("xray")
    sockets = sockets_for_port("8449")
    config_text = read_text_safe("/etc/xray/config.json")
    config = parse_xray_config()
    clients = load_vless_clients()
    pubkey = read_text_safe("/etc/xray/reality.pub").strip() or "-"
    states = xray_client_states()
    ips = xray_client_source_ips()
    recent = recent_journal_names("xray.service", [r"from\s+[0-9a-fA-F:.]+:\d+\s+accepted\b.*\bemail:\s*(\S+)"])
    name_groups = {}
    for client in clients:
        name_groups.setdefault(str(client.get("name") or "").strip().lower(), []).append(client)
    connected = sum(1 for client in clients if client.get("enabled", True) and states.get(client.get("name")) == "подключён")
    warnings = []
    cards = []
    for client in clients:
        name = client.get("name", client.get("uuid", "client"))
        enabled = client.get("enabled", True)
        status = states.get(name, "отключён") if enabled else "отключён"
        client_alerts = []
        if len(name_groups.get(str(name).strip().lower(), [])) > 1:
            client_alerts.append("дубль имени")
        if not enabled:
            client_alerts.append("выключен")
        elif status != "подключён" and name not in recent:
            client_alerts.append("старый")
        warnings.extend([f"VLESS: {name} - {item}" for item in client_alerts if item != "выключен"])
        pills = [client_pill(status, "good" if status == "подключён" else "bad", attrs=f" data-vpn-status-id='{stable_dom_id('vless', client.get('uuid') or name)}'")]
        pills.append(client_pill("выключен" if not enabled else "активный профиль", "bad" if not enabled else "good"))
        if client.get("iphone"):
            pills.append(client_pill("iPhone"))
        if client_alerts:
            pills.append(client_pill("!", "bad"))
        rows = [
            client_row("IP подключения", f"<code data-vpn-ip-id='{stable_dom_id('vless', client.get('uuid') or name)}'>{html.escape(ips.get(name, '-'))}</code>"),
            client_row("UUID", f"<code>{html.escape(client['uuid'])}</code>"),
            client_row("Flow", f"<code>{html.escape(config.get('flow', 'xtls-rprx-vision'))}</code>"),
        ]
        actions = toggle_form('/vless-toggle', '/vless', 'uuid', client['uuid'], 'Включить', 'pillbtn') if not enabled else toggle_form('/vless-toggle', '/vless', 'uuid', client['uuid'], 'Отключить', 'danger')
        actions += delete_form('/vless-delete', '/vless', 'uuid', client['uuid'])
        if enabled:
            actions += profile_action_links(client['name'])
        cards.append(client_card_html(client['name'], client['uuid'], pills, rows, "URI", vless_client_uri(client, config), actions, "URI готов для Hiddify/Shadowrocket и Amnezia."))
    body = f"""
    <div class='section vpn-page' data-vpn-tab='vless'>
      <div class='section-title'><h2><span class='ico'>{icon('vless')}</span>VLESS / Reality</h2><span class='badge' data-vpn-count>{connected}/{len(clients)} подключены</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-left' style='min-height:220px'><div class='hex'></div></div>
        <div class='hero-right'>
          <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Добавить клиента</h2><span class='badge'>{len(clients)} профилей</span></div>
          {client_add_form('/vless-add', '/vless', 'Добавить клиент')}
          <p class='mini'>URI строится под `VLESS + REALITY` и сразу готов для Hiddify/Shadowrocket.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('clients')}</span>Список клиентов</h2><span class='badge'>{len(clients)} шт.</span></div>
      <div class='client-grid'>{''.join(cards) or '<div class="sys-card"><div class="label">Клиенты</div><div class="value">Нет</div><div class="sub">Пока не добавлены</div></div>'}</div>
    </div>
    {warning_box_html(warnings)}
    <div class='section' style='margin-top:16px'><div class='actions'><form method='post' action='/service'><input type='hidden' name='return_to' value='/vless' /><input type='hidden' name='name' value='xray' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить</button></form><a class='ghost' href='/services'>Все сервисы</a></div></div>
    """
    return build_shell("VLESS", "vless", body, message, error)


def build_panel_users_page(message="", error=""):
    users = load_panel_users()
    viewer = current_request_user()
    viewer_is_admin = panel_user_is_admin(viewer)
    rows = []
    for user in users:
        name = user["username"]
        uname = html.escape(name)
        qname = quote(name, safe="")
        admin_badge = "<span class='status-pill good'><span class='status-dot'></span>главный</span>" if user.get("is_admin") else "<span class='status-pill'><span class='status-dot'></span>обычный</span>"
        totp_badge = "<span class='status-pill good'><span class='status-dot'></span>включён</span>" if user.get("totp_enabled") else "<span class='status-pill bad'><span class='status-dot'></span>выключен</span>"
        totp_setup = ""
        if user.get("totp_enabled") and user.get("totp_secret"):
            uri = totp_uri(name, user["totp_secret"])
            totp_setup = f"<div style='margin-top:10px'><img src='/totp-qr/{qname}' alt='2FA QR' style='width:118px;height:118px;border-radius:14px;background:#fff;padding:6px' /><div class='mini'>Секрет: <code>{html.escape(user['totp_secret'])}</code></div><div class='mini'><code>{html.escape(uri)}</code></div></div>"
        if viewer_is_admin or viewer == name:
            can_toggle_admin = viewer_is_admin
            can_manage_2fa = viewer_is_admin or viewer == name
            totp_actions = f"""
              <div>{totp_badge}</div>
              {totp_setup}
              <div class='actions' style='margin-top:10px'>
                <form method='post' action='/panel-users-totp'><input type='hidden' name='return_to' value='/panel-users' /><input type='hidden' name='username' value='{uname}' /><input type='hidden' name='action' value='{'regenerate' if user.get('totp_enabled') else 'enable'}' /><button type='submit' class='pillbtn'>{'Перевыпустить' if user.get('totp_enabled') else 'Включить'}</button></form>
                {f"<form method='post' action='/panel-users-totp'><input type='hidden' name='return_to' value='/panel-users' /><input type='hidden' name='username' value='{uname}' /><input type='hidden' name='action' value='disable' /><button type='submit' class='danger'>Выключить</button></form>" if user.get('totp_enabled') else ''}
              </div>
            """ if can_manage_2fa else totp_badge
            rows.append(f"""
            <tr>
              <td><input name='username' form='edit-{html.escape(name)}' value='{uname}' /></td>
              <td><input name='password' form='edit-{html.escape(name)}' placeholder='Новый пароль' autocomplete='off' /></td>
              <td>{admin_badge}{f"<label class='mini' style='display:block;margin-top:8px'><input type='checkbox' name='is_admin' form='edit-{html.escape(name)}' {'checked' if user.get('is_admin') else ''} {'disabled' if not can_toggle_admin else ''}/> Главный</label>" if can_toggle_admin else ''}</td>
              <td>{totp_actions}</td>
              <td class='actions'>
                <form id='edit-{html.escape(name)}' method='post' action='/panel-users'>
                  <input type='hidden' name='return_to' value='/panel-users' />
                  <input type='hidden' name='old_username' value='{uname}' />
                  <button type='submit'>Сохранить</button>
                </form>
                {"<form method='post' action='/panel-users-delete'><input type='hidden' name='return_to' value='/panel-users' /><input type='hidden' name='username' value='" + uname + "' /><button type='submit' class='danger'>Удалить</button></form>" if viewer_is_admin and len(users) > 1 else ''}
              </td>
            </tr>
            """)
        else:
            rows.append(f"<tr><td><code>{uname}</code></td><td>••••••••</td><td>{admin_badge}</td><td>{totp_badge}</td><td>-</td></tr>")
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('users')}</span>Пользователи панели</h2><span class='badge'>{len(users)} шт.</span></div>
      <div class='hero' style='margin-top:0'>
        <div class='hero-right' style='width:100%'>
          {'<div class="section-title"><h2><span class="ico">' + icon('users') + '</span>Добавить пользователя</h2><span class="badge">доступ к панели</span></div><form method="post" action="/panel-users"><input type="hidden" name="return_to" value="/panel-users" /><div class="grid2"><input name="username" placeholder="Логин" autocomplete="off" /><input name="password" placeholder="Пароль" autocomplete="off" /></div><div class="actions" style="margin-top:12px"><button type="submit" class="pillbtn">Создать</button><button type="submit" formmethod="post" formaction="/panel-users-reset" class="ghost">Сбросить из env</button></div></form>' if viewer_is_admin else '<div class="ops-empty">Управление пользователями доступно только главному аккаунту.</div>'}
          <p class='mini'>Пользователи сохраняются в <code>{html.escape(str(CFG['panel_users_file']))}</code>.</p>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('users')}</span>Список пользователей</h2><span class='badge'>{len(users)} всего</span></div>
      <div class='tablewrap'><table><tr><th>Логин</th><th>Пароль</th><th>Роль</th><th>Google Authenticator</th><th>Действия</th></tr>{''.join(rows) or '<tr><td colspan="5">Пользователей нет</td></tr>'}</table></div>
    </div>
    """
    return build_shell("Пользователи панели", "panel-users", body, message, error)


def build_services_page(message="", error=""):
    services = [service_status(k) for k in ["awg", "openvpn", "softether", "panel", "fail2ban", "vpn-iptables", "openvpn-iptables"] if k in SERVICE_MAP]
    label_map = SERVICE_LABELS
    cards = []
    for svc in services:
        cards.append(f"<div class='widget'><div class='widget-head'><span class='ico'>{icon('services')}</span><div class='label'>{html.escape(label_map.get(svc['name'], svc['name']))}</div></div><div class='value'>{html.escape({'active':'активен','inactive':'неактивен','failed':'ошибка'}.get(svc['active'], svc['active']))}</div><div class='sub'>{html.escape(svc['unit'])}</div></div>")
    rows = []
    for svc in services:
        rows.append(f"<tr><td>{html.escape(label_map.get(svc['name'], svc['name']))}</td><td><code>{html.escape(svc['unit'])}</code></td><td>{html.escape({'active':'активен','inactive':'неактивен','failed':'ошибка'}.get(svc['active'], svc['active']))}</td><td>{html.escape({'enabled':'включён','disabled':'выключен'}.get(svc['enabled'], svc['enabled']))}</td><td class='actions'><form method='post' action='/service'><input type='hidden' name='return_to' value='/services' /><input type='hidden' name='name' value='{html.escape(svc['name'])}' /><input type='hidden' name='action' value='start' /><button type='submit'>Запустить</button></form><form method='post' action='/service'><input type='hidden' name='return_to' value='/services' /><input type='hidden' name='name' value='{html.escape(svc['name'])}' /><input type='hidden' name='action' value='stop' /><button type='submit' class='danger'>Остановить</button></form><form method='post' action='/service'><input type='hidden' name='return_to' value='/services' /><input type='hidden' name='name' value='{html.escape(svc['name'])}' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить</button></form></td></tr>")
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Сервисы</h2><span class='badge'>управление systemd</span></div>
      <div class='widgets'>{''.join(cards)}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Управление сервисами</h2><span class='badge'>{len(services)} юнитов</span></div>
      <div class='tablewrap'><table><tr><th>Имя</th><th>Юнит</th><th>Активен</th><th>Включён</th><th>Действия</th></tr>{''.join(rows)}</table></div>
    </div>
    """
    return build_shell("Сервисы", "services", body, message, error)


def build_sstp_page(message="", error=""):
    snapshot = system_snapshot()
    tunnel = service_status("office-sstp")
    tunnel_label = {'active': 'активен', 'inactive': 'неактивен', 'failed': 'ошибка'}.get(tunnel['active'], tunnel['active'])
    sstp_route = safe_run(["ip", "route", "get", "10.10.0.71"]).strip() or "Нет данных"
    nas_mount = "/mnt/office-nas-public"
    mount_ok = path_has_active_mount(Path(nas_mount))
    backup_settings = load_backup_settings()
    target_path = backup_settings.get("target_path", "")
    tunnel_warnings = []
    if tunnel["active"] != "active":
        tunnel_warnings.append(f"{tunnel['unit']} сейчас {tunnel['active']}")
    if not mount_ok:
        tunnel_warnings.append(f"NAS mount {nas_mount} не активен")
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('sstp')}</span>Office SSTP туннель</h2><span class='badge'>{html.escape(tunnel['active'])}</span></div>
      {warning_box_html(tunnel_warnings)}
      <div class='widgets'>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('services')}</span><div class='label'>Сервис</div></div><div class='value'>{html.escape(tunnel_label)}</div><div class='sub'><code>{html.escape(tunnel['unit'])}</code></div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('server')}</span><div class='label'>Маршрут</div></div><div class='value'>ppp0</div><div class='sub'>{html.escape(sstp_route[:120])}</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('shield')}</span><div class='label'>NAS mount</div></div><div class='value'>{'active' if mount_ok else 'inactive'}</div><div class='sub'><code>{html.escape(nas_mount)}</code></div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('clients')}</span><div class='label'>Backup target</div></div><div class='value'>{html.escape('local' if backup_settings.get('target_type') == 'local' else 'rsync')}</div><div class='sub'>{html.escape(target_path or '-')}</div></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Управление</h2><span class='badge'>systemd</span></div>
      <div class='actions'>
        <form method='post' action='/service'><input type='hidden' name='return_to' value='/sstp' /><input type='hidden' name='name' value='office-sstp' /><input type='hidden' name='action' value='restart' /><button type='submit'>Перезапустить туннель</button></form>
        <form method='post' action='/service'><input type='hidden' name='return_to' value='/sstp' /><input type='hidden' name='name' value='office-sstp' /><input type='hidden' name='action' value='stop' /><button type='submit' class='danger'>Остановить туннель</button></form>
      </div>
      <p class='mini'>Этот раздел управляет только SSTP-туннелем к NAS. Клиентский SoftEther-экран и `vpncmd` тут больше не используются.</p>
    </div>
    """
    return build_shell("SSTP туннель", "sstp", body, message, error)


def build_mtproto_page(message="", error=""):
    data = telemt_snapshot()
    svc = data["service"]
    state_label = {"active": "активен", "inactive": "неактивен", "failed": "ошибка"}.get(svc.get("active"), svc.get("active", "unknown"))
    access = data.get("access") or {}
    server = access.get("ip", "-")
    port = str(access.get("port", "-"))
    tg_url = access.get("tg_url", "")
    tme_url = access.get("tme_url", "")
    qr_url = access.get("tme_qrcode") or access.get("tg_qrcode") or ""
    recent_problem = ""
    for line in reversed((data.get("logs") or "").splitlines()):
        lowered = line.lower()
        if "operation was canceled" in lowered:
            continue
        if '"level":"warn"' in lowered or '"level":"error"' in lowered or ' error ' in lowered:
            recent_problem = line.strip()
            break
    warnings = []
    if svc.get("active") != "active":
        warnings.append(f"{svc.get('unit', 'docker container telemt')} сейчас {svc.get('active')}")
    if not tg_url:
        warnings.append("не удалось прочитать ссылки Telemt")
    body = f"""
    <div class='section' data-mtproto-root>
      <div class='section-title'><h2><span class='ico'>{icon('qr')}</span>Telemt</h2><span class='badge'>{html.escape(state_label)}</span></div>
      {warning_box_html(warnings)}
      <div class='error' data-mtproto-error-box {'hidden' if not recent_problem else ''}><span data-mtproto-error-text>{html.escape(recent_problem)}</span></div>
      <div class='widgets'>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('services')}</span><div class='label'>Сервис</div></div><div class='value' data-mtproto-service>{html.escape(svc.get('active', 'unknown'))}</div><div class='sub'><code>{html.escape(svc.get('unit', 'docker container telemt'))}</code></div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('server')}</span><div class='label'>Server</div></div><div class='value'>{html.escape(server)}</div><div class='sub'>внешний IP прокси</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('shield')}</span><div class='label'>Port</div></div><div class='value'>{html.escape(port)}</div><div class='sub'>MTProto listener</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('configs')}</span><div class='label'>Config</div></div><div class='value'>{'есть' if data.get('config_exists') else 'нет'}</div><div class='sub'><code>{html.escape(data.get('config_path', '/opt/telemt-docker/telemt.toml'))}</code></div></div>
      </div>
    </div>
    <div class='dual' style='margin-top:16px'>
      <div class='section'>
        <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Ссылки доступа</h2><span class='badge'>tg:// / t.me</span></div>
        <div class='kv-grid'>
          <div class='kv'><span>tg://</span><strong><code>{html.escape(tg_url or '-')}</code></strong></div>
          <div class='kv'><span>t.me</span><strong><code>{html.escape(tme_url or '-')}</code></strong></div>
        </div>
        <div class='actions' style='margin-top:14px'>
          <button type='button' class='pillbtn' data-copy-text='{html.escape(tg_url, quote=True)}'>Скопировать tg://</button>
          <button type='button' class='ghost' data-copy-text='{html.escape(tme_url, quote=True)}'>Скопировать t.me</button>
          {f"<button type='button' class='ghost' data-qr-img='{html.escape(qr_url, quote=True)}' data-qr-title='MTProto QR'>Открыть QR</button>" if qr_url else ""}
        </div>
      </div>
      <div class='section'>
        <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Управление</h2><span class='badge'>docker compose</span></div>
        <p class='mini'>Контейнер `telemt` управляется через `/opt/telemt-docker` и `docker compose`. Для обновления пользователей используйте `telemt-users`.</p>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Конфиг</h2><span class='badge'>/opt/telemt-docker/telemt.toml</span></div>
      <pre>{html.escape(data.get('config_text') or 'Нет данных')}</pre>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Последние логи</h2><span class='badge'>journalctl</span></div>
      <pre>{html.escape(data.get('logs') or 'Нет данных')}</pre>
    </div>
    """
    return build_shell("Telemt", "mtproto", body, message, error)


def build_fail2ban_page(message="", error=""):
    data = fail2ban_snapshot()
    svc = data["service"]
    jail_cards = []
    banned_rows = []
    for jail in data["jails"]:
        jail_cards.append(f"""
        <div class='manage-card'>
          <div class='manage-head'><strong>{html.escape(jail['name'])}</strong><span class='badge'>{html.escape(jail['current_banned'])} banned</span></div>
          <div class='rule-chips'><span class='rule-chip'>failed сейчас {html.escape(jail['current_failed'])}</span><span class='rule-chip'>failed всего {html.escape(jail['total_failed'])}</span><span class='rule-chip good'>banned всего {html.escape(jail['total_banned'])}</span></div>
        </div>
        """)
        for ip in jail["banned"]:
            banned_rows.append(f"<tr><td><code>{html.escape(ip)}</code></td><td>{html.escape(jail['name'])}</td><td class='actions'><form method='post' action='/fail2ban-unban'><input type='hidden' name='return_to' value='/fail2ban' /><input type='hidden' name='jail' value='{html.escape(jail['name'])}' /><input type='hidden' name='ip' value='{html.escape(ip)}' /><button type='submit' class='danger'>Разбанить</button></form></td></tr>")
    state_label = {"active": "активен", "inactive": "неактивен", "failed": "ошибка"}.get(svc.get("active"), svc.get("active", "unknown"))
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Fail2Ban</h2><span class='badge'>{html.escape(svc.get('active', 'unknown'))}</span></div>
      <div class='widgets'>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('services')}</span><div class='label'>Сервис</div></div><div class='value'>{html.escape(state_label)}</div><div class='sub'><code>{html.escape(svc.get('unit', 'fail2ban.service'))}</code></div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('shield')}</span><div class='label'>Jails</div></div><div class='value'>{len(data['jails'])}</div><div class='sub'>активные правила защиты</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('users')}</span><div class='label'>Banned</div></div><div class='value'>{sum(len(j['banned']) for j in data['jails'])}</div><div class='sub'>IP сейчас в бане</div></div>
      </div>
      <div class='actions' style='margin-top:14px'>
        <form method='post' action='/service'><input type='hidden' name='return_to' value='/fail2ban' /><input type='hidden' name='name' value='fail2ban' /><input type='hidden' name='action' value='restart' /><button class='pillbtn' type='submit'>Перезапустить Fail2Ban</button></form>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Jails</h2><span class='badge'>{len(data['jails'])}</span></div>
      <div class='manage-grid'>{''.join(jail_cards) or '<div class="ops-empty">Jails не найдены</div>'}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('firewall')}</span>Забаненные IP</h2><span class='badge'>{len(banned_rows)}</span></div>
      <div class='tablewrap'><table><tr><th>IP</th><th>Jail</th><th>Действия</th></tr>{''.join(banned_rows) or '<tr><td colspan="3">Сейчас забаненных IP нет</td></tr>'}</table></div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Журнал</h2><span class='badge'>последние записи</span></div>
      <pre>{html.escape(data['logs'])}</pre>
    </div>
    """
    return build_shell("Fail2Ban", "fail2ban", body, message, error)


def build_configs_page(message="", error=""):
    rows = []
    for label, path in KNOWN_DOWNLOADS.items():
        exists = path.exists()
        dl = quote(label, safe="")
        rows.append(f"<div class='widget'><div class='widget-head'><span class='ico'>{icon('configs')}</span><div class='label'>{html.escape(label)}</div></div><div class='value'>{'Есть' if exists else 'Нет'}</div><div class='sub'><code>{html.escape(str(path))}</code></div><div class='actions' style='margin-top:12px'><a class='pillbtn' href='/download-file/{dl}'>Скачать</a></div></div>")
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Конфиги</h2><span class='badge'>{len(KNOWN_DOWNLOADS)} файлов</span></div>
      <div class='widgets'>{''.join(rows)}</div>
    </div>
    """
    return build_shell("Конфиги", "configs", body, message, error)


def build_firewall_page(message="", error=""):
    fw = firewall_snapshot()
    snapshot = system_snapshot()
    nft = fw["nft"]
    ip4 = fw["iptables"]
    ip6 = fw["ip6tables"]
    nft_nat_count = sum(1 for x in nft["rules"] if any(token in x for token in ["masquerade", "dnat", "snat"]))
    nft_chain_names = []
    for line in nft["chains"]:
        m = re.search(r"\bchain\s+([^{\s]+)", line)
        nft_chain_names.append(m.group(1) if m else line)
    ip4_samples = (ip4["nat_rules"] or ip4["filter_rules"])[:4]
    ip6_samples = (ip6["nat_rules"] or ip6["filter_rules"])[:4]
    rule_samples = (ip4_samples + ip6_samples)[:8]
    routes = []
    for line in snapshot["routes"].splitlines():
        tokens = line.split()
        if tokens:
            routes.append((tokens[0], line))
    sockets = []
    for line in snapshot["sockets"].splitlines()[1:]:
        if line.strip():
            sockets.append(line.split(None, 5))

    def socket_port(local):
        m = re.search(r":(\d+)$", local)
        return m.group(1) if m else "-"

    def socket_role(port, process):
        roles = {str(k): tuple(v) for k, v in SETTINGS.get("port_roles", {}).items() if isinstance(v, (list, tuple)) and len(v) >= 2}
        if port in roles:
            return roles[port]
        if "beam.smp" in process:
            return "EMQX/Erlang", "Служебный или клиентский порт брокера"
        if "python3" in process:
            return "Python service", "Веб-сервис на Python"
        return "Сервис", "Открытый сетевой сокет"

    def socket_card(row):
        proto = row[0].upper() if len(row) > 0 else "-"
        state = row[1] if len(row) > 1 else "-"
        local = row[4] if len(row) > 4 else "-"
        process = row[5] if len(row) > 5 else ""
        port = socket_port(local)
        role, purpose = socket_role(port, process)
        badge_class = "good" if role in {"AmneziaWG", "Панель", "SSH", "SSTP", "SoftEther CLI"} else ""
        return f"""
        <div class='rule-tile'>
          <div class='label'>{html.escape(proto)} · {html.escape(state)}</div>
          <div class='value'>{html.escape(port)}</div>
          <div class='sub'><strong>{html.escape(role)}</strong> · {html.escape(purpose)}</div>
          <div class='rule-chips'>
            <span class='rule-chip {badge_class}'>{html.escape(local)}</span>
            <span class='rule-chip'>{html.escape(process[:90] or 'process unknown')}</span>
          </div>
        </div>
        """

    route_chips = ''.join(
        f"<span class='rule-chip'>{html.escape(v[:110])}</span>"
        for _, v in routes[:24]
    ) or "<span class='muted'>Маршрутов нет</span>"
    socket_cards = ''.join(socket_card(row) for row in sockets if len(row) >= 2) or "<div class='rule-tile'><div class='label'>Порты</div><div class='value'>-</div><div class='sub'>нет данных</div></div>"

    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('firewall')}</span>Фаервол</h2><span class='badge'>плитки правил</span></div>
      <div class='rule-grid'>
        <div class='rule-tile'><div class='label'>Backend</div><div class='value'>{html.escape(fw['backend'])}</div><div class='sub'>активный движок правил</div></div>
        <div class='rule-tile'><div class='label'>nftables</div><div class='value'>{fw['summary']['nft_rules']}</div><div class='sub'>{fw['summary']['nft_tables']} таблиц · {fw['summary']['nft_chains']} цепочек</div></div>
        <div class='rule-tile'><div class='label'>IPv4</div><div class='value'>{fw['summary']['ip4_rules']}</div><div class='sub'>filter + nat</div></div>
        <div class='rule-tile'><div class='label'>IPv6</div><div class='value'>{fw['summary']['ip6_rules']}</div><div class='sub'>filter + nat</div></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('firewall')}</span>Плитки правил</h2><span class='badge'>{nft_nat_count} NAT</span></div>
      <div class='rule-grid'>
        <div class='rule-tile'>
          <div class='label'>nftables</div>
          <div class='value'>{fw['summary']['nft_chains']}</div>
          <div class='sub'>{fw['summary']['nft_tables']} таблиц, {fw['summary']['nft_rules']} правил</div>
          <div class='rule-chips'>{''.join(f"<span class='rule-chip good'>{html.escape(name)}</span>" for name in nft_chain_names[:6]) or '<span class=\'muted\'>Нет цепочек</span>'}</div>
        </div>
        <div class='rule-tile'>
          <div class='label'>IPv4 NAT</div>
          <div class='value'>{len(ip4['nat_rules'])}</div>
          <div class='sub'>цепочки и трансляция</div>
          <div class='rule-chips'>{''.join(f"<span class='rule-chip warn'>{html.escape(x)}</span>" for x in ip4_samples) or '<span class=\'muted\'>Нет правил</span>'}</div>
        </div>
        <div class='rule-tile'>
          <div class='label'>IPv4 filter</div>
          <div class='value'>{len(ip4['filter_rules'])}</div>
          <div class='sub'>фильтрация пакетов</div>
          <div class='rule-chips'>{''.join(f"<span class='rule-chip'>{html.escape(x)}</span>" for x in ip4['filter_rules'][:3]) or '<span class=\'muted\'>Нет правил</span>'}</div>
        </div>
        <div class='rule-tile'>
          <div class='label'>IPv6</div>
          <div class='value'>{len(ip6['filter_rules']) + len(ip6['nat_rules'])}</div>
          <div class='sub'>filter + nat</div>
          <div class='rule-chips'>{''.join(f"<span class='rule-chip bad'>{html.escape(x)}</span>" for x in rule_samples) or '<span class=\'muted\'>Нет правил</span>'}</div>
        </div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Маршруты</h2><span class='badge'>{len(routes)} записей</span></div>
      <div class='rule-chips'>{route_chips}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('server')}</span>Прослушиваемые порты</h2><span class='badge'>{len(sockets)} сокетов</span></div>
      <div class='rule-grid'>{socket_cards}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Действия</h2><span class='badge'>перезапуск</span></div>
      <div class='actions'>
        <form method='post' action='/service'><input type='hidden' name='return_to' value='/firewall' /><input type='hidden' name='name' value='vpn-iptables' /><input type='hidden' name='action' value='restart' /><button type='submit'>VPN firewall</button></form>
        <form method='post' action='/service'><input type='hidden' name='return_to' value='/firewall' /><input type='hidden' name='name' value='openvpn-iptables' /><input type='hidden' name='action' value='restart' /><button type='submit'>OpenVPN firewall</button></form>
      </div>
    </div>
    """
    return build_shell("Фаервол", "firewall", body, message, error)


def build_server_users_page(message="", error="", ssh_key_info=None):
    data = os_users_snapshot()
    ssh = ssh_settings_snapshot()
    s = ssh["settings"]
    issued_keys = load_ssh_issued_keys()
    rows = []
    for user in data["users"]:
        rows.append(f"<tr><td><code>{html.escape(user['name'])}</code></td><td>{html.escape(user['uid'])}</td><td>{html.escape(user['home'])}</td><td><code>{html.escape(user['shell'])}</code></td><td>{html.escape(user['gecos'] or '-')}</td></tr>")
    user_options = ''.join(f"<option value='{html.escape(user['name'])}' {'selected' if user['name'] == 'root' else ''}>{html.escape(user['name'])}</option>" for user in data['users'])
    key_section = ""
    if issued_keys:
        latest_public = ssh_key_info.get("public_key") if ssh_key_info else ""
        items = []
        for item in reversed(issued_keys):
            is_open = " open" if latest_public and item["public_key"] == latest_public else ""
            items.append(f"""
          <details class='issued-key'{is_open}>
            <summary><strong>{html.escape(item['username'])}</strong><span class='badge'>{html.escape(item['issued_at'] or '-')}</span></summary>
            <div class='issued-key-body'>
              <div class='kv-grid'>
                <div class='kv'><span>Пользователь</span><strong>{html.escape(item['username'])}</strong></div>
                <div class='kv'><span>Комментарий</span><strong>{html.escape(item['comment'])}</strong></div>
                <div class='kv'><span>Home</span><strong>{html.escape(item['home'])}</strong></div>
                <div class='kv'><span>authorized_keys</span><strong><code>{html.escape(item['authorized_keys'])}</code></strong></div>
              </div>
              <div class='manage-card' style='margin-top:14px'><div class='manage-head'><strong>Private key</strong></div><pre>{html.escape(item['private_key'])}</pre></div>
              <div class='manage-card' style='margin-top:14px'><div class='manage-head'><strong>Public key</strong></div><pre>{html.escape(item['public_key'])}</pre></div>
            </div>
          </details>
        """)
        key_section = f"""
      <details class='issued-key' {'open' if ssh_key_info else ''}>
        <summary><strong>Выпущенные SSH-ключи</strong><span class='badge'>{len(issued_keys)}</span></summary>
        <div class='issued-key-body'>
          {''.join(items)}
        </div>
      </details>
    """
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('users')}</span>SSH и пользователи ОС</h2><span class='badge'>{len(data['users'])} аккаунтов</span></div>
      <div class='widgets'>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('services')}</span><div class='label'>SSH</div></div><div class='value'>{html.escape(data['sshd'])}</div><div class='sub'>systemd статус ssh/sshd</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('shield')}</span><div class='label'>Sudo group</div></div><div class='value'>{'есть' if 'sudo:' in data['sudoers'] else '-'}</div><div class='sub'>{html.escape(data['sudoers'][:120])}</div></div>
        <div class='widget'><div class='widget-head'><span class='ico'>{icon('server')}</span><div class='label'>Security</div></div><div class='value'>read-only</div><div class='sub'>создание/удаление ОС-пользователей лучше включать отдельно</div></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Настройки SSH доступа</h2><span class='badge'>sshd_config.d</span></div>
      <form method='post' action='/ssh-settings'>
        <input type='hidden' name='return_to' value='/server-users' />
        <div class='manage-grid'>
          <div class='manage-card'><div class='manage-head'><strong>Парольный вход</strong><span class='badge'>{html.escape(s.get('passwordauthentication', '-'))}</span></div><select name='password_auth'><option value='yes' {'selected' if s.get('passwordauthentication') == 'yes' else ''}>Разрешён</option><option value='no' {'selected' if s.get('passwordauthentication') == 'no' else ''}>Запрещён</option></select><div class='sub'>PasswordAuthentication</div></div>
          <div class='manage-card'><div class='manage-head'><strong>Вход по ключу</strong><span class='badge'>{html.escape(s.get('pubkeyauthentication', '-'))}</span></div><select name='pubkey_auth'><option value='yes' {'selected' if s.get('pubkeyauthentication') == 'yes' else ''}>Разрешён</option><option value='no' {'selected' if s.get('pubkeyauthentication') == 'no' else ''}>Запрещён</option></select><div class='sub'>PubkeyAuthentication</div></div>
          <div class='manage-card'><div class='manage-head'><strong>Root login</strong><span class='badge'>{html.escape(s.get('permitrootlogin', '-'))}</span></div><select name='permit_root'><option value='no' {'selected' if s.get('permitrootlogin') == 'no' else ''}>Запрещён</option><option value='prohibit-password' {'selected' if s.get('permitrootlogin') == 'prohibit-password' else ''}>Только ключ</option><option value='yes' {'selected' if s.get('permitrootlogin') == 'yes' else ''}>Разрешён</option></select><div class='sub'>PermitRootLogin</div></div>
        </div>
        <div class='actions' style='margin-top:14px'><button class='pillbtn' type='submit'>Сохранить и reload SSH</button></div>
      </form>
      <p class='mini'>Перед reload выполняется <code>sshd -t</code>. Файл: <code>{html.escape(str(ssh['override']))}</code>.</p>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('qr')}</span>Выпуск SSH-ключа</h2><span class='badge'>authorized_keys</span></div>
      <form method='post' action='/ssh-key-issue'>
        <input type='hidden' name='return_to' value='/server-users' />
        <div class='manage-grid'>
          <div class='manage-card'>
            <div class='manage-head'><strong>Пользователь</strong><span class='badge'>локальный</span></div>
            <select name='username'>
              {user_options}
            </select>
            <div class='sub' style='margin-top:10px'>Ключ будет добавлен в <code>~/.ssh/authorized_keys</code>.</div>
          </div>
          <div class='manage-card'>
            <div class='manage-head'><strong>Комментарий</strong><span class='badge'>optional</span></div>
            <input name='comment' placeholder='laptop@host или ticket-123' autocomplete='off' />
          </div>
        </div>
        <div class='actions' style='margin-top:14px'><button class='pillbtn' type='submit'>Выпустить ключ</button></div>
      </form>
      {key_section}
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('users')}</span>Локальные пользователи</h2><span class='badge'>/etc/passwd</span></div>
      <div class='tablewrap'><table><tr><th>Логин</th><th>UID</th><th>Home</th><th>Shell</th><th>Описание</th></tr>{''.join(rows) or '<tr><td colspan="5">Нет данных</td></tr>'}</table></div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Последние SSH события</h2><span class='badge'>auth</span></div>
      <pre>{html.escape(data['recent_auth'] or 'Нет данных')}</pre>
    </div>
    """
    return build_shell("SSH и ОС", "server-users", body, message, error)


def build_storage_page(message="", error=""):
    data = storage_snapshot()
    backup_settings = load_backup_settings()
    timer = backup_timer_status()
    target_type = backup_settings.get("target_type", "local")
    scope = backup_settings.get("scope", "critical")
    schedule = backup_settings.get("schedule", "daily")
    disk_cards = []
    for disk in data['disks']:
        color = 'bad' if disk['pct'] >= 85 else 'warn' if disk['pct'] >= 70 else 'good'
        disk_cards.append(f"<div class='manage-card'><div class='manage-head'><strong>{html.escape(disk['mount'])}</strong><span class='status-pill {color}'>{disk['pct']}%</span></div><div class='sub'><code>{html.escape(disk['fs'])}</code> · {html.escape(disk['type'])}</div><div class='progress'><span style='width:{min(disk['pct'], 100)}%'></span></div><div class='rule-chips'><span class='rule-chip'>used {format_bytes(disk['used'])}</span><span class='rule-chip'>free {format_bytes(disk['avail'])}</span><span class='rule-chip'>total {format_bytes(disk['total'])}</span></div></div>")
    backup_rows = ''.join(f"<tr><td>{html.escape(item['name'])}</td><td><code>{html.escape(item['path'])}</code></td><td>{format_bytes(item['size'])}</td><td>{html.escape(item['mtime'])}</td></tr>" for item in data['backups'])
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('server')}</span>Диски и файловые системы</h2><span class='badge'>storage</span></div>
      <div class='manage-grid'>{''.join(disk_cards) or '<div class="ops-empty">Диски не найдены</div>'}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Бэкап системы</h2><span class='badge'>{html.escape(str(CFG['backup_dir']))}</span></div>
      <div class='manage-grid'>
        <form class='manage-card' method='post' action='/backup'><input type='hidden' name='return_to' value='/storage' /><input type='hidden' name='scope' value='critical' /><div class='manage-head'><strong>Критичные точки</strong><span class='badge'>быстро</span></div><div class='sub'>/etc, конфиги systemd, состояние панели, профили клиентов.</div><div class='actions' style='margin-top:14px'><button class='pillbtn' type='submit'>Создать backup</button></div></form>
        <form class='manage-card' method='post' action='/backup'><input type='hidden' name='return_to' value='/storage' /><input type='hidden' name='scope' value='system' /><div class='manage-head'><strong>Вся система</strong><span class='badge'>tar.gz</span></div><div class='sub'>Архив корня в пределах одного filesystem, без /proc, /sys, /dev, /run, /tmp и каталога backup.</div><div class='actions' style='margin-top:14px'><button class='danger' type='submit'>Создать полный backup</button></div></form>
        <div class='manage-card'><div class='manage-head'><strong>Restore</strong><span class='badge'>manual</span></div><div class='sub'>Восстановление не автоматизировано намеренно: сначала нужен выбор архива, dry-run и подтверждение.</div></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Назначение и расписание backup</h2><span class='badge'>{html.escape(timer['active'])}</span></div>
      <form method='post' action='/backup-settings'>
        <input type='hidden' name='return_to' value='/storage' />
        <div class='manage-grid'>
          <div class='manage-card'>
            <div class='manage-head'><strong>Куда сохранять</strong><span class='badge'>NAS/local</span></div>
            <label class='mini'>Тип назначения</label>
            <select name='target_type'>
              <option value='local' {'selected' if target_type == 'local' else ''}>Локальная/смонтированная папка</option>
              <option value='rsync' {'selected' if target_type == 'rsync' else ''}>Rsync по сети</option>
            </select>
            <label class='mini' style='display:block;margin-top:10px'>Папка для локального/NAS mount</label>
            <input name='target_path' value='{html.escape(backup_settings.get('target_path', str(CFG['backup_dir'])))}' placeholder='/mnt/nas-backups/server' autocomplete='off' />
            <label class='mini' style='display:block;margin-top:10px'>Rsync назначение</label>
            <input name='rsync_target' value='{html.escape(backup_settings.get('rsync_target', ''))}' placeholder='backup@nas:/volume1/backups/server/' autocomplete='off' />
            <p class='mini'>Если NAS смонтирован на сервере, выбери первый тип и путь вроде <code>/mnt/nas-backups</code>.</p>
          </div>
          <div class='manage-card'>
            <div class='manage-head'><strong>Что бэкапить</strong><span class='badge'>{html.escape(scope)}</span></div>
            <select name='scope'>
              <option value='critical' {'selected' if scope == 'critical' else ''}>Критичные точки</option>
              <option value='system' {'selected' if scope == 'system' else ''}>Вся система</option>
            </select>
            <div class='sub' style='margin-top:10px'>Критичные точки: <code>/etc</code>, systemd, состояние панели, профили. Вся система: архив <code>/</code> без runtime-каталогов.</div>
          </div>
          <div class='manage-card'>
            <div class='manage-head'><strong>Периодичность</strong><span class='badge'>systemd timer</span></div>
            <label class='mini'><input type='checkbox' name='schedule_enabled' {'checked' if backup_settings.get('schedule_enabled') else ''}/> Включить автоматический backup</label>
            <select name='schedule' style='margin-top:10px'>
              <option value='hourly' {'selected' if schedule == 'hourly' else ''}>Каждый час</option>
              <option value='daily' {'selected' if schedule == 'daily' else ''}>Каждый день</option>
              <option value='weekly' {'selected' if schedule == 'weekly' else ''}>Каждую неделю</option>
              <option value='monthly' {'selected' if schedule == 'monthly' else ''}>Каждый месяц</option>
              <option value='custom' {'selected' if schedule == 'custom' else ''}>Свое OnCalendar</option>
            </select>
            <input name='custom_calendar' value='{html.escape(backup_settings.get('custom_calendar', ''))}' placeholder='Mon..Fri 03:00 или *-*-* 02:30:00' autocomplete='off' style='margin-top:10px' />
            <div class='sub' style='margin-top:10px'>Статус: <code>{html.escape(timer['active'])}</code>, автозапуск: <code>{html.escape(timer['enabled'])}</code></div>
          </div>
        </div>
        <div class='actions' style='margin-top:14px'><button class='pillbtn' type='submit'>Сохранить настройки backup</button></div>
      </form>
      <pre style='margin-top:14px'>{html.escape(timer['next'])}</pre>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('server')}</span>Технические данные</h2><span class='badge'>df/lsblk</span></div>
      <div class='dual'>
        <div><h3>Разделы</h3><pre>{html.escape(data['mounts'])}</pre></div>
        <div><h3>Inodes</h3><pre>{html.escape(data['inodes'])}</pre></div>
      </div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('server')}</span>Блочные устройства</h2><span class='badge'>lsblk</span></div>
      <pre>{html.escape(data['block'])}</pre>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Бэкапы и важные файлы</h2><span class='badge'>{len(data['backups'])} файлов</span></div>
      <div class='tablewrap'><table><tr><th>Имя</th><th>Путь</th><th>Размер</th><th>Изменён</th></tr>{backup_rows or '<tr><td colspan="4">Файлы не найдены</td></tr>'}</table></div>
      <p class='mini'>Пока это безопасный обзор. Кнопки restore/backup лучше добавить отдельно с подтверждением и архивированием.</p>
    </div>
    """
    return build_shell("Диски", "storage", body, message, error)


def build_processes_page(message="", error=""):
    data = process_snapshot()
    cards = []
    for proc in data['processes']:
        cpu = min(float(proc['cpu']), 100.0)
        mem = min(float(proc['mem']), 100.0)
        cards.append(f"""
        <div class='manage-card'>
          <div class='manage-head'><strong>{html.escape(proc['comm'])}</strong><span class='badge'>PID {html.escape(proc['pid'])}</span></div>
          <div class='sub'>{html.escape(proc['args'][:180])}</div>
          <div class='rule-chips'><span class='rule-chip good'>CPU {html.escape(proc['cpu'])}%</span><span class='rule-chip'>RAM {html.escape(proc['mem'])}%</span><span class='rule-chip'>{html.escape(proc['user'])}</span></div>
          <div class='progress'><span style='width:{cpu}%'></span></div>
          <div class='actions' style='margin-top:14px'>
            <form method='post' action='/process-signal'><input type='hidden' name='return_to' value='/processes' /><input type='hidden' name='pid' value='{html.escape(proc['pid'])}' /><input type='hidden' name='signal' value='hup' /><button class='ghost' type='submit'>HUP</button></form>
            <form method='post' action='/process-signal'><input type='hidden' name='return_to' value='/processes' /><input type='hidden' name='pid' value='{html.escape(proc['pid'])}' /><input type='hidden' name='signal' value='term' /><button class='danger' type='submit'>TERM</button></form>
            <form method='post' action='/process-signal'><input type='hidden' name='return_to' value='/processes' /><input type='hidden' name='pid' value='{html.escape(proc['pid'])}' /><input type='hidden' name='signal' value='kill' /><button class='danger' type='submit'>KILL</button></form>
          </div>
        </div>
        """)
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('chart')}</span>Управление процессами</h2><span class='badge'>{len(data['processes'])} top</span></div>
      <div class='manage-grid'>{''.join(cards) or '<div class="ops-empty">Процессы не найдены</div>'}</div>
      <p class='mini'>Доступны HUP, TERM и KILL. PID 1 защищён. Все действия пишутся в аудит.</p>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('chart')}</span>Таблица процессов</h2><span class='badge'>ps</span></div>
      <div class='dual'>
        <div><h3>CPU</h3><pre>{html.escape(data['top_cpu'])}</pre></div>
        <div><h3>Память</h3><pre>{html.escape(data['top_mem'])}</pre></div>
      </div>
    </div>
    """
    return build_shell("Процессы", "processes", body, message, error)


def build_logs_page(message="", error="", unit=""):
    data = logs_snapshot(unit)
    unit_options = ''.join(f"<option value='{html.escape(u)}' {'selected' if u == data['active_unit'] else ''}>{html.escape(u)}</option>" for u in data['units'])
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Логи systemd</h2><span class='badge'>journalctl</span></div>
      <form method='get' action='/logs'><div class='grid2'><select name='unit'><option value=''>Весь журнал</option>{unit_options}</select><button class='pillbtn' type='submit'>Показать</button></div></form>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Failed units</h2><span class='badge'>systemctl</span></div>
      <pre>{html.escape(data['failed'])}</pre>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Журнал</h2><span class='badge'>{html.escape(data['active_unit'] or 'all')}</span></div>
      <pre>{html.escape(data['logs'])}</pre>
    </div>
    """
    return build_shell("Логи", "logs", body, message, error)


def build_tasks_page(message="", error=""):
    data = tasks_snapshot()
    cron_blocks = ''.join(f"<div class='section' style='margin-top:12px'><div class='section-title'><h2>{html.escape(item['name'])}</h2><span class='badge'>cron</span></div><pre>{html.escape(item['text'])}</pre></div>" for item in data['cron_files'])
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('services')}</span>Задачи и таймеры</h2><span class='badge'>cron/systemd</span></div>
      <pre>{html.escape(data['timers'])}</pre>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('configs')}</span>Root crontab</h2><span class='badge'>crontab -l</span></div>
      <pre>{html.escape(data['root_cron'])}</pre>
    </div>
    {cron_blocks}
    """
    return build_shell("Задачи", "tasks", body, message, error)


def build_domains_page(message="", error=""):
    data = domains_snapshot()
    cert_rows = ''.join(f"<tr><td>{html.escape(c['domain'])}</td><td><code>{html.escape(c['path'])}</code></td><td><pre>{html.escape(c['dates'])}</pre></td></tr>" for c in data['certs'])
    web_ports_text = "/".join(str(p) for p in SETTINGS.get("web_ports", ["80", "443", "8443"]))
    listener_chips = ''.join(f"<span class='rule-chip good'>{html.escape(x)}</span>" for x in data['listeners']) or f'<span class="muted">{html.escape(web_ports_text)} не найдены</span>'
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Домены и сертификаты</h2><span class='badge'>{len(data['certs'])} certs</span></div>
      <div class='rule-chips'>{listener_chips}</div>
    </div>
    <div class='section' style='margin-top:16px'>
      <div class='section-title'><h2><span class='ico'>{icon('shield')}</span>Let's Encrypt</h2><span class='badge'>/etc/letsencrypt/live</span></div>
      <div class='tablewrap'><table><tr><th>Домен</th><th>Сертификат</th><th>Даты</th></tr>{cert_rows or '<tr><td colspan="3">Сертификаты не найдены</td></tr>'}</table></div>
    </div>
    <div class='dual' style='margin-top:16px'>
      <div class='section'><div class='section-title'><h2>Nginx sites</h2><span class='badge'>enabled</span></div><pre>{html.escape(data['nginx_sites'])}</pre></div>
      <div class='section'><div class='section-title'><h2>Apache sites</h2><span class='badge'>enabled</span></div><pre>{html.escape(data['apache_sites'])}</pre></div>
    </div>
    """
    return build_shell("Домены", "domains", body, message, error)


def build_audit_page(message="", error=""):
    data = audit_snapshot()
    audit_rows = ''.join(f"<tr><td><code>{html.escape(line)}</code></td></tr>" for line in reversed(data['entries']))
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('system')}</span>Аудит действий панели</h2><span class='badge'>{len(data['entries'])} событий</span></div>
      <div class='tablewrap'><table><tr><th>Событие</th></tr>{audit_rows or '<tr><td>Пока нет событий</td></tr>'}</table></div>
    </div>
    <div class='dual' style='margin-top:16px'>
      <div class='section'><div class='section-title'><h2>Последние входы</h2><span class='badge'>last</span></div><pre>{html.escape(data['logins'])}</pre></div>
      <div class='section'><div class='section-title'><h2>Неудачные входы</h2><span class='badge'>lastb</span></div><pre>{html.escape(data['failed'])}</pre></div>
    </div>
    """
    return build_shell("Аудит", "audit", body, message, error)


def qr_page(profile_name, client_name):
    body = f"""
    <div class='section'>
      <div class='section-title'><h2><span class='ico'>{icon('qr')}</span>{html.escape(client_name)}</h2><span class='badge'><code>{html.escape(profile_name)}</code></span></div>
      <div class='qrbox'><img src='/qrsvg/{html.escape(profile_name)}' alt='QR-код' /></div>
    </div>
    """
    return build_shell("QR-код", "clients", body)


def page_for_path(path, message="", error=""):
    route_key = {
        "/amnezia": "amnezia",
        "/wireguard": "wireguard",
        "/openvpn": "openvpn",
        "/hysteria": "hysteria",
        "/vless": "vless",
        "/sstp": "sstp",
        "/fail2ban": "fail2ban",
    }.get(path)
    if route_key and not nav_item_visible(route_key):
        return build_home()
    if path == "/system":
        return build_system_page(message, error)
    if path in {"/clients", "/amnezia"}:
        return build_amnezia_page(message, error)
    if path == "/wireguard":
        return build_wireguard_page(message, error)
    if path == "/openvpn":
        return build_openvpn_page(message, error)
    if path == "/hysteria":
        return build_hysteria_page(message, error)
    if path == "/vless":
        return build_vless_page(message, error)
    if path == "/clients":
        return build_clients_page(message, error)
    if path == "/services":
        return build_services_page(message, error)
    if path == "/server-users":
        return build_server_users_page(message, error)
    if path == "/storage":
        return build_storage_page(message, error)
    if path == "/processes":
        return build_processes_page(message, error)
    if path == "/logs":
        return build_logs_page(message, error)
    if path == "/sstp":
        return build_sstp_page(message, error)
    if path == "/tasks":
        return build_tasks_page(message, error)
    if path == "/domains":
        return build_domains_page(message, error)
    if path == "/fail2ban":
        return build_fail2ban_page(message, error)
    if path == "/audit":
        return build_audit_page(message, error)
    if path == "/panel-users":
        return build_panel_users_page(message, error)
    if path == "/configs":
        return build_configs_page(message, error)
    if path == "/firewall":
        return build_firewall_page(message, error)
    return build_home()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, cookie=None):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        if cookie:
            for item in cookie if isinstance(cookie, (list, tuple)) else [cookie]:
                self.send_header("Set-Cookie", item)
        self.end_headers()

    def _require_auth(self):
        if request_is_authed(self.headers):
            return True
        self._redirect(f"/login?next={quote(urlparse(self.path).path, safe='')}")
        return False

    def _session_cookie(self, username, max_age=SESSION_TTL):
        value = make_session_token(username)
        return f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"

    def _pending_2fa_cookie(self, username, max_age=300):
        value = make_pending_2fa_token(username)
        return f"{PENDING_2FA_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"

    def _clear_pending_2fa_cookie(self):
        return f"{PENDING_2FA_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"

    def do_GET(self):
        try:
            set_current_request_user(None)
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                next_path = parse_qs(parsed.query).get("next", ["/"])[0] or "/"
                if request_is_authed(self.headers):
                    self._redirect(next_path)
                    return
                self._send(200, login_page(next_path=next_path))
                return
            if parsed.path == "/login-2fa":
                next_path = parse_qs(parsed.query).get("next", ["/"])[0] or "/"
                username = pending_2fa_username(self.headers)
                if not username:
                    self._redirect(f"/login?next={quote(next_path, safe='')}", cookie=self._clear_pending_2fa_cookie())
                    return
                self._send(200, totp_login_page(username, next_path=next_path))
                return
            if parsed.path == "/logout":
                self._redirect("/login", cookie=[f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", self._clear_pending_2fa_cookie()])
                return
            if not self._require_auth():
                return
            set_current_request_user(authenticated_username(self.headers))
            if parsed.path == "/":
                self._send(200, build_home())
                return
            if parsed.path == "/api/system":
                self._send(200, json.dumps(system_payload(), ensure_ascii=False), content_type="application/json; charset=utf-8")
                return
            if parsed.path == "/api/vpn-status":
                tab = parse_qs(parsed.query).get("tab", [""])[0]
                payload_map = {
                    "amnezia": amnezia_status_payload,
                    "wireguard": wireguard_status_payload,
                    "openvpn": openvpn_status_payload,
                    "hysteria": hysteria_status_payload,
                    "vless": vless_status_payload,
                }
                if tab not in payload_map:
                    raise FileNotFoundError
                self._send(200, json.dumps(payload_map[tab](), ensure_ascii=False), content_type="application/json; charset=utf-8")
                return
            if parsed.path == "/logs":
                unit = parse_qs(parsed.query).get("unit", [""])[0]
                self._send(200, build_logs_page(unit=unit))
                return
            if parsed.path in {"/system", "/clients", "/amnezia", "/wireguard", "/openvpn", "/hysteria", "/vless", "/services", "/server-users", "/storage", "/processes", "/sstp", "/tasks", "/domains", "/fail2ban", "/audit", "/panel-users", "/configs", "/firewall"}:
                self._send(200, page_for_path(parsed.path))
                return
            if parsed.path.startswith("/download/"):
                name = unquote(parsed.path.split("/download/", 1)[1])
                profile = CFG["profile_dir"] / name
                if profile.suffix not in {".conf", ".ovpn"} or not profile.exists():
                    raise FileNotFoundError
                data = profile.read_text().encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{profile.name}"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                self.wfile.write(data)
                return
            if parsed.path.startswith("/download-file/"):
                label = unquote(parsed.path.split("/download-file/", 1)[1])
                if label not in KNOWN_DOWNLOADS:
                    raise FileNotFoundError
                path = KNOWN_DOWNLOADS[label]
                if not path.exists():
                    raise FileNotFoundError
                data = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                self.wfile.write(data)
                return
            if parsed.path.startswith("/qrsvg/"):
                name = unquote(parsed.path.split("/qrsvg/", 1)[1])
                profile = CFG["profile_dir"] / name
                if profile.suffix not in {".conf", ".ovpn"} or not profile.exists():
                    raise FileNotFoundError
                svg = qr_svg(profile.read_text()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(svg)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                self.wfile.write(svg)
                return
            if parsed.path.startswith("/totp-qr/"):
                username = unquote(parsed.path.split("/totp-qr/", 1)[1])
                viewer = current_request_user()
                if not (panel_user_is_admin(viewer) or viewer == username):
                    raise RuntimeError("доступ запрещён")
                user = panel_user_by_name(username)
                if not user or not user.get("totp_enabled") or not user.get("totp_secret"):
                    raise FileNotFoundError
                svg = qr_svg(totp_uri(username, user["totp_secret"])).encode()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(svg)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.end_headers()
                self.wfile.write(svg)
                return
            if parsed.path.startswith("/qr/"):
                name = unquote(parsed.path.split("/qr/", 1)[1])
                profile = CFG["profile_dir"] / name
                if profile.suffix not in {".conf", ".ovpn"} or not profile.exists():
                    raise FileNotFoundError
                client_name = profile.stem
                for client in load_state().get("clients", []):
                    if f"{client['name']}.conf" == profile.name:
                        client_name = client['name']
                        break
                self._send(200, qr_page(profile.name, client_name))
                return
            self._send(404, "not found", content_type="text/plain; charset=utf-8")
        except Exception as e:
            self._send(500, page_for_path(parsed.path if 'parsed' in locals() else '/', error=str(e)))

    def do_POST(self):
        try:
            set_current_request_user(None)
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode()
                form = parse_qs(body)
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                next_path = form.get("next", ["/"])[0] or "/"
                record = panel_user_by_name(username)
                if record and record["password"] == password and record.get("totp_enabled"):
                    self._redirect(f"/login-2fa?next={quote(next_path, safe='')}", cookie=self._pending_2fa_cookie(username))
                elif record and record["password"] == password:
                    audit_event("login", username)
                    self._redirect(next_path, cookie=self._session_cookie(username))
                else:
                    audit_event("login_failed", username)
                    self._send(200, login_page(error="Invalid credentials", next_path=next_path))
                return
            if parsed.path == "/login-2fa":
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode()
                form = parse_qs(body)
                next_path = form.get("next", ["/"])[0] or "/"
                totp_value = form.get("totp", [""])[0]
                username = pending_2fa_username(self.headers)
                user = panel_user_by_name(username) if username else None
                if user and verify_totp(user.get("totp_secret", ""), totp_value):
                    audit_event("login", username)
                    self._redirect(next_path, cookie=[self._session_cookie(username), self._clear_pending_2fa_cookie()])
                else:
                    audit_event("login_2fa_failed", username or "unknown")
                    if username:
                        self._send(200, totp_login_page(username, error="Неверный код Google Authenticator", next_path=next_path))
                    else:
                        self._redirect(f"/login?next={quote(next_path, safe='')}", cookie=self._clear_pending_2fa_cookie())
                return
            if parsed.path == "/logout":
                self._redirect("/login", cookie=[f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", self._clear_pending_2fa_cookie()])
                return
            if not self._require_auth():
                return
            set_current_request_user(authenticated_username(self.headers))
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode()
            form = parse_qs(body)
            return_to = form.get("return_to", ["/"])[0] or "/"
            if self.path == "/add":
                name = form.get("name", [""])[0]
                iphone = form.get("iphone", [""])[0] == "1"
                client = add_client(name, iphone=iphone)
                audit_event("add_client", client.get("name", name))
                self._redirect(return_to or "/clients")
                return
            if self.path == "/wireguard-add":
                name = form.get("name", [""])[0]
                iphone = form.get("iphone", [""])[0] == "1"
                client = add_wireguard_client(name, iphone=iphone)
                audit_event("wireguard_add", client.get("name", name))
                self._redirect(return_to or "/wireguard")
                return
            if self.path == "/delete":
                public_key = form.get("public_key", [""])[0]
                remove_client(public_key)
                audit_event("delete_client", public_key[:16])
                self._redirect(return_to or "/clients")
                return
            if self.path == "/wireguard-delete":
                public_key = form.get("public_key", [""])[0]
                remove_wireguard_client(public_key)
                audit_event("wireguard_delete", public_key[:16])
                self._redirect(return_to or "/wireguard")
                return
            if self.path == "/wireguard-toggle":
                public_key = form.get("public_key", [""])[0]
                current = next((c for c in load_wireguard_clients() if c.get("public_key") == public_key), None)
                toggle_wireguard_client(public_key, not bool(current and current.get("enabled", True)))
                audit_event("wireguard_toggle", public_key[:16])
                self._redirect(return_to or "/wireguard")
                return
            if self.path == "/openvpn-add":
                name = form.get("name", [""])[0]
                client = add_openvpn_client(name)
                audit_event("openvpn_add", client.get("name", name))
                self._redirect(return_to or "/openvpn")
                return
            if self.path == "/openvpn-delete":
                name = form.get("name", [""])[0]
                revoke_openvpn_client(name)
                audit_event("openvpn_delete", name)
                self._redirect(return_to or "/openvpn")
                return
            if self.path == "/openvpn-toggle":
                name = form.get("name", [""])[0]
                current = next((c for c in load_openvpn_clients() if c.get("name") == path_safe_name(name)), None)
                toggle_openvpn_client(name, not bool(current and current.get("enabled", True)))
                audit_event("openvpn_toggle", name)
                self._redirect(return_to or "/openvpn")
                return
            if self.path == "/hysteria-add":
                name = form.get("name", [""])[0]
                client = add_hysteria_client(name)
                audit_event("hysteria_add", client.get("name", name))
                self._redirect(return_to or "/hysteria")
                return
            if self.path == "/hysteria-delete":
                username = form.get("username", [""])[0]
                remove_hysteria_client(username)
                audit_event("hysteria_delete", username)
                self._redirect(return_to or "/hysteria")
                return
            if self.path == "/hysteria-toggle":
                username = form.get("username", [""])[0]
                current = next((c for c in load_hysteria_clients() if c.get("username") == username), None)
                toggle_hysteria_client(username, not bool(current and current.get("enabled", True)))
                audit_event("hysteria_toggle", username)
                self._redirect(return_to or "/hysteria")
                return
            if self.path == "/vless-add":
                name = form.get("name", [""])[0]
                client = add_vless_client(name)
                audit_event("vless_add", client.get("name", name))
                self._redirect(return_to or "/vless")
                return
            if self.path == "/vless-delete":
                uuid_value = form.get("uuid", [""])[0]
                remove_vless_client(uuid_value)
                audit_event("vless_delete", uuid_value[:16])
                self._redirect(return_to or "/vless")
                return
            if self.path == "/vless-toggle":
                uuid_value = form.get("uuid", [""])[0]
                current = next((c for c in load_vless_clients() if c.get("uuid") == uuid_value), None)
                toggle_vless_client(uuid_value, not bool(current and current.get("enabled", True)))
                audit_event("vless_toggle", uuid_value[:16])
                self._redirect(return_to or "/vless")
                return
            if self.path == "/service":
                name = form.get("name", [""])[0]
                action = form.get("action", [""])[0]
                if name not in SERVICE_MAP:
                    raise RuntimeError("unknown service")
                service_action(name, action)
                audit_event("service", f"{action} {name}")
                self._redirect(return_to or "/services")
                return
            if self.path == "/fail2ban-unban":
                jail = form.get("jail", [""])[0]
                ip = form.get("ip", [""])[0]
                fail2ban_unban(jail, ip)
                self._redirect(return_to or "/fail2ban")
                return
            if self.path == "/process-signal":
                pid = form.get("pid", [""])[0]
                signal_name = form.get("signal", [""])[0]
                signal_process(pid, signal_name)
                self._redirect(return_to or "/processes")
                return
            if self.path == "/backup":
                scope = form.get("scope", ["critical"])[0]
                create_backup(scope)
                self._redirect(return_to or "/storage")
                return
            if self.path == "/backup-settings":
                update_backup_settings(form)
                self._redirect(return_to or "/storage")
                return
            if self.path == "/ssh-settings":
                password_auth = form.get("password_auth", ["no"])[0]
                pubkey_auth = form.get("pubkey_auth", ["yes"])[0]
                permit_root = form.get("permit_root", ["prohibit-password"])[0]
                update_ssh_settings(password_auth, pubkey_auth, permit_root)
                self._redirect(return_to or "/server-users")
                return
            if self.path == "/ssh-key-issue":
                username = form.get("username", [""])[0]
                comment = form.get("comment", [""])[0]
                key_info = issue_ssh_key(username, comment)
                save_ssh_issued_key(key_info)
                audit_event("ssh_key_issue", f"{username} {comment.strip()}")
                self._send(200, build_server_users_page(message="SSH-ключ выпущен", ssh_key_info=key_info))
                return
            if self.path == "/sstp-user":
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                full_name = form.get("full_name", [""])[0]
                note = form.get("note", [""])[0]
                softether_user_create(username, password, full_name, note)
                audit_event("sstp_user_create", username)
                self._redirect(return_to or "/sstp")
                return
            if self.path == "/sstp-user-delete":
                username = form.get("username", [""])[0]
                softether_user_delete(username)
                audit_event("sstp_user_delete", username)
                self._redirect(return_to or "/sstp")
                return
            if self.path == "/panel-users":
                username = form.get("username", [""])[0]
                password = form.get("password", [""])[0]
                old_username = form.get("old_username", [""])[0]
                viewer = current_request_user()
                viewer_is_admin = panel_user_is_admin(viewer)
                if not viewer_is_admin and (not old_username or old_username != viewer):
                    raise RuntimeError("доступ запрещён")
                is_admin = form.get("is_admin", [""])[0] == "on" if viewer_is_admin else None
                upsert_panel_user(username, password or None, is_admin, old_username=old_username or None)
                audit_event("panel_user_save", username)
                self._redirect(return_to or "/panel-users")
                return
            if self.path == "/panel-users-delete":
                viewer = current_request_user()
                if not panel_user_is_admin(viewer):
                    raise RuntimeError("доступ запрещён")
                username = form.get("username", [""])[0]
                delete_panel_user(username)
                audit_event("panel_user_delete", username)
                self._redirect(return_to or "/panel-users")
                return
            if self.path == "/panel-users-totp":
                viewer = current_request_user()
                username = form.get("username", [""])[0]
                action = form.get("action", [""])[0]
                if not (panel_user_is_admin(viewer) or viewer == username):
                    raise RuntimeError("доступ запрещён")
                set_panel_user_totp(username, action)
                self._redirect(return_to or "/panel-users")
                return
            if self.path == "/panel-users-reset":
                viewer = current_request_user()
                if not panel_user_is_admin(viewer):
                    raise RuntimeError("доступ запрещён")
                reset_panel_users_from_env()
                audit_event("panel_users_reset", "env")
                self._redirect(return_to or "/panel-users")
                return
            self._send(404, "not found", content_type="text/plain; charset=utf-8")
        except Exception as e:
            self._send(500, page_for_path(parsed.path if 'parsed' in locals() else '/', error=str(e)))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--run-backup":
        ensure_dirs()
        target = create_backup(None)
        print(target)
        return
    if not CFG["auth_pass"]:
        raise SystemExit("PANEL_PASS is required")
    ensure_dirs()
    host = os.environ.get("PANEL_HOST", "0.0.0.0")
    port = int(os.environ.get("PANEL_PORT", "8088"))
    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
