# Amnezia Panel Portable

> Быстрый установщик собственного серверного стека для VPN, удалённого доступа, MQTT и веб-панели управления.

## Возможности

Скрипт разворачивает на сервере Debian или Ubuntu набор сервисов, который можно выбрать во время установки:

| Компонент | Назначение |
|---|---|
| **AmneziaWG** | VPN на базе Amnezia WireGuard |
| **WireGuard** | Классический WireGuard VPN |
| **OpenVPN** | Совместимый VPN-сервер |
| **Hysteria 2** | Высокопроизводительный прокси-протокол |
| **VLESS Reality (Xray)** | VLESS + Reality на базе Xray |
| **SoftEther / SSTP** | VPN-сервер SoftEther и доступ по SSTP |
| **EMQX** | MQTT-брокер |
| **Fail2Ban** | Защита от перебора паролей и подозрительных подключений |
| **Веб-панель** | Управление установленными сервисами через браузер |

---

## Требования

- Сервер под управлением **Debian** или **Ubuntu**;
- доступ пользователя `root` или возможность выполнять команды через `sudo`;
- доступ сервера в интернет;
- все файлы комплекта должны находиться в одной папке.

> [!WARNING]
> Для панели и VPN используйте сложные уникальные пароли. Не оставляйте административные сервисы открытыми для всего интернета без необходимости.

---

## Быстрый запуск

Перейдите в каталог с файлами установщика и выполните:

```bash
chmod +x install.sh
./install.sh
```

Установщик откроется в интерактивном режиме, предложит выбрать нужные компоненты и спросит порты для каждого включённого VPN-модуля.

---

## Автоматическая установка

Для запуска без вопросов задайте переменные окружения перед выполнением скрипта:

```bash
NONINTERACTIVE=1 \
PANEL_PUBLIC_HOST=1.2.3.4 \
PANEL_USER=admin \
PANEL_PASS='strongpass' \
INSTALL_SOFTETHER=no \
INSTALL_EMQX=no \
./install.sh
```

### Основные параметры

| Переменная | Описание |
|---|---|
| `NONINTERACTIVE=1` | Запуск без интерактивных вопросов |
| `PANEL_PUBLIC_HOST` | Публичный IP-адрес или доменное имя сервера |
| `PANEL_USER` | Логин администратора веб-панели |
| `PANEL_PASS` | Пароль администратора веб-панели |

---

## Выбор устанавливаемых компонентов

Каждому параметру можно присвоить `yes` или `no`.

| Переменная | Компонент |
|---|---|
| `INSTALL_PANEL_CORE=yes|no` | Базовая часть веб-панели |
| `INSTALL_FAIL2BAN=yes|no` | Fail2Ban |
| `INSTALL_AMNEZIAWG=yes|no` | AmneziaWG |
| `INSTALL_WIREGUARD=yes|no` | WireGuard |
| `INSTALL_OPENVPN=yes|no` | OpenVPN |
| `INSTALL_HYSTERIA=yes|no` | Hysteria 2 |
| `INSTALL_VLESS=yes|no` | VLESS Reality / Xray |
| `INSTALL_SOFTETHER=yes|no` | SoftEther / SSTP |
| `INSTALL_EMQX=yes|no` | EMQX |
| `INSTALL_OFFICE_BACKUP=yes|no` | Настройка резервного копирования в офисное хранилище |

## Настройка портов

Можно заранее задать порты через переменные окружения:

- `AMNEZIAWG_PORT`
- `WIREGUARD_PORT`
- `OPENVPN_PORT`
- `HYSTERIA_PORT`
- `VLESS_PORT`
- `PANEL_SSTP_PORT`
- `PANEL_SSTP_ADMIN_PORT`

Пример минимальной установки с панелью, AmneziaWG и WireGuard:

```bash
NONINTERACTIVE=1 \
PANEL_PUBLIC_HOST=vpn.example.com \
PANEL_USER=admin \
PANEL_PASS='change-this-password' \
INSTALL_PANEL_CORE=yes \
INSTALL_FAIL2BAN=yes \
INSTALL_AMNEZIAWG=yes \
INSTALL_WIREGUARD=yes \
INSTALL_OPENVPN=no \
INSTALL_HYSTERIA=no \
INSTALL_VLESS=no \
INSTALL_SOFTETHER=no \
INSTALL_EMQX=no \
INSTALL_OFFICE_BACKUP=no \
AMNEZIAWG_PORT=443 \
WIREGUARD_PORT=51820 \
./install.sh
```

---

## Резервное копирование в NAS через SSTP

Настройка резервного копирования в офисное хранилище необязательна. Для её включения передайте данные SSTP-подключения и сетевой папки NAS:

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

| Переменная | Описание |
|---|---|
| `OFFICE_SSTP_HOST` | Адрес SSTP-сервера |
| `OFFICE_SSTP_USER` / `OFFICE_SSTP_PASS` | Учётные данные для SSTP |
| `OFFICE_NAS_SHARE` | Сетевая папка NAS в формате `//IP/Общий_ресурс` |
| `OFFICE_NAS_USER` / `OFFICE_NAS_PASS` | Учётные данные для NAS |
| `OFFICE_NAS_MOUNT` | Локальная точка монтирования сетевой папки |

> [!NOTE]
> Настройка резервного копирования выполняется только при явной передаче соответствующих переменных окружения.

---

## Ограничение доступа к EMQX

Чтобы разрешить доступ к EMQX только с определённых публичных IP-адресов, укажите их через запятую:

```bash
EMQX_ALLOW_IPS='1.2.3.4/32,5.6.7.8/32' ./install.sh
```

---

## Состав комплекта

| Файл | Назначение |
|---|---|
| `install.sh` | Установка и первоначальная настройка сервисов |
| `uninstall.sh` | Удаление установленных компонентов |
| `panel2.py` | Веб-панель |

Все три файла должны находиться **в одном каталоге**.

---

## Важные замечания

- Автоматическая установка рассчитана на системы с пакетным менеджером `apt`.
- Автоматическая установка `amneziawg-tools` реализована для Ubuntu.
- Существующие конфигурации по возможности сохраняются.
- Модули, отключённые во время установки, не отображаются в навигации веб-панели.
- Перед запуском на рабочем сервере рекомендуется сделать резервную копию текущих конфигураций и проверить, что нужные порты не заняты.

---

## Удаление

Запустите скрипт от имени `root`:

```bash
chmod +x uninstall.sh
./uninstall.sh
```

Скрипт удаления может:

- остановить и отключить сервисы;
- удалить созданные конфигурации и файлы;
- при необходимости удалить установленные пакеты.
