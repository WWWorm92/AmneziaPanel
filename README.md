# AmneziaPanel

[Компоненты](#что-можно-установить) · [Установка](#интерактивная-установка) · [Сообщить о проблеме](https://github.com/WWWorm92/AmneziaPanel/issues)


Набор скриптов для быстрой установки VPN-сервисов и небольшой панели управления на Debian или Ubuntu.

Проект появился из практической задачи: нужно было развернуть на одном сервере несколько VPN-протоколов, не повторяя каждый раз одну и ту же ручную настройку. Установщик можно запускать в интерактивном режиме или передавать параметры через переменные окружения.

## Что можно установить

- AmneziaWG;
- WireGuard;
- OpenVPN;
- Hysteria 2;
- VLESS Reality на базе Xray;
- SoftEther и SSTP;
- EMQX;
- Fail2Ban;
- web-панель;
- дополнительный сценарий резервного копирования на NAS.

Необязательно устанавливать все компоненты. Каждый модуль можно включить или отключить отдельно.

## Перед запуском

Скрипт рассчитан на системы с `apt` и требует права root. Лучше использовать чистую виртуальную машину или VPS и сделать snapshot перед установкой.

Проверьте, что выбранные порты свободны и разрешены в firewall и панели хостинг-провайдера.

## Интерактивная установка

Клонируйте репозиторий: файлы `install.sh`, `uninstall.sh` и `panel2.py` должны находиться в одном каталоге.

```bash
git clone https://github.com/WWWorm92/AmneziaPanel.git
cd AmneziaPanel
chmod +x install.sh
sudo ./install.sh
```

Установщик спросит, какие компоненты нужны, и предложит указать порты.

## Установка без вопросов

Для автоматического развёртывания используйте `NONINTERACTIVE=1` и передайте параметры заранее:

```bash
sudo env \
  NONINTERACTIVE=1 \
  PANEL_PUBLIC_HOST=1.2.3.4 \
  PANEL_USER=admin \
  PANEL_PASS='change-this-password' \
  INSTALL_SOFTETHER=no \
  INSTALL_EMQX=no \
  ./install.sh
```

Доступные флаги компонентов:

```text
INSTALL_PANEL_CORE
INSTALL_FAIL2BAN
INSTALL_AMNEZIAWG
INSTALL_WIREGUARD
INSTALL_OPENVPN
INSTALL_HYSTERIA
INSTALL_VLESS
INSTALL_SOFTETHER
INSTALL_EMQX
INSTALL_OFFICE_BACKUP
```

Значения: `yes` или `no`.

Порты можно задать переменными:

```text
AMNEZIAWG_PORT
WIREGUARD_PORT
OPENVPN_PORT
HYSTERIA_PORT
VLESS_PORT
PANEL_SSTP_PORT
PANEL_SSTP_ADMIN_PORT
```

## Резервное копирование на NAS

Дополнительный модуль может подключаться к удалённой сети по SSTP и монтировать SMB-ресурс:

```bash
sudo env \
  OFFICE_SSTP_HOST=vpn.example.com \
  OFFICE_SSTP_USER=backup \
  OFFICE_SSTP_PASS='secret' \
  OFFICE_NAS_SHARE='//10.0.0.10/Public' \
  OFFICE_NAS_USER=backup \
  OFFICE_NAS_PASS='secret' \
  OFFICE_NAS_MOUNT=/mnt/office-nas \
  ./install.sh
```

Этот режим имеет смысл только после проверки маршрутизации, доступности NAS и прав пользователя на запись.

## Ограничение доступа к EMQX

Публичные адреса можно передать списком CIDR:

```bash
sudo env EMQX_ALLOW_IPS='1.2.3.4/32,5.6.7.8/32' ./install.sh
```

## Удаление

```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

Скрипт умеет остановить службы, удалить созданные файлы и при необходимости удалить установленные пакеты. Перед подтверждением внимательно проверьте список действий, особенно на сервере, где уже были собственные настройки.

## Что важно учитывать

- автоматическая установка `amneziawg-tools` ориентирована прежде всего на Ubuntu;
- существующие конфигурации по возможности сохраняются, но универсально гарантировать это нельзя;
- проект не заменяет настройку firewall, DNS и правил доступа у провайдера;
- после установки нужно проверить каждый протокол отдельно;
- пароли и ключи нельзя хранить в истории shell, публичных логах или репозитории.

## Состояние проекта

Это рабочий инструмент для собственных установок, а не универсальная панель хостинг-провайдера. Разные версии Debian, Ubuntu и сторонних пакетов могут вести себя по-разному, поэтому перед использованием в production установку стоит проверить на тестовой машине.
