# Netrunner Core

Мультиплексированный VPN-туннель на Rust, маскирующийся под обычный HTTPS-трафик на TLS 1.3.
Встроенный профиль по умолчанию основан на Chrome 140; его можно заменить профилем,
снятым с нужного браузера. Клиент (Linux/OpenWrt/Android через UniFFI) + серверный узел.

🇬🇧 [English version](README.md)

> **💛 Поддержать Netrunner Core.** Ядро развивается независимо и держится на пожертвованиях, а не на доходе от коммерческого продукта. Если оно вам полезно, поддержите проект.
> USDT (TRC-20): `TQbts9Bj1LZJQE8oGbSbo1Qg6R3Co2k8jX` ([подробнее](DONATE.md))
>
> <img src=".github/donate-usdt-trc20.png" alt="QR-код USDT TRC-20" width="140">

**Возможности**

- до 4 параллельных TCP-«ног» на сессию, бесшовный переезд потоков при обрыве ноги;
- сквозное управление потоком (кредитное окно), адаптивные буферы, BBR на ногах;
- аутентифицированный хендшейк (X25519 + статический ключ узла), forward secrecy,
  AEAD (AES-GCM / ChaCha20-Poly1305);
- маскировка: встроенный профиль Chrome 140 по умолчанию (JA3/JA4, постквантовый `key_share`),
  cover-flight сервера, нерегулярная набивка длин, сайт-приманка для сканеров и активных проб;
- пользовательские профили браузеров из JSON: `netrunner-client profile record` снимает TLS-отпечаток,
  QUIC Initial и форму трафика с выбранного браузера, проверяет воспроизведение движком и пишет один файл;
- опционально: UDP-нога (QUIC/WebRTC-мимикрия), mesh из нескольких узлов с onion-маршрутами;
- L3-VPN без TCP-in-TCP: TUN + userspace-стек (`nrxp-smoltcp`), kill-switch, режим роутера.

Netrunner объединяет аутентифицированные сессии, маскировку трафика под HTTPS и транспорт по
нескольким ногам.

## Профиль нужного браузера

Клиент поставляется со встроенным профилем по умолчанию, но можно снять отдельный профиль с браузера,
трафик которого хотите воспроизводить. Live-запись работает в Linux через сырой сокет. Нужен CLI-бинарь
`netrunner-client` и право `CAP_NET_RAW` (или запуск от `root`).

```bash
# собрать CLI, если бинарь ещё не готов
cargo build --release -p netrunner-client --features cli --bin netrunner-client

# один раз выдать бинарю право на захват пакетов
sudo setcap cap_net_raw+ep ./target/release/netrunner-client

# отключить VPN, начать запись и открыть несколько HTTPS-сайтов в нужном браузере
./target/release/netrunner-client profile record \
  --out browser.json --name my-browser --seconds 120 --stop-after 12 \
  --save-pcap browser.pcap

# проверить профиль и запустить клиент с ним
./target/release/netrunner-client profile check browser.json
sudo ./target/release/netrunner-client --config client.toml --browser-profile browser.json
```

Чтобы записать QUIC-блок, оставьте QUIC включённым в браузере и откройте сайты с HTTP/3. Для нескольких
браузеров или отпечатков используйте `--all`; `--min-hellos` задаёт минимальное число соединений на группу.
Если захват уже сохранён, постройте профиль из `.pcap`/`.pcapng` командой
`netrunner-client profile build capture.pcapng --all --out profiles.json` — это подходит и для Windows/macOS.
Несколько JSON-профилей объединяются командой `profile merge first.json second.json --out pool.json`.
Файл можно указать через `--browser-profile`, параметр `browser_profile` в `client.toml` или
переменную `NETRUNNER_BROWSER_PROFILE`.

Записывайте трафик без работающего VPN, иначе в захват попадёт туннель клиента. Файл pcap содержит IP-адреса
и имена сайтов (SNI); храните его как чувствительные данные и не публикуйте. Если CLI сообщает, что захват
неполон из-за защитных лимитов, переснимите его и не используйте такой профиль как полный.

## Быстрый старт: свой узел за 5 минут

Нужен Linux-VPS с открытыми `tcp/443` и `udp/443`, Rust ≥ 1.91 (или Docker).

```bash
git clone git@github.com:nineAp/netrunner-core.git && cd netrunner-core
cargo build --release -p netrunner-server

# 1. секреты узла
export PROXY_NRXP_SECRET=$(openssl rand -hex 32)        # получат клиенты
export PROXY_NRXP_PRIVATE_KEY=$(openssl rand -hex 32)   # остаётся на узле
export PROXY_NRXP_STRICT=true

# 2. запуск
sudo -E ./target/release/netrunner-server --port 443 --decoy-host www.debian.org --health-port 9091
```

В логе найдите `"nrxp_public_key":"…"` — это публичный ключ узла. Проверка:
`curl -s http://127.0.0.1:9091/` → `{"status":"ok",…}`.

**Клиент** (Linux/OpenWrt) — `client.toml` (`chmod 600`):

```toml
remote_address  = "IP_УЗЛА:443"
sni             = "www.debian.org"            # = --decoy-host
node_secret     = "<PROXY_NRXP_SECRET>"
node_public_key = "<nrxp_public_key из лога>"
killswitch_enabled = true
```

```bash
cargo build --release -p netrunner-client --features cli --bin netrunner-client
sudo ./target/release/netrunner-client --config client.toml
```
