# vpn-client

[![ci](https://github.com/hausond/wirly-client/actions/workflows/ci.yml/badge.svg)](https://github.com/hausond/wirly-client/actions/workflows/ci.yml)

Кроссплатформенный (в перспективе) VPN-клиент на Rust. Первая цель — Windows.

## Почему так

- **Ядро — Rust**, без sidecar-процессов на Go.
- **Служба + UI разделены**: TUN и таблица маршрутов требуют администратора, поэтому
  привилегированная часть живёт в `vpn-service` (Windows-служба), UI общается с ней по IPC.
- **Роутинг — главная фича**: правила по домену/IP/порту/процессу/сниффингу,
  готовые пресеты, импорт rule-set'ов.

## Структура

```
crates/
  vpn-config/   импорт профилей: vless://, trojan://, ss://, подписки, JSON
  vpn-routing/  модель правил, компиляция матчеров, движок решений, пресеты
  vpn-proto/    trait Outbound + реализации протоколов (WireGuard, SS, Trojan, VLESS/REALITY)
  vpn-core/     состояние сессии, оркестрация, статистика
  vpn-dns/      fake-IP пул, резолвер (hickory-dns в следующих фазах)
  vpn-tun/      TUN-устройство (wintun на Windows), маршруты
  vpn-ipc/      сообщения между службой и UI
apps/
  vpn-service/  привилегированный агент (позже — Windows-служба)
  vpn-desktop/  UI (Slint)
presets/        готовые наборы правил роутинга
```

## Сборка

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
# путь проекта содержит кириллицу — mingw-линкер её не переваривает,
# поэтому target выносим в ASCII-путь:
$env:CARGO_TARGET_DIR = "C:\cargo-target\vpn"

cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p vpn-service -- presets
```

Toolchain: `stable-x86_64-pc-windows-gnu` + MSYS2 UCRT64 (`gcc`, `ld` в PATH).

Демо-запуск печатает загруженные пресеты, решения роутера по тестовым соединениям,
разбор share-ссылки, состояние сессии и выдачу fake-IP.

## Процессы и стандарты

Вся нормативная база — в [`docs/`](docs/README.md). Обязательно к прочтению:

- [`docs/00-charter.md`](docs/00-charter.md) — рамки проекта;
- [`docs/02-code-standards.md`](docs/02-code-standards.md) — как писать код;
- [`docs/03-testing.md`](docs/03-testing.md) — покрытие 100%;
- [`docs/05-quality-gates.md`](docs/05-quality-gates.md) — гейты;
- [`docs/06-agent-playbook.md`](docs/06-agent-playbook.md) — регламент для ИИ-агентов.

Локальные проверки:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup-hooks.ps1
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

CI (`.github/workflows/ci.yml`) обязателен: `fmt`, `clippy`, `test`, `coverage`,
`docs`, `deny`, `audit`, `msrv`. Обход гейтов запрещён.

## Дорожная карта

- **Фаза 0** — каркас, модели, движок правил, пресеты, тесты. ← текущее состояние
- **Фаза 1** — TUN (wintun) + userspace-стек + WireGuard/Shadowsocks/Trojan/VLESS(WS+TLS).
- **Фаза 2** — DNS fake-IP, process-routing, импорт подписок и rule-set'ов, UI.
- **Фаза 3** — VLESS+REALITY (BoringSSL/uTLS), XHTTP.
- **Фаза 4** — Hysteria2, TUIC, AmneziaWG, kill switch, автообновление.

## Лицензии зависимостей

`boringtun` — BSD-3, `shadowsocks-rust` — MIT. Код `sing-box`/`mihomo` — GPL,
`Xray-core` — MPL-2.0: портирование оттуда меняет лицензию проекта, учитывать заранее.
