# Contributing

Перед первым изменением прочитайте:

1. [`docs/README.md`](docs/README.md) — порядок чтения.
2. [`docs/06-agent-playbook.md`](docs/06-agent-playbook.md) — если вы ИИ-агент.
3. [`docs/13-definition-of-done.md`](docs/13-definition-of-done.md) — критерии готовности.

## Быстрый старт

```powershell
# 1. toolchain
$env:Path = "$env:USERPROFILE\.cargo\bin;C:\msys64\ucrt64\bin;$env:Path"
# 2. target вне пути с кириллицей
$env:CARGO_TARGET_DIR = "$env:TEMP\opencode\vpn-target"
# 3. хуки
powershell -ExecutionPolicy Bypass -File scripts/setup-hooks.ps1
# 4. проверки
powershell -ExecutionPolicy Bypass -File scripts/check.ps1
```

## Правила

- Ветка на каждую задачу, PR ≤ 400 строк.
- Conventional Commits.
- Тесты обязательны; покрытие `crates/**` — 100%.
- Документация обновляется в том же PR.
- Прямые пуши в `main` запрещены.
- Секреты, `unsafe`, GPL-зависимости — запрещены.

Полные регламенты — в [`docs/`](docs/).
