# vpnpa

Локальные SOCKS5 (`127.0.0.1:1080`) и HTTP CONNECT (`127.0.0.1:8080`). Под ними клиент AmneziaWG 3.1 внутри процесса и уже слушающие чужие SOCKS5. Пользовательский трафик держится на одном живом выходе (`sticky`). Маршрут хоста не меняется, root не нужен. Модуль `github.com/LDPet/vpnpa`, Go 1.25 (`amneziawg-go` v3).

Пользовательская инструкция — `README.md`. Здесь только то, что ломает программу.

## Раскладка

- `cmd/vpnpa` — `main`, дальше `internal/cli`.
- `internal/app` — процесс: оба ingress, `sticky`, `SIGHUP` → `Reload`.
- `internal/balance/sticky` — пробы, выбор текущего, `Down`/`Up`.
- `internal/ingress/socks5`, `internal/ingress/http` — локальные входы. `ingress.Listen` — только loopback.
- `internal/backend/amneziawg` — туннель и API-ключ. `internal/backend/socks5` — чужой SOCKS: vpnpa этот процесс не запускает и не останавливает.
- `internal/config` — YAML, `FileMode` `0600`. `internal/atomicfile` — запись через временный файл и `rename`.
- `internal/cli/update.go` — `vpnpa update`. `internal/logx` — `slog` и вырезание секретов. `internal/paths` — пути без root.
- `test/e2e` — тег `e2e`. `test/functional` входит в обычный `go test`.

Пути без root: конфиг `~/.config/vpnpa/config.yaml`, состояние `~/.local/state/vpnpa/` (`status.json`, `prefer`, `keys/<id>`), бинарник `~/.local/bin/vpnpa`.

## Инварианты

- Текущий бэкенд из-за пробы не получает `Down`/`Up`. Порог только снимает выбор. `Down`/`Up` — у уже не текущего: один раз на пороге и дальше по `restart_interval`. Ошибка пользовательского dial выбор не меняет.
- Выздоровевший бэкенд с большим `priority` текущий сам не вытесняет. `prefer` читается каждый цикл из файла состояния.
- SOCKS5 и HTTP CONNECT отдают hostname в `Dial` как есть и не резолвят его. DNS делает бэкенд.
- `listen` и `http_listen` — только loopback IP. Имя хоста и не-loopback отклоняются, сокет не открывается.
- В лог не попадают целиком `vpn://`, приватные ключи, `api_key`, preshared key и пароль SOCKS. Писать через `logx`.
- `config.yaml` всегда mode `0600`. Перезапись не добавляет биты group/world.
- API-пара X25519 для `vpn://` с `api_endpoint` лежит в `state/keys/<id>` и переиспользуется, пока uri тот же. `Down` файл не удаляет. Другой uri — новая пара.
- `SIGHUP` (`App.Reload`) не переподнимает бэкенд, у которого не изменились `id`, `type` и `uri`. Сменился uri или type — `Up` нового и `Down` старого. Снятый id гасится.
- `vpnpa update` качает релиз во временный файл в каталоге бинарника (`.vpnpa-update-*`), сверяет sha256 и делает `rename`. В запущенный файл не писать.

## Тесты

Из корня репозитория, Go 1.25:

```bash
go test -count=1 -race ./...
go test -count=1 -tags=e2e ./test/e2e
```

Первая команда не собирает `test/e2e` (`//go:build e2e`). Вторая — как в CI, без `-race`.

## Чего не делать

- Не вызывать `Down`/`Up` текущего бэкенда в `sticky` из-за неудачной пробы.
- Не добавлять `net.Lookup*` / `Resolver` во вход. Имя из клиента уходит в `DialContext` как есть.
- Не слушать `0.0.0.0`, внешний IP или hostname.
- Не логировать uri, ключи и пароли, в том числе из `err.Error()` без `logx.Redact` или `safeErr`.
- Не ставить конфигу и `keys/<id>` режим шире `0600`.
- Не генерировать новую API-пару, если `uri_hash` в `keys/<id>` совпал.
- Не делать `Up`/`Down` на reload, если `id`, `type` и `uri` те же. Приоритет можно обновить на месте.
- Не писать новый бинарник поверх исполняемого файла. Только временный файл в том же каталоге и `rename`.
