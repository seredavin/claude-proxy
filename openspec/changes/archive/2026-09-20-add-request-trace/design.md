## Context

Мотивация — в proposal.md, требования — в `specs/request-trace/spec.md`.

От чего отталкиваемся:

- `gateway.ServeHTTP`: после `authorize()` при включённом маскировании тело
  читается целиком (`maskRequest`) и подменяется; `maskState` едет в
  контексте запроса до `ModifyResponse` (`unmaskResponse`), который
  оборачивает `resp.Body`. `recorder` считает байты ответа клиенту и
  хранит `maskState` для access-лога.
- Все точки, где нужны копии тел, уже проходят через код шлюза: тело от
  клиента — в `maskRequest`, тело на апстрим — после него, тело от апстрима
  — `resp.Body` в `ModifyResponse`, тело клиенту — `recorder.Write`.
- `config.Config` — единственный носитель настроек для `run` и `local`
  (`server.RunReady`).

## Goals / Non-Goals

**Goals:**

- Ноль влияния на путь запроса без `--trace-dir`.
- Стриминг сохраняется: копии пишутся через `io.TeeReader`/обёртку writer'а,
  а не буферизацией ответа.
- Трасса — самодостаточный набор файлов: открыл `meta.json` — понял, что
  это за запрос, открыл `upstream.request` — увидел, что видел Anthropic.

**Non-Goals:**

- Ротация, лимиты, сжатие — режим отладки.
- Трассировка неавторизованных запросов (`401`) и служебных путей.
- Разбор SSE в трассе — файл ответа пишется байт в байт.

## Decisions

### D1. Пакет `internal/trace`, шлюз только вызывает

```go
tr, err := trace.New(dir)            // на старте: mkdir 0700, проверка записи
rec := tr.Begin()                    // префикс <ts>-<seq>
rec.WriteRequest(side, body []byte)  // client | upstream
w := rec.ResponseWriter(side)        // io.WriteCloser в файл; ошибки — в лог, не наружу
rec.Finish(meta)                     // meta.json
```

`side` — `client` или `upstream`. Ошибки записи пакет логирует сам (через
`slog.Logger` из опций) и глотает: трасса не должна ломать проксирование.
Файлы ответов создаются в момент начала фазы ответа — `ResponseWriter(side)`
открывает файл сразу, даже если тело окажется пустым: «апстрим ответил
пустым телом» и «апстрим не вызывался» должны различаться по наличию
файла. Для отвергнутого запроса `ResponseWriter(upstream)` просто не
вызывается. `Record` помнит все открытые writer'ы, и `Finish()` закрывает
их сам — `Close()` у `io.NopCloser` поверх `TeeReader` ничего не сбросит,
а `recorder` вообще не закрывается.

### D2. Точки врезки в шлюзе

- `ServeHTTP` после `authorize()`: если трассировка включена — `rec :=
  tracer.Begin()`, в контекст и в `recorder` — **до** проверки предела тела,
  чтобы отказ `413` тоже получил `meta.json` и `client.response`. Тело
  читается целиком тем же кодом, что и для маскирования (`maskRequest`
  обобщается до `readBody`): `client.request` — сырое тело,
  `upstream.request` — то, что легло в `r.Body` после маскирования (или то
  же сырое). Отказ по `Content-Length` до чтения тела — единственный случай,
  когда `client.request` отсутствует: тело не читалось.
- `ModifyResponse`: сначала, **независимо от маскирования** (текущий
  ранний `return` при `maskState == nil` переносится ниже), если в контексте
  есть `Record` — `resp.Body` оборачивается: `TeeReader` в
  `rec.ResponseWriter(upstream)` с сохранением исходного `Close` через
  небольшую обёртку `readCloser{Reader, Closer}`. Затем — существующая
  обёртка демаскирования. Порядок: tee → unmask, файл получает байты
  апстрима как есть.
- `recorder.Write`: дублирует записанные клиенту байты в
  `rec.ResponseWriter(client)` — это уже демаскированный поток, а для
  ошибок самого шлюза (`writeError`) — их тело.
- `logAccess`: `rec.Finish(meta)` с методом, путём, статусом, меткой,
  длительностью, заголовками и `mask.Stats`.

Заголовки апстрима берутся в `Rewrite` (`pr.Out.Header` после зачистки) и
в `ModifyResponse` (`resp.Header`) — копируются в `rec` с редактированием.

### D3. Именование и формат

`<ts>-<seq>.<file>`: `ts` — `20060102T150405.000Z`, `seq` — `%06d` от
счётчика процесса. Пять файлов: `client.request`, `upstream.request`,
`upstream.response`, `client.response`, `meta.json`. Расширений `.json`
у тел нет намеренно: ответ может быть SSE, запрос при `open`-политике —
чем угодно.

`meta.json`:

```json
{
  "started": "2026-09-20T14:09:48.344Z", "duration_ms": 722,
  "method": "POST", "path": "/v1/messages", "status": 200, "token": "dev-team",
  "request_headers": {"Authorization": "<redacted>", "Anthropic-Version": "2023-06-01"},
  "upstream_headers": {"Content-Type": "text/event-stream"},
  "mask": {"masked": {"ip": 2, "host": 1}, "unmasked": 3, "errors": 0}
}
```

`mask` отсутствует, когда маскирование выключено.

### D4. Конфигурация

`config.Raw.TraceDir` / `Config.TraceDir`, флаг `--trace-dir`, переменная
`CLAUDE_PROXY_TRACE_DIR`. `validate()` не трогает файловую систему;
каталог создаёт `trace.New` в `server.RunReady` — ошибка до занятия
портов. `local` — без изменений. `install` — строка в `envLines`.

### D5. Редактирование заголовков

Критерий — заголовок несёт credential или сессию. Набор: `Authorization`,
`Proxy-Authorization`, `X-Api-Key`, `X-Gateway-Key`, `Cookie`, `Set-Cookie`
→ `<redacted>`. Остальное как есть: `anthropic-version`, `anthropic-beta`,
`content-type`, `x-request-id` — это и нужно для разбора. Query-строка в
`path` не пишется (`URL.Path`, не `RequestURI`).

## Risks / Trade-offs

- [Диск переполнен трассой] → режим отладочный, предупреждение на старте,
  документация: «включайте на время проверки». Ошибка записи не ломает
  запрос.
- [Тела с настоящими секретами на диске] → `0700`/`0600`, предупреждение,
  явный флаг. `install` каталог не создаёт — оператор решает, где ему
  лежать.
- [Чтение тела при выключенном маскировании меняет путь запроса] → только
  с `--trace-dir`; без него код не трогает `r.Body`. Тест «без каталога тело
  байт в байт» через апстрим-эхо.
- [Tee-writer замедляет стрим] → запись в файл буферизована (`bufio`),
  сброс на `Close`; медленный диск задержит клиента, что для отладки
  приемлемо.
- [Клиент ушёл посреди SSE] → `client.response` содержит то, что успели
  записать; `meta.json` со статусом 499 пишется как обычно из `logAccess`.

## Migration Plan

Функция выключена по умолчанию. Включение — переменная в
`EnvironmentFile`/`local.env`, перезапуск. Откат — убрать переменную,
каталог удалить руками.
