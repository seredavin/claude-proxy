Ветка `feature/add-request-trace` от актуального `main`; один PR, архив
в той же ветке.

## 1. Пакет `internal/trace`

- [x] 1.1 `trace.go`: `New(dir, opts)` — `MkdirAll` 0700, проверка записи
  пробным файлом, ошибка с путём; `Tracer` со счётчиком и логгером
- [x] 1.2 `Record`: `Begin()` с префиксом `<ts>-<seq>`; `WriteRequest(side,
  body)` в файл 0600; `ResponseWriter(side)` — `io.Writer` с `bufio`, файл
  открывается сразу при вызове (пустой ответ — пустой файл); `Finish(meta)`
  — закрывает все открытые writer'ы и пишет `meta.json`
- [x] 1.3 `Meta` с полями D3 и редактированием заголовков (D5):
  `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `X-Gateway-Key`,
  `Cookie`, `Set-Cookie` → `<redacted>`; путь без query
- [x] 1.4 Ошибки записи — `Warn` в лог, наружу не возвращаются
- [x] 1.5 Тесты: пять файлов с одним префиксом и правами 0600; ответ без
  байт даёт пустой файл; `Finish` сбрасывает буферы; редактирование
  заголовков; запись после
  удаления каталога даёт предупреждение и не ошибку; `New` на недоступном
  пути — ошибка с путём

## 2. Конфигурация и запуск

- [x] 2.1 `config.Raw`/`Config`: `TraceDir`; флаг `--trace-dir`, переменная
  `CLAUDE_PROXY_TRACE_DIR`; текст справки
- [x] 2.2 `server.RunReady`: при `cfg.TraceDir != ""` — `trace.New`,
  `Warn` о телах с секретами в каталоге, передача в `gateway.Options`
- [x] 2.3 `service.envLines`: `CLAUDE_PROXY_TRACE_DIR`, если задан
- [x] 2.4 Тесты: конфиг читает флаг и переменную; `envLines` с каталогом и
  без

## 3. Шлюз

- [x] 3.1 `gateway.Options.Tracer`; `ServeHTTP` после `authorize()` и до
  проверки предела тела — `Begin()`, запись в контекст и `recorder`
- [x] 3.2 Чтение тела обобщить: при трассировке или маскировании тело
  читается целиком; `client.request` — сырое, `upstream.request` — итоговое
  `r.Body`; для отвергнутого запроса `upstream.request` не пишется
- [x] 3.3 `Rewrite`: заголовки к апстриму в `Record`; `ModifyResponse`:
  ранний выход при выключенном маскировании убрать — сначала, независимо
  от маскирования, заголовки ответа и `resp.Body` через `TeeReader` в
  `upstream.response` с сохранением исходного `Close`, затем обёртка
  демаскирования
- [x] 3.4 `recorder.Write` дублирует байты в `client.response`; `logAccess`
  зовёт `Finish(meta)` с `mask.Stats`, если маскирование включено
- [x] 3.5 Тесты шлюза: без `--trace-dir` тело байт в байт и файлов нет; с
  трассировкой и маскированием — четыре тела показывают до/после;
  без маскирования копии запроса совпадают, и `upstream.response` пишется;
  отвергнутый `closed`-запрос — три файла и статус 400 в meta; отказ по
  `Content-Length` — `meta` со статусом 413 без `client.request`; пустой
  ответ апстрима — пустые файлы ответов; `Authorization` в meta
  `<redacted>`, путь без query; SSE доходит до конца ответа (тест с
  `release`-каналом как у существующего)

## 4. Документация и проверка

- [x] 4.1 `docs/advanced.md`: раздел «Трассировка запросов» после
  «Маскирование» — зачем, состав файлов, пример проверки маскирования
  (`diff client.request upstream.request`), предупреждение; строка в
  таблице конфигурации
- [x] 4.2 `README.md`: упоминание в списке возможностей рядом с маскированием
- [x] 4.3 `make check` зелёный; ручной прогон `local` с `--trace-dir` и
  `--mask-rules`: в `upstream.request` суррогаты, в `client.response`
  настоящие значения
