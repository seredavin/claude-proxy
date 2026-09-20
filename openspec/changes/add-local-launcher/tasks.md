Ветка `feature/local-launcher` от `feature/plain-listener` (зависимость:
`--tls none`). PR — после мержа `add-plain-listener` в `main`, с перебазой
на него. Архивация — процессный шаг после мержа, в задачах не числится.

## 1. Готовность слушателя и переменные парами

- [ ] 1.1 `server.RunReady(ctx, cfg, log, ready func(net.Addr)) error`:
  `ready` зовётся после успешного `net.Listen` основного слушателя с его
  адресом; `Run` = `RunReady(…, nil)`, поведение и сигнатура `Run` прежние
- [ ] 1.2 `clientenv.Var{Name, Value string; Unset bool}` и
  `Vars(cfg, token) []Var`; `Render` печатает их (`export`/`unset`) и
  выдаёт байт в байт прежний текст для `oauth` и `apikey`
- [ ] 1.3 Тест `RunReady`: с `127.0.0.1:0` и `--tls none` `ready` получает
  адрес с ненулевым портом, `/healthz` по нему отвечает `200`, после отмены
  `ctx` порт свободен
- [ ] 1.4 Тест `Vars`/`Render`: существующие тесты `Render` проходят без
  правок; `Vars` для `oauth` содержит `Unset` для `CLAUDE_CODE_OAUTH_TOKEN`
  и `ANTHROPIC_API_KEY`

## 2. Пакет `launcher`

- [ ] 2.1 `internal/launcher`: `Options{Config, Logger, Token, AuthToken,
  ClaudePath, ClaudeArgs, Stdin/Stdout/Stderr, Environ}` и
  `Run(ctx, Options) (exitCode int, err error)`: звено через
  `server.RunReady` в горутине → ожидание `ready` (или ошибки звена) →
  окружение из `clientenv.Vars` с копией `cfg` (`Listen` = фактический
  адрес) поверх `Environ` → `exec.Command` с наследованием потоков →
  ожидание
- [ ] 2.2 Сигналы: `signal.Notify` на `SIGINT`/`SIGTERM` на время жизни
  ребёнка; `SIGINT` игнорируется, `SIGTERM` пересылается ребёнку; после
  выхода ребёнка — отмена `ctx` звена и ожидание его возврата
- [ ] 2.3 Завершение: код выхода ребёнка возвращается как есть (сигнал —
  `1`); ошибка звена до готовности — возврат ошибки без запуска ребёнка;
  ошибка звена при живом ребёнке — `SIGTERM` ребёнку, ожидание, возврат
  ошибки звена
- [ ] 2.4 Тесты `launcher` с `/bin/sh -c` вместо `claude` и заглушкой
  апстрима: окружение ребёнка (`ANTHROPIC_BASE_URL` с фактическим портом,
  `X-Gateway-Key` с пропуском, `ANTHROPIC_AUTH_TOKEN`, отсутствие
  `CLAUDE_CODE_OAUTH_TOKEN`/`ANTHROPIC_API_KEY`, сторонняя переменная
  сохранена); аргументы доходят; код выхода `3` возвращается как `3`;
  запрос ребёнка через звено доходит до заглушки с верным `X-Gateway-Key`
- [ ] 2.5 Тест сигналов: ребёнок `sh`, ждущий `sleep`; `SIGINT` запускателю
  не гасит звено (`/healthz` жив, ребёнок жив); `SIGTERM` запускателю
  завершает ребёнка и звено; ребёнок получает `SIGINT` от запускателя и
  завершается (диспозиция не унаследована)
- [ ] 2.6 Тест падения звена: заставить звено вернуть ошибку при живом
  ребёнке (закрыть слушатель) — ребёнок завершён, `Run` вернул ошибку

## 3. Команда `local`

- [ ] 3.1 `cmdLocal` в `main.go`: `config.Bind`, `--env-file` (умолчание
  `$XDG_CONFIG_HOME/claude-proxy/local.env` или
  `~/.config/claude-proxy/local.env`), `--claude` (умолчание `claude`),
  `--log-file` (умолчание `$XDG_STATE_HOME/claude-proxy/local.log` или
  `~/.local/state/claude-proxy/local.log`); `raw.TLS = "none"` и
  `raw.Listen = "127.0.0.1:0"` до `ApplyEnv`, чтобы файл и окружение
  могли переопределить адрес, а `--tls` из окружения — отвергнуть с
  ошибкой, если не `none`
- [ ] 3.2 Пропуск: если после `ApplyEnv` `raw.Tokens` пуст —
  `local:<auth.Generate()>`; затем `config.Resolve`; `claude` уходит первый
  из набора
- [ ] 3.3 Отказы до старта звена: пустой `UpstreamKey` — текст про цепочку
  и оба параметра; `oauth` без `ANTHROPIC_AUTH_TOKEN` (через тот же
  `Getenv` с учётом файла) — текст с `claude setup-token`; `--claude` не
  находится через `exec.LookPath` — текст с путём поиска и флагом
- [ ] 3.4 Логгер в файл: `MkdirAll` каталога, `O_APPEND|O_CREATE|0600`,
  формат по `--log-format`; строка на stderr перед запуском —
  `локальное звено http://<адрес> → <апстрим>, лог: <путь>`; остаток
  `fs.Args()` — аргументы `claude`
- [ ] 3.5 `dispatch`: `case "local"`; `usage`: строка про `local`; справка
  флагов — `--claude`, `--log-file`, `--env-file` с их умолчаниями
- [ ] 3.6 Тесты `cmdLocal`-уровня (табличные, без запуска `claude`):
  `--tls self` из окружения отвергается; отсутствие `--upstream-key` и
  `ANTHROPIC_AUTH_TOKEN` дают ожидаемые тексты; `--listen 0.0.0.0:9443`
  отвергается ошибкой `--tls none`; пропуск генерируется, когда не задан

## 4. Проверка на стенде

- [ ] 4.1 Вручную на ноутбуке: `local.env` с реальным внешним шлюзом;
  `claude-proxy local` открывает `claude`, запрос проходит; `Ctrl+C` внутри
  `claude` не роняет звено; выход из `claude` освобождает порт; лог в
  `~/.local/state/claude-proxy/local.log`

## 5. Документация

- [ ] 5.1 `docs/advanced.md`, «Локальное звено на ноутбуке»: раздел
  переписать вокруг `claude-proxy local` — `local.env` (три переменные,
  права `0600`), запуск, передача аргументов, `--listen` для отладки,
  лог; ручной способ через `run --tls none` — как справочный подраздел
- [ ] 5.2 `docs/advanced.md`: строка `local` в перечне команд (если есть)
  и флаги `--claude`, `--log-file` в таблице конфигурации или отдельной
  таблице команды
- [ ] 5.3 `README.md`: фраза про `claude-proxy local` в сценарии
  «локальное звено без TLS»

## 6. Финал

- [ ] 6.1 `make check` зелёный (gofmt, vet, тесты); `go vet` не ругается
  на `SysProcAttr`/сигналы под darwin и linux
- [ ] 6.2 Перебаза на `main` после мержа `add-plain-listener`; PR в `main`,
  сообщение коммита на русском
