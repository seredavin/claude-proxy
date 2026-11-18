## 1. Ветка и конфигурация

- [x] 1.1 Создать ветку `feature/add-upstream-routes` от актуального main
- [x] 1.2 `internal/config`: поля `UpstreamRoutes`/`UpstreamRouteKeys` в `Raw`,
  `bindings` (флаги `--upstream-routes`, `--upstream-route-keys`; env
  `CLAUDE_PROXY_UPSTREAM_ROUTES`, `CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS`)
- [x] 1.3 `internal/config`: тип `Route{Label, Upstream, Key}`, разбор списков
  «метка=значение» и сборка `Config.Routes` в `Resolve`
- [x] 1.4 `internal/config`: валидация — URL маршрута `https://host`, метки
  существуют в токенах, ключи ссылаются на маршруты, повтор метки, ключ
  маршрута при `api.anthropic.com` (переиспользовать `isAnthropicHost`),
  ключи без маршрутов — отказ
- [x] 1.5 Тесты конфигурации: разбор, приоритет env над флагом, все отказы,
  пустые списки не меняют поведения

## 2. Шлюз

- [x] 2.1 `internal/gateway`: `Options.Routes`, дефолтный маршрут из
  `Upstream`/`UpstreamKey`, map «метка → маршрут» при сборке
- [x] 2.2 `internal/gateway`: маршрут в контексте запроса после `authorize`,
  выбор `SetURL`/`Host`/`X-Gateway-Key` в `Rewrite`; без маршрута — прежнее
  поведение
- [x] 2.3 `internal/gateway`: хост апстрима в access-лог при заданных
  маршрутах; тесты: запрос по маршруту, токен без маршрута, Host и
  X-Gateway-Key наверху, ключа нет — заголовка нет, оба режима
- [x] 2.4 `internal/server`: проброс `Routes` в шлюз, маршруты в стартовом
  логе; тест при необходимости

## 3. Трасса и локальное звено

- [x] 3.1 `internal/trace`: поле `Upstream` в `Meta`; шлюз пишет его при
  заданных маршрутах; тест meta.json
- [x] 3.2 `local.go`: звено в цепочке при ключе маршрута метки первого
  токена; строка запуска печатает хост маршрута; тесты planLocal

## 4. Установщик и документация

- [x] 4.1 `internal/service`: запись `CLAUDE_PROXY_UPSTREAM_ROUTES` и
  `CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS` в `EnvironmentFile` при заданности;
  тесты записи и переноса при переустановке
- [x] 4.2 `docs/advanced.md`: раздел «Маршруты по меткам токенов» — синтаксис,
  пример с двумя звеньями, наблюдаемость; строка в таблице флагов
- [x] 4.3 `README.md`: пункт в «Возможности»

## 5. Проверка

- [x] 5.1 `make check` зелёный; при необходимости расширить smoke-сценарий
  маршрутом через второе звено
- [x] 5.2 Прогнать спеки по сценариям, отметить выполнение; `openspec validate`
