# Claude Code gateway

Reverse proxy, дающий Claude Code доступ к Anthropic из сети без интернета.

nginx терминирует TLS от внутренних клиентов и открывает **отдельное**
соединение к `api.anthropic.com`. Это две независимые TLS-сессии, а не
инкапсуляция — с точки зрения сетевых политик это обычный L7-прокси,
не туннель и не forward-proxy с CONNECT.

```
внутренняя сеть            граница (DMZ)          интернет
  Claude Code  ──TLS №1──>  claude-proxy  ──TLS №2──>  api.anthropic.com
                              :9443
```

Хост с контейнером должен видеть внутреннюю сеть и иметь разрешённый
исход на `api.anthropic.com:443`. Это единственное требование, которое
решается не софтом, а сетевой политикой.

## Режимы

Выбираются переменной `GATEWAY_MODE`, каждому соответствует свой шаблон
nginx в `templates-available/`.

| | `oauth` | `apikey` |
|---|---|---|
| Оплата | подписка Pro/Max | по токенам, Console |
| Credential Anthropic | на клиентах | на прокси |
| Токен шлюза | заголовок `X-Gateway-Key` | заголовок `Authorization` |
| Что лежит на прокси | ничего от Anthropic | `sk-ant-api03-...` |
| Истекает | да, обновлять на каждом клиенте | нет |

Текущая конфигурация — `oauth`.

Важное следствие выбора: в режиме `oauth` компрометация прокси **не** даёт
доступа к вашему аккаунту Anthropic — он не хранит ни одного их credential'а.
В режиме `apikey` было бы наоборот.

Токен подписки (`sk-ant-oat01-`) работает только в `oauth`. В заголовке
`x-api-key` он не принимается никогда — для `apikey` нужен ключ Console
с префиксом `sk-ant-api03-`.

## Состав

```
~/claude-proxy/
├── docker-compose.yml
├── .env                            <- секреты, не в git
├── .env.example                    <- шаблон, коммитится
├── .gitignore
├── templates-available/
│   ├── oauth.conf.template
│   └── apikey.conf.template
└── docker-entrypoint.d/
    └── 10-select-mode.sh           <- нужен chmod +x

/opt/proxy-certs/                   <- путь задаётся PROXY_CERTS_DIR
├── fullchain.pem
└── privkey.pem
```

Запускать `docker compose` только из каталога проекта — пути к шаблонам
относительные. Оба шаблона держите на месте: скрипт выбирает нужный при
старте и падает с внятной ошибкой, если файла нет.

### Переменные окружения

| Переменная | Обязательна | По умолчанию | Назначение |
|---|---|---|---|
| `GATEWAY_MODE` | нет | `apikey` | `oauth` или `apikey` |
| `GATEWAY_TOKEN` | да | — | Пропуск на сам шлюз |
| `ANTHROPIC_API_KEY` | только в `apikey` | — | Ключ Console |
| `PROXY_SERVER_NAME` | нет | `_` | Имя из сертификата (`_` — любое) |
| `PROXY_CERTS_DIR` | нет | `/opt/proxy-certs` | Каталог с сертификатами на хосте |
| `PROXY_SSL_CERT` | нет | `fullchain.pem` | Имя файла сертификата |
| `PROXY_SSL_KEY` | нет | `privkey.pem` | Имя файла ключа |

В режиме `apikey` контейнер не стартует без `ANTHROPIC_API_KEY` и
`GATEWAY_TOKEN` — проверка в `10-select-mode.sh`. В режиме `oauth` такой
проверки нет: пустой `GATEWAY_TOKEN` даст шлюз, пропускающий всех с пустым
заголовком. Задавайте его всегда.

### Как собирается конфиг

Официальный образ nginx выполняет скрипты из `/docker-entrypoint.d/` по
алфавиту. Наш `10-select-mode.sh` копирует нужный шаблон в
`/etc/nginx/templates/default.conf.template`, затем штатный
`20-envsubst-on-templates.sh` подставляет переменные окружения и кладёт
результат в `/etc/nginx/conf.d/default.conf`.

Отсюда важное: правки в `.env` и шаблонах применяются **пересозданием**
контейнера, а не `nginx -s reload` — reload не запускает entrypoint.

```bash
docker compose up -d --force-recreate
```

## Развёртывание

```bash
cp .env.example .env
$EDITOR .env
chmod +x docker-entrypoint.d/10-select-mode.sh
docker compose up -d
docker compose logs --tail=30
```

`GATEWAY_TOKEN` генерируется на хосте прокси:

```bash
openssl rand -hex 32
```

Здоровый старт содержит:

```
10-select-mode.sh: using 'oauth' mode
20-envsubst-on-templates.sh: Running envsubst on ...
start worker processes
```

Проверка:

```bash
curl -k https://127.0.0.1:9443/healthz     # ok
```

## Настройка клиента

### Режим `oauth`

```bash
export ANTHROPIC_BASE_URL=https://claude-proxy.internal:9443
export ANTHROPIC_CUSTOM_HEADERS="X-Gateway-Key: <GATEWAY_TOKEN>"
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY
claude
```

Порт в `ANTHROPIC_BASE_URL` обязателен — без него Node пойдёт на 443.

Токен подписки получается на машине с интернетом:

```bash
claude setup-token
```

Браузерный `/login` изнутри изолированной сети не отработает: он ходит на
`claude.ai`, а прокси обслуживает только `api.anthropic.com`.

Если на клиенте раньше выполнялся `/login`, сделайте `/logout` — сохранённые
креды конфликтуют с переменными окружения при заданном `ANTHROPIC_BASE_URL`.

### Режим `apikey`

Отдельного заголовка нет — `GATEWAY_TOKEN` идёт в `Authorization`, а ключ
Anthropic подставляет сам прокси:

```bash
export ANTHROPIC_BASE_URL=https://claude-proxy.internal:9443
export ANTHROPIC_AUTH_TOKEN=<GATEWAY_TOKEN>
unset ANTHROPIC_API_KEY
claude
```

## Диагностика

**Тестировать только через CLI.** Anthropic ограничивает использование
OAuth-токенов сторонними клиентами: голый curl получит `Invalid bearer token`
даже при полностью исправной конфигурации, потому что не шлёт beta-заголовки,
которые добавляет CLI.

Три уровня отказа не пересекаются:

| Ответ | Где остановилось |
|---|---|
| `invalid gateway key` | nginx, не совпал `X-Gateway-Key` |
| `missing oauth token` | nginx, CLI не подхватил `CLAUDE_CODE_OAUTH_TOKEN` |
| `Invalid bearer token` + `request_id` | Anthropic, токен просрочен или отозван |

В access-логе поле `upstream` показывает, дошло ли до Anthropic:
`upstream=-` — отказ на прокси, `upstream=401` — отказ на той стороне.

По тексту ошибки видно и загруженный шаблон: `Invalid bearer token` — режим
`oauth`, `invalid x-api-key` — режим `apikey`.

Что реально попало в конфиг:

```bash
docker compose exec claude-proxy cat /etc/nginx/conf.d/default.conf
```

Вывод содержит подставленные секреты — никуда его не пересылайте.

`docker compose logs` без `--tail` показывает историю с самого начала;
легко принять прошлый запуск за текущий.

Строки `SIGCHLD` и `unknown process exited with code 0` — это healthcheck
раз в 30 секунд, не ошибка.

### Известные грабли

**`10-select-mode.sh` смонтирован как каталог.** Docker создаёт пустой
каталог, если файла bind-mount'а нет на хосте. В логе тогда не будет ни
запуска скрипта, ни строки `not executable` — просто тишина, а nginx
поднимется на дефолтном конфиге. Проверка: `ls -l` должен показать
`-rwxr-xr-x`, а не `drwxr-xr-x`.

**`could not build map_hash`.** Токен из `openssl rand -hex 32` длиннее
дефолтного бакета. Лечится строкой `map_hash_bucket_size 128;` перед `map` —
она уже есть в шаблоне.

**Windows-переводы строк в `.env`.** Приклеивают `\r` к значению.
Проверка: `grep -c $'\r' .env` должен вернуть 0.

**Спецсимволы в `GATEWAY_TOKEN`.** Значение подставляется через `envsubst`
прямо в текст nginx-конфига. Hex из `openssl rand` безопасен; произвольная
строка с `"`, `$` или `;` сломает конфиг или изменит его смысл.

## Эксплуатация

**Секреты на прокси.** В режиме `oauth` — только `GATEWAY_TOKEN` (ваш
собственный, отзывается правкой одной строки) и `privkey.pem`. Токенов
Anthropic здесь нет: они проходят транзитом и в логи не пишутся.

**Обновление сертификата.** nginx читает файлы один раз при старте. После
`certbot renew` нужен reload — процесс не перезапускается, соединения не
рвутся:

```bash
docker compose exec claude-proxy nginx -s reload
```

Deploy-hook: `--deploy-hook "docker compose -f /root/claude-proxy/docker-compose.yml exec -T claude-proxy nginx -s reload"`

Обратите внимание на асимметрию: сертификат подхватывается через reload,
а изменения в `.env` — только через `--force-recreate`.

**Ротация токенов подписки.** Токен `setup-token` со временем истекает,
а обновить его изнутри сети без интернета нельзя — процедуру придётся
повторять на внешней машине и разносить по клиентам. Это цена подписочного
режима в изолированном контуре; режим `apikey` от неё избавлен.

## Ключевые места конфигурации

- `proxy_buffering off` — без него ломается SSE-стриминг. На коротких
  ответах незаметно, проверяется запросом с `"stream":true`.
- Таймауты 600s — на дефолтных 60s рвутся длинные генерации.
- `proxy_pass https://$upstream$request_uri` через переменную плюс
  `resolver` — заставляет перечитывать DNS. Без переменной nginx резолвит
  IP один раз при старте и однажды молча отвалится.
- `proxy_set_header X-Gateway-Key ""` — токен шлюза не уходит наверх.
- `log_format proxy_fmt` не пишет заголовки — токены не попадают в логи.
- `map` вместо прямого сравнения — точка расширения на случай, если
  понадобятся разные токены для разных команд.
