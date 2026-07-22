# Claude Code gateway — подробно

Режимы, ручная установка, диагностика и эксплуатация. Быстрый старт — в
корневом [README.md](../README.md).

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

## Ручная установка

Автоматический путь (`curl ... | sudo bash` для публичного домена с открытым
портом 80) описан в корневом README. Ниже — установка по шагам: нужна для
сценариев DNS-01, внутреннего CA и самоподписанного сертификата, а также
когда запускать скачанный по сети код от root нежелательно.

Тот же автоскрипт в два шага, с возможностью прочитать, что запускается:

```bash
git clone git@github.com:seredavin/claude-proxy.git
cd claude-proxy
sudo ./install.sh --domain proxy.example.com --email admin@example.com
```

Для режима `apikey` добавьте `--mode apikey --api-key sk-ant-api03-...`.
Без аргументов скрипт спросит недостающее интерактивно, `--help` покажет
все опции.

Скрипт идемпотентен: повторный запуск не перевыпускает действующий
сертификат и сохраняет прежний `GATEWAY_TOKEN` — его уже могли разнести
по клиентам. Прежний `.env` сохраняется как `.env.bak`.

Требуется root, Debian/Ubuntu или RHEL/Fedora. Скрипт меняет состояние
хоста: подключает репозиторий Docker, ставит пакеты, пишет в
`/opt/proxy-certs` и `/etc/letsencrypt/renewal-hooks/`.

### Шаг 0. Предварительные условия

На хосте прокси:

* Docker Engine и плагин Compose (`docker compose version`)
* Разрешённый исход на `api.anthropic.com:443` — проверяется до всего
  остального, иначе диагностика на шаге 5 будет вводить в заблуждение:

  ```bash
  curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/v1/messages
  # 401 — сеть в порядке (Anthropic отверг запрос без ключа, но ответил)
  # зависание или connection refused — исход закрыт, дальше идти бессмысленно
  ```
* Свободный порт `9443`, доступный из внутренней сети

На клиентах: имя прокси должно резолвиться (внутренний DNS или `/etc/hosts`).

### Шаг 1. Выбор имени

Имя, по которому клиенты будут обращаться к прокси, должно совпадать в трёх
местах, иначе TLS не соберётся:

1. `PROXY_SERVER_NAME` в `.env`
2. CN/SAN сертификата
3. `ANTHROPIC_BASE_URL` на клиентах

От выбора имени зависит и способ получить сертификат: для публичного домена
(`claude-proxy.example.com`) доступен Let's Encrypt, для внутреннего
(`claude-proxy.internal`) — только собственный CA или самоподписанный.

### Шаг 2. Сертификат

Нужны два PEM-файла: цепочка (сертификат + промежуточные) и приватный ключ.
Ниже четыре способа — выберите один.

Проверить готовый сертификат перед запуском:

```bash
openssl x509 -in fullchain.pem -noout -subject -ext subjectAltName -dates
```

Имя из шага 1 должно быть в **subjectAltName**. Одного CN недостаточно:
Node.js (а значит и Claude Code) игнорирует CN и проверяет только SAN —
сертификат без него даст `ERR_TLS_CERT_ALTNAME_INVALID`.

#### Вариант A. Let's Encrypt, DNS-01

Публичный домен, но входящий трафик на прокси закрыт. Валидация идёт через
TXT-запись в DNS, порты извне не нужны — единственный вариант LE для хоста
в DMZ без входящих правил.

```bash
# пример для Cloudflare; плагины есть для большинства провайдеров
apt install certbot python3-certbot-dns-cloudflare

install -m 600 /dev/null /root/.secrets/cloudflare.ini
cat > /root/.secrets/cloudflare.ini <<'EOF'
dns_cloudflare_api_token = <API-ТОКЕН С ПРАВОМ ПРАВКИ ЗОНЫ>
EOF

certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d claude-proxy.example.com
```

Цена варианта: на хосте прокси появляется API-токен от вашей DNS-зоны.
Выдавайте его правами только на нужную зону.

Домену необязательно резолвиться в адрес прокси — LE проверяет владение
зоной, а не доступность хоста. Внутренние клиенты могут ходить по
split-horizon DNS на приватный адрес.

#### Вариант B. Let's Encrypt, HTTP-01

Публичный домен и доступный из интернета порт 80. Проще всего, но требует
входящего правила — часто несовместимо с политикой DMZ.

```bash
apt install certbot
certbot certonly --standalone -d claude-proxy.example.com
```

Порт 80 нужен только на время выпуска и продления. Если на хосте уже висит
веб-сервер — используйте `--webroot -w /var/www/html` вместо `--standalone`.

#### Вариант C. Внутренний CA

Корпоративный удостоверяющий центр, имя вида `claude-proxy.internal`.
Генерируем ключ и CSR, CSR отдаём в CA:

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout privkey.pem \
  -out proxy.csr \
  -subj "/CN=claude-proxy.internal" \
  -addext "subjectAltName=DNS:claude-proxy.internal"
```

Из CA забираем подписанный сертификат и **собираем цепочку** — сначала
сертификат сервера, затем промежуточные CA:

```bash
cat proxy.crt intermediate-ca.crt > fullchain.pem
```

Порядок важен. Корневой сертификат в цепочку не добавляется — он должен
быть в доверенных на клиентах.

Клиентам понадобится корневой CA — см. «Доверие к сертификату на клиентах».

#### Вариант D. Самоподписанный

Лаборатория и быстрая проверка схемы. Для постоянной эксплуатации не
годится: отозвать такой сертификат нечем, а доверие раздаётся вручную.

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout privkey.pem -out fullchain.pem -days 365 \
  -subj "/CN=claude-proxy.internal" \
  -addext "subjectAltName=DNS:claude-proxy.internal"
```

Если клиенты ходят по IP, SAN должен быть `IP:10.0.0.5`, а не `DNS:`.

Клиентам понадобится сам этот файл — см. следующий раздел.

### Шаг 3. Размещение файлов

```bash
mkdir -p /opt/proxy-certs
cp fullchain.pem privkey.pem /opt/proxy-certs/
chmod 600 /opt/proxy-certs/privkey.pem
chmod 644 /opt/proxy-certs/fullchain.pem
```

nginx читает сертификаты мастер-процессом от root до сброса привилегий,
поэтому `600` на ключе ему не мешает.

**Для Let's Encrypt есть нюанс.** В `/etc/letsencrypt/live/<домен>/` лежат
не файлы, а симлинки в `../../archive/`. Смонтировать только каталог `live`
нельзя — внутри контейнера симлинки укажут в пустоту, и nginx не стартует.
Два решения:

*Смонтировать весь `/etc/letsencrypt`* — `PROXY_SSL_CERT` может содержать
подпуть:

```dotenv
PROXY_CERTS_DIR=/etc/letsencrypt
PROXY_SSL_CERT=live/claude-proxy.example.com/fullchain.pem
PROXY_SSL_KEY=live/claude-proxy.example.com/privkey.pem
```

*Либо копировать в `/opt/proxy-certs` deploy-хуком* при каждом продлении —
тогда переменные остаются дефолтными (см. «Эксплуатация»).

### Шаг 4. Конфигурация

```bash
cp .env.example .env
$EDITOR .env
```

Заполнить: `GATEWAY_MODE`, `PROXY_SERVER_NAME` (имя из шага 1),
пути к сертификатам (шаг 3), `GATEWAY_TOKEN`. В режиме `apikey` —
ещё и `ANTHROPIC_API_KEY`.

`GATEWAY_TOKEN` генерируется на хосте прокси:

```bash
openssl rand -hex 32
```

Только hex — значение подставляется через `envsubst` прямо в текст
nginx-конфига, и спецсимволы его сломают.

### Шаг 5. Запуск и проверка

```bash
chmod +x docker-entrypoint.d/10-select-mode.sh
docker compose up -d
docker compose logs --tail=30
```

Здоровый старт содержит:

```
10-select-mode.sh: using 'oauth' mode
20-envsubst-on-templates.sh: Running envsubst on ...
start worker processes
```

Три проверки по возрастанию охвата:

```bash
# 1. nginx жив, TLS терминируется
curl -k https://127.0.0.1:9443/healthz     # ok

# 2. сертификат отдаётся правильный и клиент ему доверяет
curl https://claude-proxy.example.com:9443/healthz

# 3. запрос доходит до Anthropic (в access-логе upstream=401, а не upstream=-)
docker compose logs --tail=5 claude-proxy
```

Вторая проверка без `-k` — именно она ловит несовпадение имени и
недоверенный CA. Полный тест с реальным запросом делается только через CLI,
см. «Диагностика».

### Доверие к сертификату на клиентах

Нужно для вариантов C и D — для Let's Encrypt всё работает из коробки.

Claude Code работает на Node.js, а Node **не использует** системное
хранилище сертификатов. Добавления CA в систему (`update-ca-certificates`,
Keychain) недостаточно — нужна переменная окружения:

```bash
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/internal-ca.crt
```

Для варианта C это корневой сертификат вашего CA, для варианта D — сам
`fullchain.pem` с прокси. Файл должен быть в PEM.

Проверка, что доверие настроено:

```bash
node -e "require('https').get('https://claude-proxy.internal:9443/healthz',
  r => console.log(r.statusCode)).on('error', e => console.log(e.message))"
# 200 — доверие есть
# unable to verify the first certificate — цепочка неполна (см. вариант C)
# self-signed certificate — NODE_EXTRA_CA_CERTS не подхватился
```

Переменную нужно выставлять в том же окружении, где запускается `claude` —
пропишите её в профиль пользователя, а не разово в сессии.

## Настройка клиента, режим `apikey`

Отдельного заголовка нет — `GATEWAY_TOKEN` идёт в `Authorization`, а ключ
Anthropic подставляет сам прокси:

```bash
export ANTHROPIC_BASE_URL=https://claude-proxy.internal:9443
export ANTHROPIC_AUTH_TOKEN=<GATEWAY_TOKEN>
unset ANTHROPIC_API_KEY
claude
```

Клиентская настройка режима `oauth` — в корневом README.

## Диагностика

**Тестировать только через CLI.** Anthropic ограничивает использование
OAuth-токенов сторонними клиентами: голый curl получит `Invalid bearer token`
даже при полностью исправной конфигурации, потому что не шлёт beta-заголовки,
которые добавляет CLI.

Три уровня отказа не пересекаются:

| Ответ | Где остановилось |
|---|---|
| `invalid gateway key` | nginx, не совпал `X-Gateway-Key` |
| `missing oauth token` | nginx, CLI не подхватил `ANTHROPIC_AUTH_TOKEN` |
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

**`Unable to connect to Anthropic services` / `ERR_BAD_REQUEST` на старте
CLI.** Клиент запущен с `CLAUDE_CODE_OAUTH_TOKEN`: в этом режиме часть
служебных запросов уходит напрямую на `api.anthropic.com` мимо
`ANTHROPIC_BASE_URL` и упирается в блокировку. Лечится подачей токена через
`ANTHROPIC_AUTH_TOKEN` и флагами `CLAUDE_CODE_*` — см. «Настройка клиента»
в корневом README.

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

Чтобы это происходило само, повесьте deploy-hook на certbot. Если вы
монтируете `/etc/letsencrypt` целиком, хватит одного reload:

```bash
certbot renew --deploy-hook \
  "docker compose -f /root/claude-proxy/docker-compose.yml exec -T claude-proxy nginx -s reload"
```

Если сертификаты копируются в `/opt/proxy-certs` (см. шаг 3), хук должен
сначала копировать, потом перезагружать. Положите его файлом
`/etc/letsencrypt/renewal-hooks/deploy/claude-proxy.sh` с `chmod +x` —
тогда он отработает при любом `certbot renew`, в том числе из systemd-таймера:

```bash
#!/bin/sh
set -e
install -m 644 "$RENEWED_LINEAGE/fullchain.pem" /opt/proxy-certs/fullchain.pem
install -m 600 "$RENEWED_LINEAGE/privkey.pem"   /opt/proxy-certs/privkey.pem
docker compose -f /root/claude-proxy/docker-compose.yml exec -T claude-proxy nginx -s reload
```

Проверить, что продление отработает, не дожидаясь срока:

```bash
certbot renew --dry-run
```

Для варианта D (самоподписанный) автопродления нет — сертификат придётся
перевыпускать руками и заново раздавать клиентам. Ещё один довод не
использовать его дольше, чем для проверки схемы.

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
- `location = /` отвечает `200` без проверки ключа — это префлайт-зонд Claude
  Code при старте (идёт без `X-Gateway-Key`). Иначе CLI получает `401` и падает
  с «Unable to connect» до первого реального запроса.
- `log_format proxy_fmt` не пишет заголовки — токены не попадают в логи.
- `map` вместо прямого сравнения — точка расширения на случай, если
  понадобятся разные токены для разных команд.
