# Claude Code gateway — подробно

Режимы, источники сертификата, конфигурация, диагностика и эксплуатация.
Быстрый старт — в корневом [README.md](../README.md).

## Режимы

Выбираются флагом `--mode` (переменная `CLAUDE_PROXY_MODE`).

| | `oauth` | `apikey` |
|---|---|---|
| Оплата | подписка Pro/Max | по токенам, Console |
| Credential Anthropic | на клиентах | на шлюзе |
| Токен шлюза | заголовок `X-Gateway-Key` | заголовок `Authorization` |
| Что лежит на шлюзе | ничего от Anthropic | `sk-ant-api03-...` |
| Истекает | да, обновлять на каждом клиенте | нет |

Важное следствие выбора: в режиме `oauth` компрометация шлюза **не** даёт
доступа к вашему аккаунту Anthropic — он не хранит ни одного их credential'а.
В режиме `apikey` было бы наоборот.

Токен подписки (`sk-ant-oat01-`) работает только в `oauth`. В заголовке
`x-api-key` он не принимается никогда — для `apikey` нужен ключ Console
с префиксом `sk-ant-api03-`. Шлюз проверяет это на старте и отказывается
подниматься с перепутанными значениями.

## Конфигурация

Значения берутся из флагов и переменных окружения. **Переменная перебивает
флаг.** Порядок выбран под systemd: юнит настраивается через `EnvironmentFile`,
не трогая строку `ExecStart`. Если флаг был задан явно и перекрыт переменной,
шлюз пишет об этом предупреждение при старте — молчаливое игнорирование
флага слишком неожиданно.

| Флаг | Переменная | По умолчанию | Назначение |
|---|---|---|---|
| `--mode` | `CLAUDE_PROXY_MODE` | `oauth` | `oauth` или `apikey` |
| `--listen` | `CLAUDE_PROXY_LISTEN` | `:9443` | Адрес TLS-слушателя |
| `--domain` | `CLAUDE_PROXY_DOMAIN` | — | Имя шлюза; обязательно для `auto` и `self` |
| `--tokens` | `CLAUDE_PROXY_TOKENS` | — | Токены шлюза, см. ниже |
| `--api-key` | `CLAUDE_PROXY_ANTHROPIC_API_KEY` | — | Ключ Console, только для `apikey` |
| `--tls` | `CLAUDE_PROXY_TLS` | `auto` | `auto`, `files` или `self` |
| `--cert-file` | `CLAUDE_PROXY_CERT_FILE` | — | PEM с цепочкой, для `files` |
| `--key-file` | `CLAUDE_PROXY_KEY_FILE` | — | PEM с ключом, для `files` |
| `--acme-email` | `CLAUDE_PROXY_ACME_EMAIL` | — | Контакт для Let's Encrypt |
| `--acme-http` | `CLAUDE_PROXY_ACME_HTTP` | `:80` | Слушатель проверки HTTP-01 |
| `--acme-directory` | `CLAUDE_PROXY_ACME_DIRECTORY` | — | URL ACME; пусто — боевая LE |
| `--state-dir` | `CLAUDE_PROXY_STATE_DIR` | `/var/lib/claude-proxy` | Кэш ACME, самоподписанные пары |
| `--upstream` | `CLAUDE_PROXY_UPSTREAM` | `https://api.anthropic.com` | Куда проксировать |
| `--max-body` | `CLAUDE_PROXY_MAX_BODY` | `100m` | Предел тела запроса |
| `--log-format` | `CLAUDE_PROXY_LOG_FORMAT` | `text` | `text` или `json` |
| `--env-file` | — | у `install` и `client-env` — `/etc/claude-proxy/claude-proxy.env` | Файл, откуда брать переменные, если их нет в окружении |

Установленный сервис читает `/etc/claude-proxy/claude-proxy.env` (режим `600`).
После правки файла нужен `systemctl restart claude-proxy`.

### Токены шлюза

`--tokens` принимает список `метка:значение` через запятую:

```dotenv
CLAUDE_PROXY_TOKENS="dev-team:8f3a…,analytics:1c77…,ci:ab90…"
```

Метка нужна для двух вещей: она пишется в лог каждого запроса (само значение —
никогда), и по ней понятно, чей токен отзывать. Отзыв — удаление одного
элемента списка и рестарт; остальные команды продолжают работать.

Значение без метки получает метку `default`. Генерация:

```bash
claude-proxy gen-token --label dev-team
# dev-team:2f1c…
```

Только hex: значение подставляется в shell-команды на клиентах и в
`EnvironmentFile`, где спецсимволы пришлось бы экранировать.

Шлюз не стартует с пустым набором токенов — иначе он пропускал бы всех.

## Источники сертификата

### `auto` — встроенный ACME

Сертификат выпускается и продлевается самим процессом, кэш лежит в
`<state-dir>/acme`. Certbot, deploy-хуки и cron не нужны.

Проверка идёт по HTTP-01, поэтому порт 80 должен быть доступен из интернета —
и при первом выпуске, и при каждом продлении (примерно раз в два месяца).
Юнит получает `CAP_NET_BIND_SERVICE`, так что привилегированный порт занимается
без работы от root.

Подобрать конфигурацию, не расходуя лимит Let's Encrypt (5 выпусков на домен
в неделю), помогает staging-директория:

```bash
claude-proxy run --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory ...
```

Сертификаты оттуда недоверенные — это только для проверки самой схемы выпуска.
После перехода на боевую директорию очистите кэш: `rm -rf /var/lib/claude-proxy/acme`.

TLS-ALPN-01 шлюз не использует: эта проверка работает только на порту 443,
а шлюз слушает 9443.

### `files` — готовые PEM

Для внутреннего CA, DNS-01 или любого другого внешнего выпуска.

```bash
claude-proxy run --tls files \
  --cert-file /etc/letsencrypt/live/proxy.example.com/fullchain.pem \
  --key-file  /etc/letsencrypt/live/proxy.example.com/privkey.pem \
  --domain proxy.example.com
```

Файлы перечитываются автоматически, когда меняются на диске: проверка времени
модификации происходит не чаще раза в 5 секунд, при рукопожатии. После
`certbot renew` ни рестарта, ни сигнала не требуется. Если в момент проверки
файл недоступен (перезапись не атомарна), шлюз продолжает отдавать прежний
сертификат.

На старте шлюз проверяет, что имя из `--domain` есть в **subjectAltName**, и
предупреждает, если нет. Одного CN недостаточно: Node.js (а значит и Claude
Code) игнорирует CN и отдаёт `ERR_TLS_CERT_ALTNAME_INVALID`. Заодно
предупреждает, если до истечения осталось меньше двух недель.

Сертификаты обычно принадлежат root с правами `600` на ключ, а сервис работает
от пользователя `claude-proxy`. Установщик проверяет доступ и подсказывает
два выхода:

```bash
setfacl -m u:claude-proxy:r /etc/letsencrypt/live/proxy.example.com/privkey.pem
# или
sudo claude-proxy install --service-user root ...
```

#### Внутренний CA

Генерируем ключ и CSR, CSR отдаём в корпоративный УЦ:

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout privkey.pem \
  -out proxy.csr \
  -subj "/CN=claude-proxy.internal" \
  -addext "subjectAltName=DNS:claude-proxy.internal"
```

Из CA забираем подписанный сертификат и **собираем цепочку** — сначала
сертификат сервера, затем промежуточные:

```bash
cat proxy.crt intermediate-ca.crt > fullchain.pem
```

Порядок важен. Корневой сертификат в цепочку не добавляется — он должен быть
в доверенных на клиентах.

#### Let's Encrypt через DNS-01

Нужен, когда домен публичный, а входящий трафик на шлюз закрыт: валидация
идёт через TXT-запись, порты извне не требуются.

```bash
apt install certbot python3-certbot-dns-cloudflare
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /root/.secrets/cloudflare.ini \
  -d claude-proxy.example.com
```

Дальше `--tls files` с путями в `/etc/letsencrypt/live/...`. Цена варианта: на
хосте шлюза появляется API-токен от вашей DNS-зоны — выдавайте права только на
нужную зону.

### `self` — самоподписанный

Лаборатория и быстрая проверка схемы. При первом запуске пара генерируется
в `<state-dir>/self-signed` автоматически. Отдельно:

```bash
claude-proxy gen-cert --domain claude-proxy.internal --out-dir /opt/proxy-certs
```

Имя попадает в SAN: `DNS:` для доменного имени, `IP:` если передан адрес.
Ключ — ECDSA P-256, срок 825 дней, права на `privkey.pem` — `600`.

Для постоянной эксплуатации не годится: отозвать такой сертификат нечем,
а доверие раздаётся вручную.

### Доверие к сертификату на клиентах

Нужно для внутреннего CA и самоподписанного; для Let's Encrypt всё работает
из коробки.

Claude Code работает на Node.js, а Node **не использует** системное хранилище
сертификатов. Добавления CA в систему (`update-ca-certificates`, Keychain)
недостаточно — нужна переменная окружения:

```bash
export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/internal-ca.crt
```

Для внутреннего CA это его корневой сертификат, для самоподписанного — сам
`fullchain.pem` со шлюза. Файл должен быть в PEM.

Проверка:

```bash
node -e "require('https').get('https://claude-proxy.internal:9443/healthz',
  r => console.log(r.statusCode)).on('error', e => console.log(e.message))"
# 200 — доверие есть
# unable to verify the first certificate — цепочка неполна
# self-signed certificate — NODE_EXTRA_CA_CERTS не подхватился
```

Переменную нужно выставлять в том же окружении, где запускается `claude` —
пропишите её в профиль пользователя, а не разово в сессии.

## Настройка клиента, режим `apikey`

Отдельного заголовка нет — токен шлюза идёт в `Authorization`, а ключ
Anthropic подставляет сам шлюз:

```bash
export ANTHROPIC_BASE_URL=https://claude-proxy.internal:9443
export ANTHROPIC_AUTH_TOKEN=<GATEWAY_TOKEN>
unset ANTHROPIC_API_KEY
claude
```

Клиентская настройка режима `oauth` — в корневом README.

## Запуск в контейнере

Основной способ — бинарь под systemd. Образ нужен, если политика требует
контейнер:

```bash
docker run -d --name claude-proxy \
  -p 9443:9443 -p 80:8080 \
  -v claude-proxy-state:/var/lib/claude-proxy \
  -e CLAUDE_PROXY_DOMAIN=proxy.example.com \
  -e CLAUDE_PROXY_ACME_EMAIL=admin@example.com \
  -e CLAUDE_PROXY_TOKENS="dev:$(openssl rand -hex 32)" \
  ghcr.io/seredavin/claude-proxy:latest
```

Процесс в образе работает от непривилегированного пользователя и не может
занять порт 80, поэтому проверка HTTP-01 слушает `:8080` — снаружи её надо
пробрасывать именно с 80, как в примере. Том `/var/lib/claude-proxy` обязателен:
без него кэш ACME теряется при пересоздании контейнера и лимит выпусков
расходуется впустую.

## Переход с nginx-версии

Прежняя версия собиралась из `docker-compose.yml`, шаблонов nginx и
`install.sh`. Переход:

```bash
cd /opt/claude-proxy && docker compose down
curl -fsSLo /usr/local/bin/claude-proxy \
  https://github.com/seredavin/claude-proxy/releases/latest/download/claude-proxy-linux-amd64
chmod +x /usr/local/bin/claude-proxy

# Старый .env читается как есть: имена переменных распознаются.
sudo claude-proxy install --env-file /opt/claude-proxy/.env
```

Legacy-имена поддерживаются наравне с новыми: `GATEWAY_MODE`, `GATEWAY_TOKEN`,
`PROXY_SERVER_NAME`, `PROXY_CERTS_DIR` + `PROXY_SSL_CERT`/`PROXY_SSL_KEY`,
`ANTHROPIC_API_KEY`. `PROXY_SERVER_NAME=_` понимается как «имя не задано».
`GATEWAY_TOKEN` становится токеном с меткой `default`, так что клиентам
ничего перенастраивать не нужно.

Что изменилось по поведению:

- сертификат по умолчанию выпускается встроенным ACME; чтобы остаться на
  файлах от certbot, добавьте `--tls files` с путями из старого `.env`;
- deploy-хук certbot и `nginx -s reload` больше не нужны: файлы перечитываются
  автоматически;
- пустой `GATEWAY_TOKEN` раньше давал шлюз, пропускающий всех, — теперь это
  ошибка старта;
- непустой `ANTHROPIC_API_KEY` при `GATEWAY_MODE=oauth` тоже ошибка старта:
  в этом режиме ключ Console не используется, и лежать на шлюзе ему незачем.
  Уберите строку (или оставьте пустой) — прежний `install.sh` так и делал;
- `X-Forwarded-*` от клиента наверх не уходят;
- шлюз больше не запускается от root: юнит работает от пользователя
  `claude-proxy` с одной привилегией `CAP_NET_BIND_SERVICE`.

После проверки можно снести старое: `rm -rf /opt/claude-proxy`,
`docker image rm nginx:1.27-alpine`, `apt remove certbot`.

## Диагностика

**Тестировать только через CLI.** Anthropic ограничивает использование
OAuth-токенов сторонними клиентами: голый curl получит `Invalid bearer token`
даже при полностью исправной конфигурации, потому что не шлёт beta-заголовки,
которые добавляет CLI.

Три уровня отказа не пересекаются:

| Ответ | Где остановилось |
|---|---|
| `invalid gateway key` | шлюз, не совпал `X-Gateway-Key` (режим `oauth`) |
| `invalid gateway token` | шлюз, не совпал `Authorization` (режим `apikey`) |
| `missing oauth token` | шлюз, CLI не подхватил `ANTHROPIC_AUTH_TOKEN` |
| `api_error` + `gateway could not reach` | шлюз не достучался до Anthropic |
| `Invalid bearer token` + `request_id` | Anthropic, токен просрочен или отозван |

Быстрые проверки:

```bash
# 1. процесс жив, TLS терминируется
curl -k https://127.0.0.1:9443/healthz     # ok

# 2. сертификат отдаётся правильный и клиент ему доверяет
curl https://proxy.example.com:9443/healthz

# 3. исход наружу есть
curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/v1/messages
# 401 — сеть в порядке (Anthropic отверг запрос без ключа, но ответил)
# зависание или connection refused — исход закрыт
```

Вторая проверка без `-k` — именно она ловит несовпадение имени и недоверенный CA.

Логи:

```bash
journalctl -u claude-proxy -f
journalctl -u claude-proxy -n 50 --no-pager
```

Строка запроса содержит метку токена, статус, длительность и объём ответа.
Заголовков в ней нет умышленно: токен шлюза, `Authorization` и `x-api-key`
в логи не попадают.

### Известные грабли

**`Unable to connect to Anthropic services` / `ERR_BAD_REQUEST` на старте
CLI.** Клиент запущен с `CLAUDE_CODE_OAUTH_TOKEN`: в этом режиме часть
служебных запросов уходит напрямую на `api.anthropic.com` мимо
`ANTHROPIC_BASE_URL` и упирается в блокировку. Лечится подачей токена через
`ANTHROPIC_AUTH_TOKEN` и флагами `CLAUDE_CODE_*` — см. «Настройка клиента»
в корневом README.

**Флаг не действует.** Переменная окружения перебивает флаг. Шлюз пишет об
этом при старте строкой `флаг --X перекрыт переменной Y`; смотрите
`journalctl -u claude-proxy | head`.

**Сертификат не выпускается.** Проверьте, что порт 80 открыт снаружи и
A-запись указывает на этот хост. Лимит Let's Encrypt — 5 выпусков на домен
в неделю; отлаживайте на `--acme-directory` со staging.

**Windows-переводы строк в конфигурации.** Приклеивают `\r` к значению.
Шлюз отвергает токены с пробельными символами на старте; проверка:
`grep -c $'\r' /etc/claude-proxy/claude-proxy.env` должен вернуть 0.

**Сервис не читает сертификат.** В режиме `files` ключ обычно принадлежит
root с правами `600`. Смотрите «Источники сертификата → files».

## Эксплуатация

**Секреты на шлюзе.** В режиме `oauth` — только токены шлюза (ваши
собственные, отзываются правкой одной строки) и приватный ключ TLS. Токенов
Anthropic здесь нет: они проходят транзитом и в логи не пишутся.

**Ротация токенов шлюза.** Добавьте новый токен рядом со старым, раздайте
клиентам, затем уберите старый:

```bash
# /etc/claude-proxy/claude-proxy.env
CLAUDE_PROXY_TOKENS="dev-team:старый,dev-team-new:новый"
systemctl restart claude-proxy
```

Оба работают одновременно, поэтому окно перехода не требует простоя.

**Ротация токенов подписки.** Токен `setup-token` со временем истекает,
а обновить его изнутри сети без интернета нельзя — процедуру придётся
повторять на внешней машине и разносить по клиентам. Это цена подписочного
режима в изолированном контуре; режим `apikey` от неё избавлен.

**Обновление шлюза.** Скачать новый бинарь и переустановить: токены и
конфигурация сохраняются.

```bash
curl -fsSLo /tmp/claude-proxy https://github.com/seredavin/claude-proxy/releases/latest/download/claude-proxy-linux-amd64
chmod +x /tmp/claude-proxy
sudo /tmp/claude-proxy install
```

**Удаление.**

```bash
sudo claude-proxy uninstall          # снять сервис, конфигурацию оставить
sudo claude-proxy uninstall --purge  # снести всё, включая токены и кэш ACME
```

## Ключевые места реализации

- Немедленный сброс буфера (`FlushInterval = -1`) — без него ломается
  SSE-стриминг. На коротких ответах незаметно, проверяется запросом
  с `"stream":true`.
- Таймаут ожидания заголовков ответа 600s — на дефолтных 60s рвутся длинные
  генерации.
- Пауза внутри уже начатого ответа тоже ограничена 600s, и отсчёт начинается
  заново после каждого полученного байта. Это поведение `proxy_read_timeout`
  из nginx: длина стрима не ограничена, ограничено молчание в нём. Без такого
  предела соединение, замолчавшее без разрыва TCP (half-open, потеря маршрута),
  висело бы до перезапуска процесса.
- Заголовок `Host` подменяется на `api.anthropic.com`, иначе Anthropic не
  узнает свой виртуальный хост.
- Токен шлюза (`X-Gateway-Key` или `Authorization`) наверх не уходит.
- `X-Forwarded-*` от клиента отбрасываются и свои не добавляются: внутренняя
  топология наружу не утекает.
- Сравнение токенов идёт за постоянное время и перебирает весь список до
  конца — время ответа не зависит ни от позиции токена, ни от длины
  совпавшего префикса.
- `/` отвечает `200` без проверки ключа — это префлайт-зонд Claude Code при
  старте (идёт без `X-Gateway-Key`). Иначе CLI получает `401` и падает с
  «Unable to connect» до первого реального запроса.
- Ошибки отдаются в формате Anthropic API (`{"type":"error",…}`), чтобы клиент
  и диагностика разбирали их теми же средствами, что и ответы Anthropic.
- Исход наружу уважает `HTTPS_PROXY`/`NO_PROXY` — на случай, когда интернет
  доступен только через корпоративный прокси.
- Со стороны клиента ограничены заголовки (30s), простой соединения (120s) и
  размер тела, но не скорость его передачи: медленно «капающий» запрос держит
  горутину. Это осознанный компромисс — тело читается только после проверки
  токена, поэтому занять ресурсы так может лишь тот, у кого пропуск на шлюз
  уже есть.
