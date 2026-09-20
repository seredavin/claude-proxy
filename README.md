# Claude Code gateway

Reverse proxy, дающий Claude Code доступ к Anthropic из сети без прямого
интернета. Один статический бинарь: сам шлюз, ACME-клиент и установщик
systemd-сервиса. Ни Docker, ни nginx, ни certbot не нужны.

## Архитектура

Шлюз терминирует TLS от внутренних клиентов и открывает **отдельное**
соединение к `api.anthropic.com`. Это две независимые TLS-сессии, а не
инкапсуляция — с точки зрения сетевых политик обычный L7-прокси, не туннель
и не forward-proxy с CONNECT.

```
внутренняя сеть            граница (DMZ)          интернет
  Claude Code  ──TLS №1──>  claude-proxy  ──TLS №2──>  api.anthropic.com
                              :9443
```

Хост со шлюзом должен видеть внутреннюю сеть и иметь разрешённый исход
на `api.anthropic.com:443`. Это единственное требование, которое решается
не софтом, а сетевой политикой.

Токен подписки Anthropic (`sk-ant-oat01-`) живёт **на клиентах**, не на
шлюзе: его компрометация не даёт доступа к вашему аккаунту. Про режимы,
источники сертификата, диагностику и эксплуатацию —
[docs/advanced.md](docs/advanced.md).

## Установка

Публичный домен, A-запись на этот хост и открытый из интернета порт 80
(нужен для проверки Let's Encrypt — и при первом выпуске, и при продлении).

```bash
curl -fsSLo claude-proxy \
  https://github.com/seredavin/claude-proxy/releases/latest/download/claude-proxy-linux-amd64
chmod +x claude-proxy

sudo ./claude-proxy install \
  --domain proxy.example.com \
  --acme-email admin@example.com
```

Установщик разложит бинарь в `/usr/local/bin`, заведёт системного
пользователя, сгенерирует токен шлюза, напишет `/etc/claude-proxy/claude-proxy.env`
и юнит, запустит сервис и напечатает готовый набор переменных для клиента —
с уже подставленным токеном.

Сертификат выпускается и продлевается самим процессом; cron и хуки не нужны.

Другие сценарии — внутренний CA, самоподписанный сертификат, готовые PEM от
certbot, цепочка из нескольких шлюзов, локальное звено без TLS на машине с
Claude Code, запуск в контейнере — в [docs/advanced.md](docs/advanced.md).

## Получение токена подписки

Токен получается на машине с интернетом — в вашем обычном Claude Code:

```bash
claude setup-token
```

Значение вида `sk-ant-oat01-...`. Браузерный `/login` изнутри изолированной
сети не отработает: он ходит на `claude.ai`, а шлюз обслуживает только
`api.anthropic.com`.

## Настройка клиента (целевая машина)

```bash
export ANTHROPIC_BASE_URL=https://proxy.example.com:9443
export ANTHROPIC_CUSTOM_HEADERS="X-Gateway-Key: <GATEWAY_TOKEN>"
export ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-...
# служебный трафик Claude Code (проверка fast mode, телеметрия) идёт напрямую
# на api.anthropic.com мимо шлюза — в изолированной сети его надо отключить,
# иначе CLI падает на старте:
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK=1
export CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS=1
unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY
claude
```

Этот же блок печатает `claude-proxy client-env` на хосте шлюза.

Два критичных момента:

- **Токен идёт через `ANTHROPIC_AUTH_TOKEN`, а не `CLAUDE_CODE_OAUTH_TOKEN`.**
  Значение то же, но `CLAUDE_CODE_OAUTH_TOKEN` переводит CLI в режим «залогинен
  по подписке» и заставляет часть служебных запросов идти напрямую на Anthropic
  мимо `ANTHROPIC_BASE_URL` — в сети без интернета это `ERR_BAD_REQUEST` на
  старте. Тот же токен как `Authorization: Bearer` на base URL работает через
  шлюз; Anthropic принимает `sk-ant-oat01-` и в этом заголовке.
- **Порт в `ANTHROPIC_BASE_URL` обязателен** — без него Node пойдёт на 443.

Если на клиенте раньше выполнялся `/login`, сделайте `/logout` — сохранённые
креды конфликтуют с переменными окружения.

## Команды

| Команда | Что делает |
|---|---|
| `claude-proxy run` | Запустить шлюз (команда по умолчанию) |
| `claude-proxy install` | Установить и запустить systemd-сервис |
| `claude-proxy uninstall` | Снять сервис; `--purge` — вместе с конфигурацией и состоянием |
| `claude-proxy gen-token` | Сгенерировать токен шлюза |
| `claude-proxy gen-cert` | Выпустить самоподписанный сертификат |
| `claude-proxy client-env` | Напечатать переменные для клиентской машины |
| `claude-proxy version` | Показать версию |

Режим `apikey`, несколько токенов, доверие к самоподписанным сертификатам,
переход с прежней nginx-версии и диагностика — в
[docs/advanced.md](docs/advanced.md).
