# Claude Code gateway

Reverse proxy, дающий Claude Code доступ к Anthropic из сети без прямого
интернета.

## Архитектура

nginx терминирует TLS от внутренних клиентов и открывает **отдельное**
соединение к `api.anthropic.com`. Это две независимые TLS-сессии, а не
инкапсуляция — с точки зрения сетевых политик обычный L7-прокси, не туннель
и не forward-proxy с CONNECT.

```
внутренняя сеть            граница (DMZ)          интернет
  Claude Code  ──TLS №1──>  claude-proxy  ──TLS №2──>  api.anthropic.com
                              :9443
```

Хост с контейнером должен видеть внутреннюю сеть и иметь разрешённый исход
на `api.anthropic.com:443`. Это единственное требование, которое решается
не софтом, а сетевой политикой.

Токен подписки Anthropic (`sk-ant-oat01-`) живёт **на клиентах**, не на
прокси: его компрометация не даёт доступа к вашему аккаунту. Про режимы,
ручную установку, диагностику и эксплуатацию — [docs/advanced.md](docs/advanced.md).

## Установка

Публичный домен и открытый из интернета порт 80. Скрипт доставит Docker и
certbot, выпустит сертификат Let's Encrypt, сгенерирует `GATEWAY_TOKEN`,
соберёт `.env` и поднимет контейнер:

```bash
curl -fsSL https://raw.githubusercontent.com/seredavin/claude-proxy/main/bootstrap.sh \
  | sudo bash -s -- --domain proxy.example.com --email admin@example.com
```

По завершении скрипт печатает готовый набор переменных для клиента — с уже
подставленным токеном шлюза.

Другие сценарии (DNS-01, внутренний CA, самоподписанный сертификат, установка
по шагам без запуска скачанного кода от root) — в [docs/advanced.md](docs/advanced.md).

## Получение токена подписки

Токен получается на машине с интернетом — в вашем обычном Claude Code:

```bash
claude setup-token
```

Значение вида `sk-ant-oat01-...`. Браузерный `/login` изнутри изолированной
сети не отработает: он ходит на `claude.ai`, а прокси обслуживает только
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

Режим `apikey`, доверие к самоподписанным сертификатам и диагностика — в
[docs/advanced.md](docs/advanced.md).
