#!/usr/bin/env bash
#
# Установка claude-proxy: зависимости, сертификат Let's Encrypt (HTTP-01),
# конфигурация и запуск контейнера.
#
# Скрипт идемпотентен — повторный запуск не выпускает сертификат заново
# и не перезаписывает существующий GATEWAY_TOKEN.
#
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# apt должен работать молча. DEBIAN_FRONTEND глушит debconf, но не needrestart:
# тот после обновления libcurl/libssl показывает диалог «какие сервисы
# перезапустить» и ждёт ввода. NEEDRESTART_MODE=a перезапускает их сам.
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

readonly CERTS_DIR=/opt/proxy-certs
readonly HOOK_PATH=/etc/letsencrypt/renewal-hooks/deploy/claude-proxy.sh

DOMAIN=""
EMAIL=""
MODE="oauth"
API_KEY=""
ASSUME_YES=0
SKIP_DNS_CHECK=0

# --- вывод ------------------------------------------------------------------

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mОшибка:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Установка claude-proxy — TLS-шлюза к Anthropic API.

Использование:
  sudo ./install.sh --domain proxy.example.com --email admin@example.com [опции]

Обязательные:
  --domain <fqdn>     Публичное имя прокси. Должно резолвиться в адрес
                      этого хоста — иначе Let's Encrypt не выдаст сертификат.
  --email <адрес>     Контакт для Let's Encrypt (уведомления об истечении).

Опции:
  --mode <oauth|apikey>   Режим шлюза. По умолчанию oauth.
  --api-key <ключ>        Ключ Console (sk-ant-api03-...). Только для apikey.
  --yes                   Не задавать вопросов, брать значения из флагов.
  --skip-dns-check        Не проверять, что домен указывает на этот хост.
  --help                  Эта справка.

Требования: root, Debian/Ubuntu или RHEL/Fedora, открытый из интернета
порт 80 (нужен только на время выпуска и продления сертификата).
EOF
}

# --- разбор аргументов ------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)          DOMAIN="${2:-}"; shift 2 ;;
        --email)           EMAIL="${2:-}"; shift 2 ;;
        --mode)            MODE="${2:-}"; shift 2 ;;
        --api-key)         API_KEY="${2:-}"; shift 2 ;;
        --yes|-y)          ASSUME_YES=1; shift ;;
        --skip-dns-check)  SKIP_DNS_CHECK=1; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 usage >&2; die "неизвестный аргумент: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "нужны права root: sudo $0 ..."

# Интерактивный доспрос только если есть терминал и не задан --yes.
ask() {
    local prompt="$1" varname="$2" flag="$3" value=""
    if [ -n "${!varname}" ]; then return 0; fi
    if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then
        die "не задан обязательный параметр $flag (см. --help)"
    fi
    read -r -p "$prompt" value
    printf -v "$varname" '%s' "$value"
    [ -n "${!varname}" ] || die "пустое значение"
}

ask "Домен прокси (например proxy.example.com): " DOMAIN --domain
ask "Email для Let's Encrypt: " EMAIL --email

case "$MODE" in
    oauth) ;;
    apikey)
        ask "Ключ Anthropic Console (sk-ant-api03-...): " API_KEY --api-key
        case "$API_KEY" in
            sk-ant-api03-*) ;;
            sk-ant-oat01-*) die "это токен подписки, он работает только в режиме oauth" ;;
            *) warn "ключ не похож на ключ Console (ожидается префикс sk-ant-api03-)" ;;
        esac
        ;;
    *) die "недопустимый --mode '$MODE' (ожидается oauth или apikey)" ;;
esac

[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
    || die "'$DOMAIN' не похож на FQDN (для кириллических доменов укажите punycode: xn--...)"
if [[ "$DOMAIN" =~ ^[0-9.]+$ ]]; then
    die "Let's Encrypt не выдаёт сертификаты на IP-адреса, нужно доменное имя"
fi

# --- шаг 1: предварительные проверки ----------------------------------------

log "Проверка окружения"

[ -f "$SCRIPT_DIR/docker-compose.yml" ] \
    || die "docker-compose.yml не найден рядом со скриптом — запускайте из каталога проекта"

# Исход на Anthropic. Без него всё остальное бессмысленно, а симптомы
# проявятся только на этапе реального запроса и будут выглядеть иначе.
# Нас устраивает любой HTTP-ответ: 401 без ключа означает, что связь есть.
anthropic_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
    https://api.anthropic.com/v1/messages 2>/dev/null)" || anthropic_code=000
if [ "$anthropic_code" != 000 ]; then
    ok "api.anthropic.com доступен (HTTP $anthropic_code)"
else
    warn "не удалось достучаться до api.anthropic.com:443"
    warn "проверьте сетевую политику — прокси не заработает без исхода наружу"
fi

# HTTP-01 требует, чтобы публичный DNS указывал на этот хост.
if [ "$SKIP_DNS_CHECK" -eq 0 ]; then
    resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')" || true
    # Локальный резолвер может не видеть запись (кэш, свой DNS, dynamic DNS),
    # а Let's Encrypt смотрит публичный. Поэтому при пустом ответе спрашиваем
    # публичные резолверы и падаем только если запись не видит вообще никто.
    if [ -z "$resolved" ] && command -v dig >/dev/null 2>&1; then
        for ns in 1.1.1.1 8.8.8.8; do
            resolved="$(dig +short +time=5 +tries=1 "@$ns" "$DOMAIN" A 2>/dev/null \
                | grep -m1 -E '^[0-9.]+$')" || true
            [ -n "$resolved" ] && break
        done
        [ -n "$resolved" ] && warn "$DOMAIN виден в публичном DNS ($resolved), но не резолвится на этом хосте"
    fi
    public_ip="$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null)" || true
    if [ -z "$resolved" ]; then
        die "$DOMAIN не резолвится. Для HTTP-01 нужна A-запись на этот хост (обойти: --skip-dns-check)"
    elif [ -n "$public_ip" ] && [ "$resolved" != "$public_ip" ]; then
        warn "$DOMAIN резолвится в $resolved, а внешний адрес хоста — $public_ip"
        warn "если это не NAT, выпуск сертификата не пройдёт (обойти: --skip-dns-check)"
    else
        ok "$DOMAIN -> $resolved"
    fi
fi

# certbot --standalone поднимает свой слушатель на 80; занятый порт его сломает.
if command -v ss >/dev/null 2>&1; then
    listening="$(ss -lnt 2>/dev/null | awk 'NR>1{print $4}')"
elif command -v netstat >/dev/null 2>&1; then
    listening="$(netstat -lnt 2>/dev/null | awk 'NR>2{print $4}')"
else
    listening=""
    warn "нет ни ss, ни netstat — занятость портов 80 и 9443 не проверена"
fi

if printf '%s\n' "$listening" | grep -qE '(^|[:.])80$'; then
    die "порт 80 занят. Освободите его на время выпуска сертификата или используйте --webroot вручную"
fi
if printf '%s\n' "$listening" | grep -qE '(^|[:.])9443$'; then
    warn "порт 9443 уже занят — если это не старый claude-proxy, контейнер не поднимется"
fi

# --- шаг 2: зависимости -----------------------------------------------------

log "Установка зависимостей"

if command -v apt-get >/dev/null 2>&1; then
    PKG=apt
elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf
else
    die "поддерживаются только apt и dnf; поставьте docker, docker compose и certbot вручную"
fi

install_docker() {
    log "Ставлю Docker из официального репозитория"
    if [ "$PKG" = apt ]; then
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg
        install -m 0755 -d /etc/apt/keyrings
        # --max-time обязателен: без него на отфильтрованной сети curl висит вечно.
        curl -fsSL --connect-timeout 10 --max-time 60 \
            "https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg" \
            | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg \
            || die "не удалось получить ключ download.docker.com — репозиторий недоступен с этого хоста"
        chmod a+r /etc/apt/keyrings/docker.gpg
        cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") $(. /etc/os-release && echo "$VERSION_CODENAME") stable
EOF
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        dnf install -y -q dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null \
            || dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/centos/docker-ce.repo
        dnf install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
    systemctl enable --now docker
}

if ! command -v docker >/dev/null 2>&1; then
    install_docker
elif ! docker compose version >/dev/null 2>&1; then
    warn "docker есть, но нет плагина compose — доставляю"
    install_docker
fi
docker compose version >/dev/null 2>&1 || die "docker compose так и не заработал"
systemctl is-active --quiet docker || systemctl start docker
ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

if ! command -v certbot >/dev/null 2>&1; then
    log "Ставлю certbot"
    if [ "$PKG" = apt ]; then
        apt-get install -y -qq certbot
    else
        dnf install -y -q certbot
    fi
fi
ok "certbot $(certbot --version 2>&1 | awk '{print $2}')"

# --- шаг 3: сертификат ------------------------------------------------------

log "Сертификат Let's Encrypt для $DOMAIN"

LINEAGE="/etc/letsencrypt/live/$DOMAIN"

if [ -d "$LINEAGE" ] && openssl x509 -in "$LINEAGE/fullchain.pem" -noout -checkend 2592000 2>/dev/null; then
    ok "действующий сертификат уже есть, выпуск пропущен"
else
    # --standalone поднимает временный сервер на 80 и гасит его после проверки.
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        --keep-until-expiring \
        -d "$DOMAIN" \
        || die "certbot не смог выпустить сертификат. Частые причины: порт 80 закрыт снаружи, A-запись указывает не сюда, исчерпан лимит LE (5 выпусков на домен в неделю)"
    ok "сертификат выпущен"
fi

# Копируем из lineage в отдельный каталог: в live/ лежат симлинки в archive/,
# и bind-mount только live/ внутри контейнера указывал бы в пустоту.
install -d -m 755 "$CERTS_DIR"
install -m 644 "$LINEAGE/fullchain.pem" "$CERTS_DIR/fullchain.pem"
install -m 600 "$LINEAGE/privkey.pem"   "$CERTS_DIR/privkey.pem"
ok "сертификаты разложены в $CERTS_DIR"

# --- шаг 4: автопродление ---------------------------------------------------

log "Настройка автопродления"

install -d -m 755 "$(dirname "$HOOK_PATH")"
cat > "$HOOK_PATH" <<EOF
#!/bin/sh
# Обновляет копии сертификатов для claude-proxy и перечитывает их в nginx.
# Создан install.sh, правки при переустановке будут перезаписаны.
set -e
[ "\$RENEWED_LINEAGE" = "$LINEAGE" ] || exit 0
install -m 644 "\$RENEWED_LINEAGE/fullchain.pem" "$CERTS_DIR/fullchain.pem"
install -m 600 "\$RENEWED_LINEAGE/privkey.pem"   "$CERTS_DIR/privkey.pem"
docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T claude-proxy nginx -s reload
EOF
chmod +x "$HOOK_PATH"
ok "deploy-hook: $HOOK_PATH"

if systemctl list-timers 2>/dev/null | grep -q certbot; then
    ok "таймер certbot активен"
else
    warn "systemd-таймер certbot не найден — добавьте продление в cron:"
    warn "  0 3 * * * certbot renew --quiet"
fi

# --- шаг 5: конфигурация ----------------------------------------------------

log "Конфигурация"

ENV_FILE="$SCRIPT_DIR/.env"

# Токен шлюза переживает переустановку: его уже могли разнести по клиентам.
GATEWAY_TOKEN=""
if [ -f "$ENV_FILE" ]; then
    GATEWAY_TOKEN="$(awk -F= '/^GATEWAY_TOKEN=/{print $2; exit}' "$ENV_FILE")"
    case "$GATEWAY_TOKEN" in
        ""|REPLACE_ME*) GATEWAY_TOKEN="" ;;
    esac
    cp -a "$ENV_FILE" "$ENV_FILE.bak"
    warn "прежний .env сохранён как .env.bak"
fi

if [ -n "$GATEWAY_TOKEN" ]; then
    ok "GATEWAY_TOKEN сохранён из прежнего .env"
else
    GATEWAY_TOKEN="$(openssl rand -hex 32)"
    ok "GATEWAY_TOKEN сгенерирован"
fi

umask 077
cat > "$ENV_FILE" <<EOF
# Создано install.sh $(date +%Y-%m-%d)

# apikey | oauth
GATEWAY_MODE=$MODE

# Имя, на которое выписан сертификат (или _ для любого)
PROXY_SERVER_NAME=$DOMAIN

# Сертификаты: каталог на хосте и имена файлов внутри него
PROXY_CERTS_DIR=$CERTS_DIR
PROXY_SSL_CERT=fullchain.pem
PROXY_SSL_KEY=privkey.pem

# --- только для GATEWAY_MODE=apikey ---
# Настоящий ключ Anthropic. Живёт ТОЛЬКО здесь, на хосте прокси.
ANTHROPIC_API_KEY=$API_KEY

# Токен, который будут предъявлять внутренние клиенты.
GATEWAY_TOKEN=$GATEWAY_TOKEN
EOF
umask 022
ok "записан $ENV_FILE (режим 600)"

chmod +x "$SCRIPT_DIR/docker-entrypoint.d/10-select-mode.sh"

# --- шаг 6: запуск ----------------------------------------------------------

log "Запуск контейнера"

cd "$SCRIPT_DIR"
docker compose up -d --force-recreate

# Первый старт занимает несколько секунд: healthcheck имеет start_period 10s.
for i in $(seq 1 30); do
    if curl -ksS -o /dev/null --max-time 3 https://127.0.0.1:9443/healthz 2>/dev/null; then
        ok "прокси отвечает на /healthz"
        break
    fi
    [ "$i" -eq 30 ] && {
        docker compose logs --tail=30 claude-proxy >&2
        die "контейнер не ответил за 30 секунд — логи выше"
    }
    sleep 1
done

# Проверка без -k: ловит несовпадение имени и битую цепочку.
if curl -fsS -o /dev/null --max-time 10 "https://$DOMAIN:9443/healthz" 2>/dev/null; then
    ok "TLS-цепочка валидна по имени $DOMAIN"
else
    warn "с хоста не удалось проверить https://$DOMAIN:9443/ — возможно, имя не резолвится изнутри"
    warn "проверьте с клиентской машины"
fi

# --- итог -------------------------------------------------------------------

cat <<EOF

$(log "Готово")

Настройка клиента:

  export ANTHROPIC_BASE_URL=https://$DOMAIN:9443
EOF

if [ "$MODE" = oauth ]; then
    cat <<EOF
  export ANTHROPIC_CUSTOM_HEADERS="X-Gateway-Key: $GATEWAY_TOKEN"
  export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...   # получить: claude setup-token
  unset ANTHROPIC_AUTH_TOKEN ANTHROPIC_API_KEY
EOF
else
    cat <<EOF
  export ANTHROPIC_AUTH_TOKEN=$GATEWAY_TOKEN
  unset ANTHROPIC_API_KEY
EOF
fi

cat <<EOF

Токен шлюза выведен выше и лежит в $ENV_FILE — это секрет,
передавайте клиентам защищённым каналом.

Логи:   docker compose -f $SCRIPT_DIR/docker-compose.yml logs -f
Рестарт: docker compose -f $SCRIPT_DIR/docker-compose.yml up -d --force-recreate
EOF
