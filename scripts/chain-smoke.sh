#!/usr/bin/env bash
# Сквозная проверка цепочки шлюзов на настоящих бинарях.
#
# Поднимает заглушку вместо Anthropic и два звена шлюза, после чего гоняет
# запросы через внутреннее звено. В отличие от тестов пакета gateway здесь
# работает боевой транспорт: сертификат следующего звена проверяется по
# системным корням, а доверие к самоподписанному приезжает через
# SSL_CERT_FILE — ровно так, как описано в docs/advanced.md.
#
# Только Linux: на macOS Go читает системную связку ключей, а SSL_CERT_FILE
# игнорирует, поэтому проверить эту схему там невозможно.
set -euo pipefail

BIN=${BIN:-./claude-proxy}
STUB_PORT=${STUB_PORT:-19445}   # «Anthropic»
EDGE_PORT=${EDGE_PORT:-19444}   # звено B, у интернета
INNER_PORT=${INNER_PORT:-19443} # звено A, внутреннее
EDGE_TOKEN=edge-token
INNER_TOKEN=inner-token

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: проверка требует Linux (SSL_CERT_FILE работает только там)"
    exit 0
fi

WORK=$(mktemp -d)
STUB_PID=""
EDGE_PID=""
INNER_PID=""

cleanup() {
    local code=$?
    for pid in "$INNER_PID" "$EDGE_PID" "$STUB_PID"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    if (( code != 0 )); then
        for log in "$WORK"/*.log; do
            [[ -f "$log" ]] || continue
            echo "===== $(basename "$log") ====="
            cat "$log"
        done
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Снимает последнее фоновое задание с учёта: иначе bash при остановке
# печатает «Terminated» вместе с телом heredoc заглушки.
hush() {
    disown %% 2>/dev/null || true
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Ждёт, пока звено начнёт отвечать на /healthz.
wait_ready() {
    local port=$1 name=$2
    for _ in $(seq 50); do
        if curl -sk --max-time 1 "https://127.0.0.1:$port/healthz" | grep -q ok; then
            return 0
        fi
        sleep 0.2
    done
    fail "$name не поднялся на порту $port"
}

# Ждёт, пока процесс действительно завершится: пока он жив, порт занят.
wait_gone() {
    local pid=$1 name=$2
    for _ in $(seq 50); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    fail "$name не завершилось после SIGTERM"
}

# Запускает внутреннее звено. Прежнее сначала гасится и дожидается выхода:
# иначе порт ещё занят и новое звено не поднимется.
start_inner() {
    local name=$1; shift
    if [[ -n "$INNER_PID" ]]; then
        kill "$INNER_PID" 2>/dev/null || true
        wait_gone "$INNER_PID" "звено A"
    fi
    "$BIN" run --tls files \
        --cert-file "$WORK/fullchain.pem" --key-file "$WORK/privkey.pem" \
        --listen "127.0.0.1:$INNER_PORT" --tokens "client:$INNER_TOKEN" \
        --upstream "https://127.0.0.1:$EDGE_PORT" \
        "$@" >"$WORK/$name.log" 2>&1 &
    INNER_PID=$!
    hush
    wait_ready "$INNER_PORT" "звено A"
}

# Запрос через внутреннее звено. Печатает код ответа, тело кладёт в файл.
request() {
    curl -s -o "$WORK/body" -w '%{http_code}' \
        --cacert "$WORK/fullchain.pem" --max-time 10 \
        "https://127.0.0.1:$INNER_PORT/v1/messages" -d '{}' "$@"
}

# Проверяет, что заголовок дошёл до «Anthropic».
want_header() {
    if ! grep -q "$1" "$WORK/body"; then
        fail "в запросе до Anthropic нет $1: $(cat "$WORK/body")"
    fi
}

# Проверяет, что заголовок до «Anthropic» НЕ дошёл.
deny_header() {
    if grep -q "$1" "$WORK/body"; then
        fail "до Anthropic утёк $1: $(cat "$WORK/body")"
    fi
}

echo "==> Сертификат для 127.0.0.1"
"$BIN" gen-cert --domain 127.0.0.1 --out-dir "$WORK" >/dev/null

# Доверие к самоподписанному сертификату — как на хосте звена A.
export SSL_CERT_FILE="$WORK/fullchain.pem"

echo "==> Заглушка вместо Anthropic на :$STUB_PORT"
python3 - "$WORK" "$STUB_PORT" >"$WORK/stub.log" 2>&1 <<'PY' &
import http.server, json, ssl, sys

work, port = sys.argv[1], int(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    """Отвечает JSON со всеми полученными заголовками."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{work}/fullchain.pem", f"{work}/privkey.pem")
srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
STUB_PID=$!
hush

echo "==> Звено B (oauth) на :$EDGE_PORT"
"$BIN" run --tls files \
    --cert-file "$WORK/fullchain.pem" --key-file "$WORK/privkey.pem" \
    --mode oauth --listen "127.0.0.1:$EDGE_PORT" --tokens "edge:$EDGE_TOKEN" \
    --upstream "https://127.0.0.1:$STUB_PORT" >"$WORK/edge.log" 2>&1 &
EDGE_PID=$!
hush
wait_ready "$EDGE_PORT" "звено B"

echo "--> цепочка oauth -> oauth"
start_inner inner-oauth --mode oauth --upstream-key "$EDGE_TOKEN"
code=$(request -H "X-Gateway-Key: $INNER_TOKEN" -H "Authorization: Bearer sk-ant-oat01-smoke")
[[ "$code" == 200 ]] || fail "код $code вместо 200: $(cat "$WORK/body")"
want_header sk-ant-oat01-smoke
deny_header x-gateway-key
echo "    ok токен подписки прошёл два звена, пропуски наверх не ушли"

echo "--> неверный пропуск на звено B"
start_inner inner-wrong --mode oauth --upstream-key wrong-token
code=$(request -H "X-Gateway-Key: $INNER_TOKEN" -H "Authorization: Bearer sk-ant-oat01-smoke")
[[ "$code" == 401 ]] || fail "код $code вместо 401: звено B обязано отвергать чужой пропуск"
grep -q 'invalid gateway key' "$WORK/body" || fail "не та ошибка: $(cat "$WORK/body")"
echo "    ok звено B отвергает чужой пропуск"

echo "--> цепочка apikey -> oauth"
start_inner inner-apikey --mode apikey --api-key sk-ant-api03-smoke --upstream-key "$EDGE_TOKEN"
code=$(request -H "Authorization: Bearer $INNER_TOKEN")
[[ "$code" == 200 ]] || fail "код $code вместо 200: $(cat "$WORK/body")"
want_header sk-ant-api03-smoke
deny_header authorization
echo "    ok ключ Console внутреннего звена дошёл через внешнее"

echo "==> Цепочка работает"
