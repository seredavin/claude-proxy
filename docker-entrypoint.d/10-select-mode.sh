#!/bin/sh
set -e

MODE="${GATEWAY_MODE:-apikey}"
SRC="/etc/nginx/templates-available/${MODE}.conf.template"

if [ ! -f "$SRC" ]; then
    echo "10-select-mode.sh: unknown GATEWAY_MODE='${MODE}' (expected apikey|oauth)" >&2
    exit 1
fi

if [ "$MODE" = "apikey" ]; then
    [ -n "$ANTHROPIC_API_KEY" ] || { echo "ANTHROPIC_API_KEY is required in apikey mode" >&2; exit 1; }
    [ -n "$GATEWAY_TOKEN" ]     || { echo "GATEWAY_TOKEN is required in apikey mode" >&2; exit 1; }
fi

mkdir -p /etc/nginx/templates
cp "$SRC" /etc/nginx/templates/default.conf.template
echo "10-select-mode.sh: using '${MODE}' mode"
