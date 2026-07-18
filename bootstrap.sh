#!/usr/bin/env bash
#
# Загрузчик claude-proxy для запуска через curl:
#
#   curl -fsSL https://raw.githubusercontent.com/seredavin/claude-proxy/main/bootstrap.sh \
#     | sudo bash -s -- --domain proxy.example.com --email admin@example.com
#
# Забирает репозиторий в /opt/claude-proxy и передаёт управление install.sh.
# Всё тело обёрнуто в main() и вызывается последней строкой: при обрыве
# загрузки скрипт не выполнится частично, а просто не дойдёт до вызова.
#
set -euo pipefail

main() {
    local repo="${CLAUDE_PROXY_REPO:-https://github.com/seredavin/claude-proxy.git}"
    local ref="${CLAUDE_PROXY_REF:-main}"
    local dir="${CLAUDE_PROXY_DIR:-/opt/claude-proxy}"
    local tarball="https://codeload.github.com/seredavin/claude-proxy/tar.gz/refs/heads"

    red()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
    blue() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

    if [ "$(id -u)" -ne 0 ]; then
        red "Нужны права root. Добавьте sudo:"
        red "  curl -fsSL .../bootstrap.sh | sudo bash -s -- --domain ... --email ..."
        exit 1
    fi

    command -v curl >/dev/null 2>&1 || { red "не найден curl"; exit 1; }

    blue "Получаю claude-proxy ($ref) в $dir"

    if command -v git >/dev/null 2>&1; then
        if [ -d "$dir/.git" ]; then
            # Повторный запуск: подтягиваем ref, не трогая .env с секретами.
            git -C "$dir" fetch --quiet --depth 1 origin "$ref"
            git -C "$dir" checkout --quiet FETCH_HEAD
        else
            if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
                red "$dir существует, не пуст и не является git-репозиторием"
                exit 1
            fi
            git clone --quiet --depth 1 --branch "$ref" "$repo" "$dir"
        fi
    else
        # Без git — тарболом. .env при этом не перезаписывается: его нет в архиве.
        blue "git не найден, качаю архивом"
        mkdir -p "$dir"
        curl -fsSL "$tarball/$ref.tar.gz" | tar -xz -C "$dir" --strip-components=1 \
            || { red "не удалось скачать архив — репозиторий приватный или ref '$ref' не существует"; exit 1; }
    fi

    [ -f "$dir/install.sh" ] || { red "install.sh не найден в $dir — репозиторий получен не полностью"; exit 1; }
    chmod +x "$dir/install.sh"

    # При запуске через пайп stdin занят телом скрипта, и install.sh не сможет
    # ничего спросить. Если терминал доступен — возвращаем ему ввод.
    # Безопасно только потому, что после main() ничего не читается (см. низ файла).
    if [ ! -t 0 ] && [ -e /dev/tty ] && exec </dev/tty 2>/dev/null; then
        :
    fi

    blue "Запускаю install.sh"
    exec "$dir/install.sh" "$@"
}

# Вызов и выход одной строкой: bash не станет дочитывать файл после main,
# иначе после переключения stdin на /dev/tty он ждал бы ввод с клавиатуры.
main "$@"; exit $?
