# Образ нужен только тем, у кого политика требует контейнер:
# основной способ установки — бинарь под systemd.

FROM golang:1.25-alpine AS build

ARG VERSION=docker
WORKDIR /src

# Слой зависимостей кэшируется отдельно от исходников.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/claude-proxy .

# Каталог состояния готовим здесь: том, созданный Docker'ом с нуля, принадлежал
# бы root, и непривилегированный процесс не записал бы в него кэш ACME.
RUN mkdir -p /state && chown 65532:65532 /state

# static-debian12 приносит корневые сертификаты — они нужны для проверки
# сертификата api.anthropic.com. На scratch пришлось бы копировать их руками.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/claude-proxy /usr/local/bin/claude-proxy
COPY --from=build --chown=65532:65532 /state /var/lib/claude-proxy

# Порт 80 непривилегированному пользователю недоступен, поэтому проверка
# HTTP-01 слушает 8080. Снаружи её надо пробросить именно с 80:
#   docker run -p 80:8080 -p 9443:9443 ...
ENV CLAUDE_PROXY_ACME_HTTP=:8080 \
    CLAUDE_PROXY_STATE_DIR=/var/lib/claude-proxy

EXPOSE 9443 8080
VOLUME /var/lib/claude-proxy

ENTRYPOINT ["/usr/local/bin/claude-proxy"]
CMD ["run"]
