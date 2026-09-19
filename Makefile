# Сборка claude-proxy.
#
# Бинарь статический: CGO выключен, чтобы один и тот же файл работал
# и на glibc, и на musl, и в образе scratch.

BINARY  := claude-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

# Платформы релиза. Хост прокси почти всегда linux, darwin — для локальных проверок.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: all build test vet fmt check dist clean docker install

all: check build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Форматирование проверяется, а не исправляется: в CI правки недопустимы.
check: vet test
	@test -z "$$(gofmt -l .)" || { echo "не отформатировано:"; gofmt -l .; exit 1; }

dist:
	@rm -rf $(DIST)
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "==> $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(DIST)/$(BINARY)-$$os-$$arch . || exit 1; \
	done
	@cd $(DIST) && (sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS)
	@ls -l $(DIST)

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

# Локальная установка сервиса из свежесобранного бинаря.
install: build
	sudo ./$(BINARY) install $(ARGS)

clean:
	rm -rf $(DIST) $(BINARY)
