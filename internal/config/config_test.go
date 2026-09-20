package config

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// load прогоняет полный путь «флаги -> env -> Config», как это делает main.
func load(t *testing.T, args []string, env map[string]string) (*Config, []string, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	raw := Bind(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("разбор аргументов: %v", err)
	}
	warnings := ApplyEnv(raw, fs, func(k string) string { return env[k] })
	cfg, err := Resolve(*raw)
	return cfg, warnings, err
}

func TestEnvПеребиваетФлагИПредупреждает(t *testing.T) {
	cfg, warnings, err := load(t,
		[]string{"--mode", "oauth", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--tokens", "flag-token"},
		map[string]string{"CLAUDE_PROXY_TOKENS": "env-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tokens.Lookup("env-token"); !ok {
		t.Error("значение из переменной окружения не применилось")
	}
	if _, ok := cfg.Tokens.Lookup("flag-token"); ok {
		t.Error("значение флага осталось активным, хотя перекрыто переменной")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "--tokens") {
		t.Errorf("ожидалось предупреждение про --tokens, получено %v", warnings)
	}
}

func TestEnvБезЯвногоФлагаНеПредупреждает(t *testing.T) {
	_, warnings, err := load(t,
		[]string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
		map[string]string{"CLAUDE_PROXY_TOKENS": "env-token"})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("лишние предупреждения: %v", warnings)
	}
}

func TestОсновноеИмяВыигрываетУLegacy(t *testing.T) {
	cfg, _, err := load(t,
		[]string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
		map[string]string{
			"CLAUDE_PROXY_TOKENS": "new",
			"GATEWAY_TOKEN":       "old",
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tokens.Lookup("new"); !ok {
		t.Error("CLAUDE_PROXY_TOKENS должен выигрывать у GATEWAY_TOKEN")
	}
}

func TestСтарыйEnvФайлПодхватываетсяЦеликом(t *testing.T) {
	// Ровно тот .env, который писал прежний install.sh.
	cfg, _, err := load(t, nil, map[string]string{
		"GATEWAY_MODE":      "apikey",
		"PROXY_SERVER_NAME": "proxy.example.com",
		"PROXY_CERTS_DIR":   "/opt/proxy-certs",
		"PROXY_SSL_CERT":    "fullchain.pem",
		"PROXY_SSL_KEY":     "privkey.pem",
		"ANTHROPIC_API_KEY": "sk-ant-api03-xxx",
		"GATEWAY_TOKEN":     "abc123",
		"CLAUDE_PROXY_TLS":  "files",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeAPIKey {
		t.Errorf("Mode = %q, ожидалось apikey", cfg.Mode)
	}
	if cfg.Domain != "proxy.example.com" {
		t.Errorf("Domain = %q", cfg.Domain)
	}
	if cfg.CertFile != "/opt/proxy-certs/fullchain.pem" {
		t.Errorf("CertFile = %q — PROXY_CERTS_DIR не приклеился", cfg.CertFile)
	}
	if cfg.KeyFile != "/opt/proxy-certs/privkey.pem" {
		t.Errorf("KeyFile = %q", cfg.KeyFile)
	}
	if _, ok := cfg.Tokens.Lookup("abc123"); !ok {
		t.Error("GATEWAY_TOKEN не подхватился")
	}
}

func TestАбсолютныйПутьНеСклеиваетсяСCertsDir(t *testing.T) {
	cfg, _, err := load(t, []string{"--tls", "files"}, map[string]string{
		"GATEWAY_TOKEN":   "abc",
		"PROXY_CERTS_DIR": "/opt/proxy-certs",
		"PROXY_SSL_CERT":  "/etc/letsencrypt/live/x/fullchain.pem",
		"PROXY_SSL_KEY":   "/etc/letsencrypt/live/x/privkey.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertFile != "/etc/letsencrypt/live/x/fullchain.pem" {
		t.Errorf("CertFile = %q", cfg.CertFile)
	}
}

func TestПодчёркиваниеВИмениСервераОзначаетЛюбоеИмя(t *testing.T) {
	cfg, _, err := load(t,
		[]string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
		map[string]string{"GATEWAY_TOKEN": "abc", "PROXY_SERVER_NAME": "_"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "" {
		t.Errorf("Domain = %q, ожидалась пустая строка", cfg.Domain)
	}
}

func TestОшибкиВалидации(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{
			name: "без токенов",
			args: []string{"--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
			want: "токен шлюза",
		},
		{
			name: "apikey без ключа",
			args: []string{"--mode", "apikey", "--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
			want: "ключ Console",
		},
		{
			name: "apikey с токеном подписки",
			args: []string{"--mode", "apikey", "--tokens", "a", "--api-key", "sk-ant-oat01-zzz", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
			want: "только в режиме oauth",
		},
		{
			name: "oauth с ключом Console",
			args: []string{"--mode", "oauth", "--tokens", "a", "--api-key", "sk-ant-api03-zzz", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
			want: "в режиме oauth ключ Console не используется",
		},
		{
			name: "auto без домена",
			args: []string{"--tokens", "a", "--tls", "auto"},
			want: "нужен --domain",
		},
		{
			name: "files без путей",
			args: []string{"--tokens", "a", "--tls", "files"},
			want: "нужны --cert-file и --key-file",
		},
		{
			name: "self без домена",
			args: []string{"--tokens", "a", "--tls", "self"},
			want: "нужен --domain",
		},
		{
			name: "неизвестный режим",
			args: []string{"--mode", "bearer", "--tokens", "a"},
			want: "недопустимый режим",
		},
		{
			name: "неизвестный источник сертификата",
			args: []string{"--tokens", "a", "--tls", "vault"},
			want: "недопустимый источник сертификата",
		},
		{
			name: "listen без порта",
			args: []string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--listen", "9443"},
			want: "listen должен быть",
		},
		{
			name: "upstream по http",
			args: []string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--upstream", "http://api.anthropic.com"},
			want: "upstream должен быть https",
		},
		{
			name: "пропуск на следующее звено при дефолтном апстриме",
			args: []string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--upstream-key", "next"},
			want: "--upstream-key имеет смысл только",
		},
		{
			name: "пропуск на следующее звено при дефолтном апстриме в другом регистре",
			args: []string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--upstream", "https://API.Anthropic.COM.", "--upstream-key", "next"},
			want: "--upstream-key имеет смысл только",
		},
		{
			name: "none без хоста слушает все интерфейсы",
			args: []string{"--tokens", "a", "--tls", "none", "--listen", ":9443"},
			want: "--tls none допустим только на loopback",
		},
		{
			name: "none на 0.0.0.0",
			args: []string{"--tokens", "a", "--tls", "none", "--listen", "0.0.0.0:9443"},
			want: "--tls none допустим только на loopback",
		},
		{
			name: "none на внешнем адресе",
			args: []string{"--tokens", "a", "--tls", "none", "--listen", "10.0.0.5:9443"},
			want: "--tls none допустим только на loopback",
		},
		{
			name: "none на [::]",
			args: []string{"--tokens", "a", "--tls", "none", "--listen", "[::]:9443"},
			want: "--tls none допустим только на loopback",
		},
		{
			name: "none не отменяет https для апстрима",
			args: []string{"--tokens", "a", "--tls", "none", "--listen", "127.0.0.1:9443", "--upstream", "http://edge.example.com:9443"},
			want: "upstream должен быть https",
		},
		{
			name: "мусор в max-body",
			args: []string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem", "--max-body", "много"},
			want: "max-body",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, tc.args, tc.env)
			if err == nil {
				t.Fatalf("ожидалась ошибка с текстом %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка %q не содержит %q", err, tc.want)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"100m", 100 << 20},
		{"1g", 1 << 30},
		{"512k", 512 << 10},
		{"1024", 1024},
		{" 100M ", 100 << 20},
	}
	for _, tc := range tests {
		got, err := parseSize(tc.in)
		if err != nil {
			t.Errorf("parseSize(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSize(%q) = %d, ожидалось %d", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "0", "-5m", "m", "1x", "1.5m"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) не вернул ошибку", bad)
		}
	}
}

func TestДефолтыПоУмолчанию(t *testing.T) {
	cfg, _, err := load(t,
		[]string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeOAuth {
		t.Errorf("Mode = %q, ожидалось oauth", cfg.Mode)
	}
	if cfg.Listen != ":9443" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.Upstream.Host != UpstreamHost {
		t.Errorf("Upstream = %q", cfg.Upstream)
	}
	if cfg.MaxBodyBytes != 100<<20 {
		t.Errorf("MaxBodyBytes = %d", cfg.MaxBodyBytes)
	}
}

func TestUpstreamKeyFromEnv(t *testing.T) {
	cfg, _, err := load(t,
		[]string{"--tokens", "a", "--tls", "files", "--cert-file", "c.pem", "--key-file", "k.pem"},
		map[string]string{
			"CLAUDE_PROXY_UPSTREAM":     "https://edge.example.com:9443",
			"CLAUDE_PROXY_UPSTREAM_KEY": " next-secret ",
		})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.Host != "edge.example.com:9443" {
		t.Errorf("апстрим = %q", cfg.Upstream.Host)
	}
	if cfg.UpstreamKey != "next-secret" {
		t.Errorf("пропуск на следующее звено = %q, пробелы должны срезаться", cfg.UpstreamKey)
	}
}

// Без TLS не нужны ни имя шлюза, ни каталог состояния, ни файлы сертификата —
// но только на петле.
func TestNoneСтартуетТолькоНаLoopback(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:9443", "[::1]:9443", "localhost:9443", "LOCALHOST:9443", "127.0.0.2:9443"} {
		t.Run(listen, func(t *testing.T) {
			cfg, _, err := load(t, []string{"--tokens", "a", "--tls", "none", "--listen", listen, "--state-dir", "", "--domain", ""}, nil)
			if err != nil {
				t.Fatalf("none на %s должен стартовать: %v", listen, err)
			}
			if cfg.TLS != TLSNone {
				t.Errorf("TLS = %q, ожидалось none", cfg.TLS)
			}
		})
	}
}

func TestNoneИзПеременнойОкружения(t *testing.T) {
	cfg, _, err := load(t, []string{"--tokens", "a"}, map[string]string{
		"CLAUDE_PROXY_TLS":    "none",
		"CLAUDE_PROXY_LISTEN": "127.0.0.1:9443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS != TLSNone {
		t.Errorf("TLS = %q, ожидалось none", cfg.TLS)
	}
}
