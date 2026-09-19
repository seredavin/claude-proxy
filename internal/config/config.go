// Package config собирает настройки шлюза из флагов и переменных окружения.
//
// Приоритет: переменная окружения > флаг > значение по умолчанию.
// Порядок выбран под systemd: unit получает значения через EnvironmentFile,
// и они должны перебивать всё, что вшито в строку ExecStart. Если флаг задан
// явно, но перекрыт переменной, Load возвращает об этом предупреждение —
// молча игнорировать флаг было бы слишком неожиданно.
package config

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/seredavin/claude-proxy/internal/auth"
)

// Mode — способ, которым клиент доказывает право на шлюз, и то, чем шлюз
// авторизуется перед Anthropic.
type Mode string

const (
	// ModeOAuth: клиент шлёт токен подписки в Authorization, а пропуск на
	// шлюз — в X-Gateway-Key. Credential Anthropic на прокси не хранится.
	ModeOAuth Mode = "oauth"
	// ModeAPIKey: клиент шлёт пропуск на шлюз в Authorization, а ключ Console
	// подставляет сам шлюз.
	ModeAPIKey Mode = "apikey"
)

// TLSSource — откуда берётся серверный сертификат.
type TLSSource string

const (
	// TLSAuto — встроенный ACME-клиент (Let's Encrypt, HTTP-01).
	TLSAuto TLSSource = "auto"
	// TLSFiles — готовая пара PEM-файлов на диске.
	TLSFiles TLSSource = "files"
	// TLSSelf — самоподписанный сертификат из каталога состояния.
	TLSSelf TLSSource = "self"
	// TLSNone — слушатель без TLS. Допустим только на loopback: шлюз живёт
	// на одной машине с клиентами, и сертификат там ничего не защищает.
	TLSNone TLSSource = "none"
)

// Пути по умолчанию. Совпадают с тем, что прописывает подкоманда install.
const (
	DefaultStateDir   = "/var/lib/claude-proxy"
	DefaultConfigDir  = "/etc/claude-proxy"
	DefaultConfigFile = DefaultConfigDir + "/claude-proxy.env"
	DefaultBinPath    = "/usr/local/bin/claude-proxy"
	ServiceName       = "claude-proxy"
	UpstreamHost      = "api.anthropic.com"
)

// Config — полный набор настроек работающего шлюза.
type Config struct {
	Mode     Mode
	Listen   string
	Domain   string
	Tokens   auth.Set
	APIKey   string
	Upstream *url.URL

	// UpstreamKey — пропуск на следующий шлюз, когда апстрим не Anthropic,
	// а ещё один claude-proxy. Уходит наверх в X-Gateway-Key.
	UpstreamKey string

	TLS      TLSSource
	CertFile string
	KeyFile  string

	ACMEEmail     string
	ACMEHTTP      string
	ACMEDirectory string

	StateDir     string
	MaxBodyBytes int64
	LogFormat    string
}

// Raw — значения до разбора и валидации. Отдельный тип нужен подкоманде
// install: ей важны исходные строки, а не готовый к запуску Config.
type Raw struct {
	Mode          string
	Listen        string
	Domain        string
	Tokens        string
	APIKey        string
	Upstream      string
	UpstreamKey   string
	TLS           string
	CertFile      string
	KeyFile       string
	ACMEEmail     string
	ACMEHTTP      string
	ACMEDirectory string
	StateDir      string
	MaxBody       string
	LogFormat     string
}

// Getenv — источник переменных окружения. Параметризован ради тестов.
type Getenv func(string) string

// binding связывает поле Raw с флагом и переменными окружения.
type binding struct {
	target *string
	flag   string
	envs   []string // первое имя — основное, остальные — legacy-алиасы
}

func (r *Raw) bindings() []binding {
	return []binding{
		{&r.Mode, "mode", []string{"CLAUDE_PROXY_MODE", "GATEWAY_MODE"}},
		{&r.Listen, "listen", []string{"CLAUDE_PROXY_LISTEN"}},
		{&r.Domain, "domain", []string{"CLAUDE_PROXY_DOMAIN", "PROXY_SERVER_NAME"}},
		{&r.Tokens, "tokens", []string{"CLAUDE_PROXY_TOKENS", "GATEWAY_TOKEN"}},
		{&r.APIKey, "api-key", []string{"CLAUDE_PROXY_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"}},
		{&r.Upstream, "upstream", []string{"CLAUDE_PROXY_UPSTREAM"}},
		{&r.UpstreamKey, "upstream-key", []string{"CLAUDE_PROXY_UPSTREAM_KEY"}},
		{&r.TLS, "tls", []string{"CLAUDE_PROXY_TLS"}},
		{&r.CertFile, "cert-file", []string{"CLAUDE_PROXY_CERT_FILE", "PROXY_SSL_CERT"}},
		{&r.KeyFile, "key-file", []string{"CLAUDE_PROXY_KEY_FILE", "PROXY_SSL_KEY"}},
		{&r.ACMEEmail, "acme-email", []string{"CLAUDE_PROXY_ACME_EMAIL"}},
		{&r.ACMEHTTP, "acme-http", []string{"CLAUDE_PROXY_ACME_HTTP"}},
		{&r.ACMEDirectory, "acme-directory", []string{"CLAUDE_PROXY_ACME_DIRECTORY"}},
		{&r.StateDir, "state-dir", []string{"CLAUDE_PROXY_STATE_DIR"}},
		{&r.MaxBody, "max-body", []string{"CLAUDE_PROXY_MAX_BODY"}},
		{&r.LogFormat, "log-format", []string{"CLAUDE_PROXY_LOG_FORMAT"}},
	}
}

// ManagedEnvKeys возвращает имена переменных, которыми распоряжается сам
// claude-proxy: основные и legacy-алиасы. Всё, чего нет в этом списке,
// в EnvironmentFile поставил оператор.
func ManagedEnvKeys() []string {
	var r Raw
	var keys []string
	for _, b := range r.bindings() {
		keys = append(keys, b.envs...)
	}
	// Разбирается не через binding, а отдельно в ApplyEnv, но переносить
	// её из nginx-версии тоже незачем.
	return append(keys, "PROXY_CERTS_DIR")
}

// Defaults возвращает Raw со значениями по умолчанию.
func Defaults() Raw {
	return Raw{
		Mode:      string(ModeOAuth),
		Listen:    ":9443",
		Upstream:  "https://" + UpstreamHost,
		TLS:       string(TLSAuto),
		ACMEHTTP:  ":80",
		StateDir:  DefaultStateDir,
		MaxBody:   "100m",
		LogFormat: "text",
	}
}

// Bind регистрирует флаги во fs и возвращает Raw, куда попадут их значения.
func Bind(fs *flag.FlagSet) *Raw {
	r := Defaults()
	d := r

	fs.StringVar(&r.Mode, "mode", d.Mode, "режим шлюза: oauth | apikey")
	fs.StringVar(&r.Listen, "listen", d.Listen, "адрес прослушивания, host:port (для --tls none — только loopback)")
	fs.StringVar(&r.Domain, "domain", d.Domain, "имя, по которому клиенты обращаются к шлюзу (обязательно для --tls auto и self)")
	fs.StringVar(&r.Tokens, "tokens", d.Tokens, "токены шлюза: \"метка:значение\" через запятую")
	fs.StringVar(&r.APIKey, "api-key", d.APIKey, "ключ Anthropic Console, только для --mode apikey")
	fs.StringVar(&r.Upstream, "upstream", d.Upstream, "базовый URL Anthropic API")
	fs.StringVar(&r.UpstreamKey, "upstream-key", d.UpstreamKey,
		"пропуск на следующий шлюз в цепочке; уходит наверх как X-Gateway-Key")
	fs.StringVar(&r.TLS, "tls", d.TLS, "источник сертификата: auto | files | self | none (без TLS, только loopback)")
	fs.StringVar(&r.CertFile, "cert-file", d.CertFile, "PEM с цепочкой сертификатов, для --tls files")
	fs.StringVar(&r.KeyFile, "key-file", d.KeyFile, "PEM с приватным ключом, для --tls files")
	fs.StringVar(&r.ACMEEmail, "acme-email", d.ACMEEmail, "контакт для Let's Encrypt")
	fs.StringVar(&r.ACMEHTTP, "acme-http", d.ACMEHTTP, "адрес слушателя HTTP-01, для --tls auto")
	fs.StringVar(&r.ACMEDirectory, "acme-directory", d.ACMEDirectory, "ACME-директория; пусто — боевая Let's Encrypt, иначе URL (например staging)")
	fs.StringVar(&r.StateDir, "state-dir", d.StateDir, "каталог состояния: кэш ACME, самоподписанные сертификаты")
	fs.StringVar(&r.MaxBody, "max-body", d.MaxBody, "предел размера тела запроса (например 100m)")
	fs.StringVar(&r.LogFormat, "log-format", d.LogFormat, "формат логов: text | json")

	return &r
}

// ApplyEnv накладывает переменные окружения поверх разобранных флагов.
// Возвращает предупреждения о флагах, которые были явно заданы и перекрыты.
func ApplyEnv(r *Raw, fs *flag.FlagSet, getenv Getenv) []string {
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	var warnings []string
	for _, b := range r.bindings() {
		for _, name := range b.envs {
			value := strings.TrimSpace(getenv(name))
			if value == "" {
				continue
			}
			if explicit[b.flag] && value != *b.target {
				warnings = append(warnings, fmt.Sprintf(
					"флаг --%s перекрыт переменной %s", b.flag, name))
			}
			*b.target = value
			break // основное имя выигрывает у legacy-алиаса
		}
	}

	// PROXY_CERTS_DIR из старого .env задавал каталог, а PROXY_SSL_CERT —
	// только имя файла внутри него. Собираем путь обратно.
	if dir := strings.TrimSpace(getenv("PROXY_CERTS_DIR")); dir != "" {
		if r.CertFile != "" && !filepath.IsAbs(r.CertFile) {
			r.CertFile = filepath.Join(dir, r.CertFile)
		}
		if r.KeyFile != "" && !filepath.IsAbs(r.KeyFile) {
			r.KeyFile = filepath.Join(dir, r.KeyFile)
		}
	}

	return warnings
}

// Resolve проверяет Raw и превращает его в готовый Config.
func Resolve(r Raw) (*Config, error) {
	c := &Config{
		Listen:        strings.TrimSpace(r.Listen),
		APIKey:        strings.TrimSpace(r.APIKey),
		CertFile:      strings.TrimSpace(r.CertFile),
		KeyFile:       strings.TrimSpace(r.KeyFile),
		ACMEEmail:     strings.TrimSpace(r.ACMEEmail),
		ACMEHTTP:      strings.TrimSpace(r.ACMEHTTP),
		ACMEDirectory: strings.TrimSpace(r.ACMEDirectory),
		StateDir:      strings.TrimSpace(r.StateDir),
		UpstreamKey:   strings.TrimSpace(r.UpstreamKey),
		LogFormat:     strings.TrimSpace(r.LogFormat),
	}

	switch Mode(strings.ToLower(strings.TrimSpace(r.Mode))) {
	case ModeOAuth:
		c.Mode = ModeOAuth
	case ModeAPIKey:
		c.Mode = ModeAPIKey
	default:
		return nil, fmt.Errorf("недопустимый режим %q (ожидается oauth или apikey)", r.Mode)
	}

	// "_" в nginx означало «любое имя». Для нас это просто отсутствие домена:
	// ACME без него не работает, а files и self — работают.
	c.Domain = strings.TrimSpace(r.Domain)
	if c.Domain == "_" {
		c.Domain = ""
	}

	switch TLSSource(strings.ToLower(strings.TrimSpace(r.TLS))) {
	case TLSAuto:
		c.TLS = TLSAuto
	case TLSFiles:
		c.TLS = TLSFiles
	case TLSSelf:
		c.TLS = TLSSelf
	case TLSNone:
		c.TLS = TLSNone
	default:
		return nil, fmt.Errorf("недопустимый источник сертификата %q (ожидается auto, files, self или none)", r.TLS)
	}

	tokens, err := auth.Parse(r.Tokens)
	if err != nil {
		return nil, fmt.Errorf("токены шлюза: %w", err)
	}
	c.Tokens = tokens

	upstream, err := url.Parse(strings.TrimSpace(r.Upstream))
	if err != nil {
		return nil, fmt.Errorf("некорректный upstream %q: %w", r.Upstream, err)
	}
	if upstream.Scheme != "https" || upstream.Host == "" {
		return nil, fmt.Errorf("upstream должен быть https://host, получено %q", r.Upstream)
	}
	c.Upstream = upstream

	size, err := parseSize(r.MaxBody)
	if err != nil {
		return nil, fmt.Errorf("max-body: %w", err)
	}
	c.MaxBodyBytes = size

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen должен быть вида host:port или :port, получено %q", c.Listen)
	}

	// Пустой набор токенов дал бы шлюз, пропускающий кого угодно.
	// В nginx-версии это было тихой дырой в режиме oauth — здесь отказ.
	if c.Tokens.Empty() {
		return fmt.Errorf("не задан ни один токен шлюза (--tokens, CLAUDE_PROXY_TOKENS; сгенерировать: claude-proxy gen-token)")
	}

	// Anthropic про X-Gateway-Key ничего не знает и молча его проигнорирует —
	// заданный ключ при дефолтном апстриме значит, что цепочку настроили
	// наполовину: забыли переставить --upstream на следующее звено.
	if c.UpstreamKey != "" && isAnthropicHost(c.Upstream.Hostname()) {
		return fmt.Errorf("--upstream-key имеет смысл только когда апстрим — другой claude-proxy; для %s он бесполезен", UpstreamHost)
	}

	switch c.Mode {
	case ModeAPIKey:
		if c.APIKey == "" {
			return fmt.Errorf("в режиме apikey обязателен ключ Console (--api-key, ANTHROPIC_API_KEY)")
		}
		if strings.HasPrefix(c.APIKey, "sk-ant-oat01-") {
			return fmt.Errorf("передан токен подписки (sk-ant-oat01-), он работает только в режиме oauth")
		}
	case ModeOAuth:
		if c.APIKey != "" {
			return fmt.Errorf("в режиме oauth ключ Console не используется — уберите --api-key/ANTHROPIC_API_KEY, иначе он лежит на прокси зря")
		}
	}

	switch c.TLS {
	case TLSAuto:
		if c.Domain == "" {
			return fmt.Errorf("для --tls auto нужен --domain: Let's Encrypt выпускает сертификат на имя")
		}
		if c.ACMEHTTP == "" {
			return fmt.Errorf("для --tls auto нужен --acme-http: проверка HTTP-01 идёт по порту 80")
		}
		if _, _, err := net.SplitHostPort(c.ACMEHTTP); err != nil {
			return fmt.Errorf("acme-http должен быть вида host:port или :port, получено %q", c.ACMEHTTP)
		}
		if c.StateDir == "" {
			return fmt.Errorf("для --tls auto нужен --state-dir: там хранится кэш ACME")
		}
	case TLSFiles:
		if c.CertFile == "" || c.KeyFile == "" {
			return fmt.Errorf("для --tls files нужны --cert-file и --key-file")
		}
	case TLSSelf:
		if c.Domain == "" {
			return fmt.Errorf("для --tls self нужен --domain: имя попадёт в SAN сертификата")
		}
		if c.StateDir == "" {
			return fmt.Errorf("для --tls self нужен --state-dir: там лежит самоподписанная пара")
		}
	case TLSNone:
		// Без TLS пропуски и токены подписки идут открытым текстом. На петле
		// это никому не видно, в сети — видно всем, поэтому не предупреждение,
		// а отказ. Пустой хост означает все интерфейсы и тоже не годится.
		host, _, _ := net.SplitHostPort(c.Listen)
		if !isLoopbackHost(host) {
			return fmt.Errorf("--tls none допустим только на loopback-адресе (127.0.0.1, ::1, localhost), получено %q: без TLS пропуски и токены подписки ушли бы по сети открытым текстом", c.Listen)
		}
	}

	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("недопустимый log-format %q (ожидается text или json)", c.LogFormat)
	}

	return nil
}

// isAnthropicHost отвечает, ведёт ли имя на сам Anthropic. Регистр и
// завершающая точка в имени хоста ничего не меняют для DNS, но url.Parse
// оставляет их как есть, а обычное сравнение строк на них спотыкается.
func isAnthropicHost(host string) bool {
	return strings.EqualFold(strings.TrimSuffix(host, "."), UpstreamHost)
}

// isLoopbackHost отвечает, ведёт ли хост слушателя на петлю. Имя localhost
// принимается как есть, без резолва: DNS в валидации — лишняя зависимость,
// а подмена localhost через /etc/hosts на что-то другое — экзотика.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseSize разбирает размер с необязательным суффиксом k, m или g.
func parseSize(s string) (int64, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return 0, fmt.Errorf("пустое значение")
	}

	multiplier := int64(1)
	switch v[len(v)-1] {
	case 'k':
		multiplier, v = 1<<10, v[:len(v)-1]
	case 'm':
		multiplier, v = 1<<20, v[:len(v)-1]
	case 'g':
		multiplier, v = 1<<30, v[:len(v)-1]
	}

	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q не похоже на размер (примеры: 100m, 1g, 524288)", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("размер должен быть положительным, получено %q", s)
	}
	if n > (1<<62)/multiplier {
		return 0, fmt.Errorf("слишком большое значение %q", s)
	}
	return n * multiplier, nil
}

// LoadEnvFile читает EnvironmentFile systemd: строки KEY=VALUE, комментарии
// с # и необязательные кавычки вокруг значения.
//
// Нужен подкомандам, которые запускаются руками: у них в окружении нет того,
// что systemd подставляет сервису.
func LoadEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	vars := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if unquoted, uerr := strconv.Unquote(value); uerr == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `"'`)
		}
		vars[key] = value
	}
	return vars, nil
}

// EnvWithFallback отдаёт значение из окружения процесса, а если там пусто —
// из прочитанного файла. Настоящее окружение всегда главнее.
func EnvWithFallback(fallback map[string]string) Getenv {
	return func(key string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback[key]
	}
}
