// Command claude-proxy — TLS-шлюз, через который Claude Code из сети без
// прямого интернета работает с Anthropic API.
//
// Один бинарь: сам шлюз, встроенный ACME-клиент, установка systemd-сервиса.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/clientenv"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/server"
	"github.com/seredavin/claude-proxy/internal/service"
	"github.com/seredavin/claude-proxy/internal/tlsconf"
)

// version подставляется при сборке: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\033[1;31mОшибка:\033[0m %v\n", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	command := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}

	switch command {
	case "run":
		return cmdRun(args)
	case "install":
		return cmdInstall(args)
	case "uninstall":
		return cmdUninstall(args)
	case "gen-token":
		return cmdGenToken(args)
	case "gen-cert":
		return cmdGenCert(args)
	case "client-env":
		return cmdClientEnv(args)
	case "version":
		fmt.Println("claude-proxy " + version)
		return nil
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("неизвестная команда %q", command)
	}
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `claude-proxy %s — TLS-шлюз к Anthropic API для сети без прямого интернета.

Использование:
  claude-proxy <команда> [флаги]

Команды:
  run           Запустить шлюз (команда по умолчанию).
  install       Разложить бинарь, конфигурацию и systemd-юнит, запустить сервис.
  uninstall     Остановить сервис и убрать юнит. С --purge — снести всё.
  gen-token     Сгенерировать токен шлюза.
  gen-cert      Выпустить самоподписанный сертификат.
  client-env    Напечатать переменные окружения для клиентской машины.
  version       Показать версию.

Флаги команды: claude-proxy <команда> --help

Значения берутся из флагов и переменных окружения, причём переменная
перебивает флаг — так systemd-юнит настраивается через EnvironmentFile,
не трогая строку ExecStart.
`, version)
}

// --- run ---------------------------------------------------------------

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	raw := config.Bind(fs)
	envFile := fs.String("env-file", "", "дополнительный EnvironmentFile; настоящее окружение всё равно главнее")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, warnings, err := resolve(raw, fs, *envFile)
	if err != nil {
		return err
	}

	log := newLogger(cfg.LogFormat)
	for _, w := range warnings {
		log.Warn(w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return server.Run(ctx, cfg, log)
}

// --- install -----------------------------------------------------------

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	raw := config.Bind(fs)
	runAs := fs.String("service-user", service.ServiceUser,
		"пользователь юнита; root нужен, если сертификаты читаются только им")
	envFile := fs.String("env-file", config.DefaultConfigFile,
		"откуда взять исходные значения; при переходе с nginx-версии — прежний .env")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Токен не задан и прежнего нет — выпускаем новый прямо здесь,
	// чтобы установка за один заход давала рабочую конфигурацию.
	generated := ""
	if raw.Tokens == "" && os.Getenv("CLAUDE_PROXY_TOKENS") == "" && os.Getenv("GATEWAY_TOKEN") == "" {
		if existing, err := config.LoadEnvFile(*envFile); err != nil || (existing["CLAUDE_PROXY_TOKENS"] == "" && existing["GATEWAY_TOKEN"] == "") {
			generated = auth.Generate()
			raw.Tokens = auth.DefaultLabel + ":" + generated
		}
	}

	cfg, warnings, err := resolve(raw, fs, *envFile)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "  ! %s\n", w)
	}

	fmt.Println("==> Установка claude-proxy")
	if err := service.Install(service.InstallOptions{
		Raw:      *raw,
		Resolved: cfg,
		RunAs:    *runAs,
		Out:      os.Stdout,
	}); err != nil {
		return err
	}

	token := generated
	if token == "" {
		if first, ok := cfg.Tokens.First(); ok {
			token = first.Value
		}
	}

	fmt.Printf("\n==> Готово\n\nНастройка клиента:\n\n")
	fmt.Println(indent(clientenv.Render(cfg, token)))
	fmt.Printf("Токен шлюза — секрет: он лежит в %s и выведен выше.\n", config.DefaultConfigFile)
	fmt.Printf("Логи:    journalctl -u %s -f\n", config.ServiceName)
	fmt.Printf("Рестарт: systemctl restart %s\n", config.ServiceName)
	return nil
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "удалить также конфигурацию, состояние и бинарь")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Println("==> Удаление claude-proxy")
	return service.Uninstall(*purge, os.Stdout)
}

// --- вспомогательные команды -------------------------------------------

func cmdGenToken(args []string) error {
	fs := flag.NewFlagSet("gen-token", flag.ExitOnError)
	label := fs.String("label", "", "метка токена; с ней вывод готов к подстановке в CLAUDE_PROXY_TOKENS")
	if err := fs.Parse(args); err != nil {
		return err
	}

	token := auth.Generate()
	if *label == "" {
		fmt.Println(token)
		return nil
	}
	fmt.Printf("%s:%s\n", *label, token)
	return nil
}

func cmdGenCert(args []string) error {
	fs := flag.NewFlagSet("gen-cert", flag.ExitOnError)
	domain := fs.String("domain", "", "имя или IP шлюза; попадёт в subjectAltName")
	outDir := fs.String("out-dir", ".", "куда положить fullchain.pem и privkey.pem")
	days := fs.Int("days", tlsconf.DefaultSelfSignedDays, "срок действия в днях")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("укажите --domain: имя должно попасть в SAN, иначе Node его отвергнет")
	}

	if err := tlsconf.GenerateSelfSigned(*domain, *outDir, *days); err != nil {
		return err
	}
	fmt.Printf("Сертификат для %s на %d дней: %s/fullchain.pem, %s/privkey.pem\n",
		*domain, *days, *outDir, *outDir)
	fmt.Printf("На клиентах: export NODE_EXTRA_CA_CERTS=<путь к fullchain.pem>\n")
	return nil
}

func cmdClientEnv(args []string) error {
	fs := flag.NewFlagSet("client-env", flag.ExitOnError)
	raw := config.Bind(fs)
	envFile := fs.String("env-file", config.DefaultConfigFile, "откуда читать конфигурацию шлюза")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _, err := resolve(raw, fs, *envFile)
	if err != nil {
		return err
	}

	token := ""
	if first, ok := cfg.Tokens.First(); ok {
		token = first.Value
	}
	fmt.Print(clientenv.Render(cfg, token))
	return nil
}

// --- общее -------------------------------------------------------------

// resolve достраивает конфигурацию: флаги, затем файл, затем окружение.
func resolve(raw *config.Raw, fs *flag.FlagSet, envFile string) (*config.Config, []string, error) {
	getenv := config.Getenv(os.Getenv)
	if envFile != "" {
		if vars, err := config.LoadEnvFile(envFile); err == nil {
			getenv = config.EnvWithFallback(vars)
		} else if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("чтение %s: %w", envFile, err)
		}
	}

	warnings := config.ApplyEnv(raw, fs, getenv)
	cfg, err := config.Resolve(*raw)
	if err != nil {
		return nil, nil, err
	}
	return cfg, warnings, nil
}

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line != "" {
			b.WriteString("  ")
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
