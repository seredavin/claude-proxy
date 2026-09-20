package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/launcher"
)

// --- local -------------------------------------------------------------

// localPlan — всё, что команда local решила до старта звена.
type localPlan struct {
	cfg        *config.Config
	token      string // пропуск звена, уходит claude
	authToken  string // токен подписки, только для oauth
	claudePath string
}

func cmdLocal(args []string) error {
	fs := flag.NewFlagSet("local", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `Использование: claude-proxy local [флаги] [-- аргументы claude]

Поднимает локальное звено без TLS на loopback, запускает claude с
переменными на это звено и гасит звено по выходу claude. Всё после флагов
(или после --) уходит claude как есть.

Обязательны --upstream и --upstream-key (адрес и пропуск внешнего звена) и,
в режиме oauth, ANTHROPIC_AUTH_TOKEN в окружении или файле настроек.

Флаги:
`)
		fs.PrintDefaults()
	}
	raw := config.Bind(fs)
	envFile := fs.String("env-file", localConfigFile(), "файл настроек; отсутствие — не ошибка")
	claude := fs.String("claude", "claude", "исполняемый файл claude")
	logFile := fs.String("log-file", localLogFile(), "лог звена; в терминал он не пишется")
	if err := fs.Parse(args); err != nil {
		return err
	}

	getenv, err := envSource(*envFile)
	if err != nil {
		return err
	}
	plan, err := planLocal(raw, fs, getenv, *claude, exec.LookPath)
	if err != nil {
		return err
	}

	log, closeLog, err := fileLogger(*logFile, plan.cfg.LogFormat)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	code, err := launcher.Run(ctx, launcher.Options{
		Config:     plan.cfg,
		Logger:     log,
		Token:      plan.token,
		AuthToken:  plan.authToken,
		ClaudePath: plan.claudePath,
		ClaudeArgs: fs.Args(),
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		Environ:    os.Environ(),
		Ready: func(baseURL string) {
			fmt.Fprintf(os.Stderr, "локальное звено %s → %s, лог: %s\n", baseURL, plan.cfg.Upstream, *logFile)
		},
	})
	closeLog()
	if err != nil {
		return err
	}
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

// planLocal достраивает конфигурацию звена и проверяет всё, без чего
// запускать его бессмысленно. Чистая функция ради тестов: окружение и поиск
// claude приходят параметрами.
func planLocal(raw *config.Raw, fs *flag.FlagSet, getenv config.Getenv, claude string,
	lookPath func(string) (string, error)) (*localPlan, error) {
	// Умолчания local ложатся до окружения: файл настроек может задать свой
	// loopback-адрес, а Resolve проверит, что он loopback.
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if !explicit["listen"] {
		raw.Listen = "127.0.0.1:0"
	}
	if !explicit["tls"] {
		raw.TLS = string(config.TLSNone)
	}

	config.ApplyEnv(raw, fs, getenv)

	if raw.TLS != string(config.TLSNone) {
		return nil, fmt.Errorf("команда local работает только без TLS (--tls none), задано %q", raw.TLS)
	}

	// Пропуск одноразовый: живёт в памяти и в окружении claude.
	if raw.Tokens == "" {
		raw.Tokens = "local:" + auth.Generate()
	}

	cfg, err := config.Resolve(*raw)
	if err != nil {
		return nil, err
	}
	if cfg.UpstreamKey == "" {
		return nil, errors.New("локальное звено работает только в цепочке: задайте адрес и пропуск внешнего звена " +
			"(--upstream и --upstream-key, или CLAUDE_PROXY_UPSTREAM и CLAUDE_PROXY_UPSTREAM_KEY в файле настроек)")
	}

	plan := &localPlan{cfg: cfg}
	if first, ok := cfg.Tokens.First(); ok {
		plan.token = first.Value
	}

	if cfg.Mode == config.ModeOAuth {
		plan.authToken = getenv("ANTHROPIC_AUTH_TOKEN")
		if plan.authToken == "" {
			return nil, errors.New("нет токена подписки: задайте ANTHROPIC_AUTH_TOKEN в окружении или файле настроек " +
				"(получить: claude setup-token)")
		}
	}

	path, err := lookPath(claude)
	if err != nil {
		return nil, fmt.Errorf("не найден %s (ищется в PATH; путь можно задать флагом --claude): %w", claude, err)
	}
	plan.claudePath = path
	return plan, nil
}

// fileLogger — логгер звена в файл: каталог создаётся, файл дописывается.
func fileLogger(path, format string) (*slog.Logger, func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("каталог лога: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("лог %s: %w", path, err)
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var handler slog.Handler = slog.NewTextHandler(f, opts)
	if format == "json" {
		handler = slog.NewJSONHandler(f, opts)
	}
	return slog.New(handler), func() { _ = f.Close() }, nil
}

// localConfigFile — $XDG_CONFIG_HOME/claude-proxy/local.env, без переменной —
// ~/.config/…: место для пользовательских настроек, оно же в документации.
func localConfigFile() string {
	return filepath.Join(xdgDir("XDG_CONFIG_HOME", ".config"), "claude-proxy", "local.env")
}

// localLogFile — $XDG_STATE_HOME/claude-proxy/local.log, без переменной —
// ~/.local/state/…: по XDG логи живут здесь; на macOS путь тоже приемлем.
func localLogFile() string {
	return filepath.Join(xdgDir("XDG_STATE_HOME", filepath.Join(".local", "state")), "claude-proxy", "local.log")
}

func xdgDir(env, fallback string) string {
	if dir := os.Getenv(env); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, fallback)
}
