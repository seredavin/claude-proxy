// Package launcher запускает claude через локальное звено, поднятое в этом
// же процессе: звено и claude живут и умирают вместе.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/seredavin/claude-proxy/internal/clientenv"
	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/server"
)

// Столько ждём выхода claude после SIGTERM, прежде чем убить: ему надо
// успеть сохранить состояние сессии, но бесконечно висеть нельзя.
const childGrace = 5 * time.Second

// Options — всё, что нужно для одного запуска.
type Options struct {
	// Config — конфигурация звена: TLS none, loopback-адрес (порт может быть 0).
	Config *config.Config
	// Logger — куда пишет звено. В терминал ему нельзя — там интерфейс claude.
	Logger *slog.Logger

	// Token — пропуск звена, который получит claude.
	Token string
	// AuthToken — токен подписки для режима oauth. В режиме apikey не нужен:
	// claude предъявляет пропуск, ключ Console подставляет само звено.
	AuthToken string

	// ClaudePath — исполняемый файл claude, уже найденный.
	ClaudePath string
	// ClaudeArgs — его аргументы как есть.
	ClaudeArgs []string

	// Потоки для claude: терминал наследуется.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Environ — исходное окружение, поверх которого ложатся переменные звена.
	Environ []string

	// Ready зовётся перед запуском claude с адресом звена — для одной строки
	// в stderr. Может быть nil.
	Ready func(baseURL string)

	// runGateway подменяется в тестах; nil — server.RunReady.
	runGateway func(context.Context, *config.Config, *slog.Logger, func(net.Addr)) error
}

// Run поднимает звено, дожидается готовности, запускает claude и после его
// выхода гасит звено. Возвращает код выхода claude; ошибка — когда до claude
// дело не дошло или звено упало под ним.
func Run(ctx context.Context, o Options) (int, error) {
	runGateway := o.runGateway
	if runGateway == nil {
		runGateway = server.RunReady
	}

	gwCtx, stopGateway := context.WithCancel(ctx)
	defer stopGateway()

	ready := make(chan net.Addr, 1)
	gwDone := make(chan error, 1)
	go func() {
		gwDone <- runGateway(gwCtx, o.Config, o.Logger, func(a net.Addr) { ready <- a })
	}()

	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-gwDone:
		if err == nil {
			err = errors.New("остановлено до готовности")
		}
		return 1, fmt.Errorf("локальное звено не поднялось: %w", err)
	}

	baseURL := "http://" + addr.String()
	if o.Ready != nil {
		o.Ready(baseURL)
	}

	// Переменные звена считаем от фактического адреса: в конфигурации мог
	// быть порт 0.
	envCfg := *o.Config
	envCfg.Listen = addr.String()

	cmd := exec.Command(o.ClaudePath, o.ClaudeArgs...)
	cmd.Env = Environ(o.Environ, &envCfg, o.Token, o.AuthToken)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, o.Stderr

	// Подписка, а не signal.Ignore: SIG_IGN пережил бы exec и достался
	// claude, а обработчик Go у ребёнка сбрасывается в умолчание.
	// Ctrl+C приходит всей группе процессов; что с ним делать — решает claude,
	// звено под ним исчезать не должно.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		stopGateway()
		<-gwDone
		return 1, fmt.Errorf("запуск %s: %w", o.ClaudePath, err)
	}

	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGTERM {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}

		case err := <-childDone:
			stopGateway()
			if gwErr := <-gwDone; gwErr != nil {
				o.Logger.Error("остановка локального звена", "err", gwErr)
			}
			return exitCode(err), nil

		case gwErr := <-gwDone:
			// Звено ушло раньше claude: без него claude бесполезен.
			childErr := terminate(cmd, childDone)
			if gwErr != nil {
				return 1, fmt.Errorf("локальное звено остановилось: %w", gwErr)
			}
			// Остановка снаружи через ctx — штатная.
			return exitCode(childErr), nil
		}
	}
}

// terminate просит ребёнка выйти и ждёт; не дождавшись — убивает.
func terminate(cmd *exec.Cmd, done <-chan error) error {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		return err
	case <-time.After(childGrace):
		_ = cmd.Process.Kill()
		return <-done
	}
}

// exitCode переводит результат Wait в код выхода. Убитый сигналом процесс
// кода не имеет — считаем это ошибкой.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return exit.ExitCode()
	}
	return 1
}

// Environ накладывает переменные клиента на base: то, что client-env велит
// задать, — задаётся, что велит снять, — снимается, остальное — как было.
// В режиме oauth плейсхолдер токена подписки заменяется настоящим authToken.
func Environ(base []string, cfg *config.Config, token, authToken string) []string {
	set := map[string]string{}
	var order []string
	drop := map[string]bool{}
	for _, v := range clientenv.Vars(cfg, token) {
		switch {
		case v.Unset:
			drop[v.Name] = true
		case v.Name != "":
			set[v.Name] = v.Value
			order = append(order, v.Name)
		}
	}
	if cfg.Mode != config.ModeAPIKey {
		set["ANTHROPIC_AUTH_TOKEN"] = authToken
	}

	env := make([]string, 0, len(base)+len(order))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if drop[name] {
			continue
		}
		if _, ours := set[name]; ours {
			continue
		}
		env = append(env, kv)
	}
	for _, name := range order {
		env = append(env, name+"="+set[name])
	}
	return env
}
