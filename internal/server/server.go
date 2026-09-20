// Package server поднимает слушатели шлюза и гасит их по сигналу.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
	"github.com/seredavin/claude-proxy/internal/gateway"
	"github.com/seredavin/claude-proxy/internal/mask"
	"github.com/seredavin/claude-proxy/internal/tlsconf"
)

const (
	// Запас на завершение уже начатых ответов. Стриминг может идти долго,
	// но бесконечно ждать при остановке сервиса нельзя.
	shutdownTimeout = 30 * time.Second

	// Заголовки запроса должны прийти быстро; само тело и ответ — без предела,
	// иначе длинная генерация с SSE обрывается на середине.
	readHeaderTimeout = 30 * time.Second
	idleTimeout       = 120 * time.Second
)

// Run запускает шлюз и возвращает управление, когда ctx отменён
// или один из слушателей упал.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return RunReady(ctx, cfg, log, nil)
}

// RunReady — то же, что Run, но зовёт ready с фактическим адресом основного
// слушателя, как только тот занят. Нужен тому, кто поднимает шлюз в своём
// процессе и должен знать порт (например, при --listen 127.0.0.1:0) и момент,
// с которого соединения уже принимаются. nil — не уведомлять.
func RunReady(ctx context.Context, cfg *config.Config, log *slog.Logger, ready func(net.Addr)) error {
	provider, err := tlsconf.New(cfg, log)
	if err != nil {
		return err
	}

	// Маскирование включается наличием файла правил. Реестр таблиц —
	// один на процесс, и создаётся здесь, а не в конфиге: у него есть
	// состояние и логгер.
	var masker *mask.Registry
	if cfg.Mask != nil {
		masker = mask.NewRegistry(cfg.Mask, mask.Options{Debug: cfg.MaskDebug, Logger: log})
		log.Info("маскирование включено", "rules", cfg.MaskRules, "summary", cfg.Mask.Summary(),
			"on_error", string(cfg.MaskOnError))
		if cfg.MaskDebug {
			log.Warn("включён --mask-debug: настоящие значения IP, хостов и секретов пишутся в лог открытым текстом")
		}
	}

	gw := gateway.New(gateway.Options{
		Mode:         cfg.Mode,
		Tokens:       cfg.Tokens,
		APIKey:       cfg.APIKey,
		Upstream:     cfg.Upstream,
		UpstreamKey:  cfg.UpstreamKey,
		MaxBodyBytes: cfg.MaxBodyBytes,
		Logger:       log,
		Masker:       masker,
		MaskOnError:  cfg.MaskOnError,
	})

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: gw,
		// nil — слушатель без TLS (источник none).
		TLSConfig:         provider.TLSConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		// Warn, а не Debug: иначе хендлер с уровнем Info отфильтровал бы всё,
		// включая ошибки рукопожатия TLS и паники, пойманные сервером.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("не удалось занять %s: %w", cfg.Listen, err)
	}

	// Слушатель ACME поднимаем до основного: без него сертификат не выпустится,
	// и первое же рукопожатие зависнет в ожидании проверки HTTP-01.
	var acmeSrv *http.Server
	if provider.HTTPHandler != nil {
		acmeSrv = &http.Server{
			Addr:              provider.HTTPAddr,
			Handler:           provider.HTTPHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		acmeLn, lerr := net.Listen("tcp", provider.HTTPAddr)
		if lerr != nil {
			_ = ln.Close()
			return fmt.Errorf("не удалось занять %s под проверку HTTP-01: %w", provider.HTTPAddr, lerr)
		}
		go func() {
			if serr := acmeSrv.Serve(acmeLn); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				log.Error("слушатель HTTP-01 остановился", "err", serr)
			}
		}()
		// Гасим на любом выходе, включая ошибку основного слушателя:
		// иначе горутина и сокет переживают возврат из Run.
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = acmeSrv.Shutdown(ctx)
		}()
	}

	// Все слушатели заняты, отказов на старте больше не будет — можно
	// сообщать адрес. Сокет уже принимает соединения в очередь, Serve ниже
	// лишь начинает их разбирать.
	if ready != nil {
		ready(ln.Addr())
	}

	log.Info("шлюз запущен",
		"listen", ln.Addr().String(),
		"mode", string(cfg.Mode),
		"domain", cfg.Domain,
		"upstream", cfg.Upstream.String(),
		"tls", provider.Description,
		"tokens", cfg.Tokens.Labels(),
	)

	serveErr := make(chan error, 1)
	go func() {
		if srv.TLSConfig == nil {
			serveErr <- srv.Serve(ln)
			return
		}
		// Сертификат и ключ берутся из TLSConfig.GetCertificate.
		serveErr <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("остановка", "timeout", shutdownTimeout.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Соединения не успели закрыться сами — рвём их.
		_ = srv.Close()
		return fmt.Errorf("остановка не уложилась в %s: %w", shutdownTimeout, err)
	}
	return nil
}
