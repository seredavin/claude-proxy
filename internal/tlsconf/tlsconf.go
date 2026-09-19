// Package tlsconf собирает tls.Config шлюза из одного из трёх источников
// сертификата: встроенный ACME, готовые PEM-файлы, самоподписанная пара.
package tlsconf

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/seredavin/claude-proxy/internal/config"
)

// Provider — готовая к употреблению конфигурация TLS.
type Provider struct {
	// TLSConfig nil означает слушатель без TLS (источник none).
	TLSConfig *tls.Config

	// HTTPHandler не nil только для ACME: на нём отвечает проверка HTTP-01.
	// Вызывающий обязан поднять его на HTTPAddr, иначе сертификат не выпустится.
	HTTPHandler http.Handler
	HTTPAddr    string

	// Description — строка для стартового лога.
	Description string
}

// New выбирает источник сертификата по конфигурации и готовит tls.Config.
func New(cfg *config.Config, log *slog.Logger) (*Provider, error) {
	switch cfg.TLS {
	case config.TLSAuto:
		return newACME(cfg, log)
	case config.TLSFiles:
		return newFiles(cfg.CertFile, cfg.KeyFile, cfg.Domain, log)
	case config.TLSSelf:
		return newSelfSigned(cfg, log)
	case config.TLSNone:
		// Допустимость loopback-адреса проверена в config: сюда доходит
		// только конфигурация, где открытый текст не покидает машину.
		return &Provider{Description: "без TLS (только loopback)"}, nil
	default:
		return nil, fmt.Errorf("неизвестный источник сертификата %q", cfg.TLS)
	}
}

// baseTLSConfig — общие параметры для всех трёх источников.
func baseTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// --- ACME --------------------------------------------------------------

func newACME(cfg *config.Config, log *slog.Logger) (*Provider, error) {
	cacheDir := filepath.Join(cfg.StateDir, "acme")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("кэш ACME %s: %w", cacheDir, err)
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMEDirectory != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACMEDirectory}
	}

	tc := baseTLSConfig()
	tc.GetCertificate = m.GetCertificate
	// acme-tls/1 нужен для TLS-ALPN-проверки. Она работает только на порту 443,
	// поэтому на нестандартном порту шлюза остаётся неиспользуемой — но и не мешает.
	tc.NextProtos = append(tc.NextProtos, acme.ALPNProto)

	directory := cfg.ACMEDirectory
	if directory == "" {
		directory = "Let's Encrypt (боевая)"
	}

	return &Provider{
		TLSConfig:   tc,
		HTTPHandler: m.HTTPHandler(nil),
		HTTPAddr:    cfg.ACMEHTTP,
		Description: fmt.Sprintf("ACME для %s, кэш %s, директория %s", cfg.Domain, cacheDir, directory),
	}, nil
}

// --- файлы на диске ----------------------------------------------------

// reloader перечитывает пару PEM-файлов, когда они изменились на диске.
// Благодаря ему продление сертификата не требует ни перезапуска процесса,
// ни сигнала: certbot или любой другой инструмент просто переписывает файлы.
type reloader struct {
	certFile string
	keyFile  string

	mu        sync.RWMutex
	cert      *tls.Certificate
	stamp     string
	lastCheck time.Time
}

// checkInterval ограничивает частоту stat: на каждое рукопожатие ходить
// в файловую систему незачем.
const checkInterval = 5 * time.Second

func newFiles(certFile, keyFile, domain string, log *slog.Logger) (*Provider, error) {
	r := &reloader{certFile: certFile, keyFile: keyFile}

	// Загружаем сразу: битые пути должны валить старт, а не первое соединение.
	cert, stamp, err := loadPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	r.cert, r.stamp, r.lastCheck = cert, stamp, time.Now()

	warnIfNameMismatch(cert, domain, log)

	tc := baseTLSConfig()
	tc.GetCertificate = r.GetCertificate

	return &Provider{
		TLSConfig:   tc,
		Description: fmt.Sprintf("файлы %s и %s (перечитываются при изменении)", certFile, keyFile),
	}, nil
}

func (r *reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, stamp, last := r.cert, r.stamp, r.lastCheck
	r.mu.RUnlock()

	if time.Since(last) < checkInterval {
		return cert, nil
	}

	current, err := stampOf(r.certFile, r.keyFile)
	if err != nil || current == stamp {
		// Файлы временно недоступны или не менялись — отдаём прежний
		// сертификат. Ронять живые соединения из-за этого не за что.
		r.mu.Lock()
		r.lastCheck = time.Now()
		r.mu.Unlock()
		return cert, nil
	}

	fresh, freshStamp, err := loadPair(r.certFile, r.keyFile)
	if err != nil {
		r.mu.Lock()
		r.lastCheck = time.Now()
		r.mu.Unlock()
		return cert, nil
	}

	r.mu.Lock()
	r.cert, r.stamp, r.lastCheck = fresh, freshStamp, time.Now()
	r.mu.Unlock()
	return fresh, nil
}

func loadPair(certFile, keyFile string) (*tls.Certificate, string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("не удалось загрузить сертификат %s / ключ %s: %w", certFile, keyFile, err)
	}
	// Leaf нужен для проверки имени и срока без повторного разбора.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		if leaf, perr := parseLeaf(cert.Certificate[0]); perr == nil {
			cert.Leaf = leaf
		}
	}
	stamp, err := stampOf(certFile, keyFile)
	if err != nil {
		return nil, "", err
	}
	return &cert, stamp, nil
}

// stampOf — дешёвая подпись состояния файлов: время изменения и размер.
func stampOf(paths ...string) (string, error) {
	stamp := ""
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return "", err
		}
		stamp += fmt.Sprintf("%s:%d:%d;", p, info.ModTime().UnixNano(), info.Size())
	}
	return stamp, nil
}

// warnIfNameMismatch ловит на старте самую частую ошибку установки:
// сертификат без нужного SAN. Node.js игнорирует CN, поэтому клиент
// получил бы ERR_TLS_CERT_ALTNAME_INVALID уже в бою.
func warnIfNameMismatch(cert *tls.Certificate, domain string, log *slog.Logger) {
	if domain == "" || cert.Leaf == nil {
		return
	}
	if err := cert.Leaf.VerifyHostname(domain); err != nil {
		log.Warn("сертификат не подходит под имя шлюза — клиенты получат ERR_TLS_CERT_ALTNAME_INVALID",
			"domain", domain, "err", err)
	}
	if left := time.Until(cert.Leaf.NotAfter); left < 14*24*time.Hour {
		log.Warn("сертификат скоро истекает", "not_after", cert.Leaf.NotAfter.Format(time.RFC3339))
	}
}

// --- самоподписанный ---------------------------------------------------

func newSelfSigned(cfg *config.Config, log *slog.Logger) (*Provider, error) {
	dir := filepath.Join(cfg.StateDir, "self-signed")
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		if err := GenerateSelfSigned(cfg.Domain, dir, DefaultSelfSignedDays); err != nil {
			return nil, err
		}
		log.Info("сгенерирован самоподписанный сертификат", "dir", dir, "domain", cfg.Domain)
	}

	p, err := newFiles(certFile, keyFile, cfg.Domain, log)
	if err != nil {
		return nil, err
	}
	p.Description = fmt.Sprintf("самоподписанный сертификат из %s", dir)
	return p, nil
}
