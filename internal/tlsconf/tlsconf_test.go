package tlsconf

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func TestGenerateSelfSignedDNS(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("claude-proxy.internal", dir, 30); err != nil {
		t.Fatal(err)
	}

	cert, _, err := loadPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Leaf.VerifyHostname("claude-proxy.internal"); err != nil {
		t.Errorf("имя не попало в SAN: %v", err)
	}
	if err := cert.Leaf.VerifyHostname("other.internal"); err == nil {
		t.Error("сертификат принял чужое имя")
	}
	if !cert.Leaf.IsCA {
		t.Error("сертификат не помечен как CA — на клиентах он служит якорем доверия")
	}
	if left := time.Until(cert.Leaf.NotAfter); left > 31*24*time.Hour || left < 29*24*time.Hour {
		t.Errorf("срок действия %v не соответствует запрошенным 30 дням", left)
	}
}

func TestGenerateSelfSignedIP(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("10.0.0.5", dir, 30); err != nil {
		t.Fatal(err)
	}
	cert, _, err := loadPair(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("IP не попал в SAN: %v", cert.Leaf.IPAddresses)
	}
	if len(cert.Leaf.DNSNames) != 0 {
		t.Errorf("для IP не должно быть DNS-имён: %v", cert.Leaf.DNSNames)
	}
}

func TestGenerateSelfSignedПраваНаКлюч(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("x.internal", dir, 30); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("права на приватный ключ %o, ожидалось 600", info.Mode().Perm())
	}
}

func TestGenerateSelfSignedОтказы(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("", dir, 30); err == nil {
		t.Error("пустое имя принято")
	}
	if err := GenerateSelfSigned("x.internal", dir, 0); err == nil {
		t.Error("нулевой срок принят")
	}
}

func TestFilesПадаетНаОтсутствующемФайле(t *testing.T) {
	var logs bytes.Buffer
	_, err := newFiles("/nope/fullchain.pem", "/nope/privkey.pem", "x", testLogger(&logs))
	if err == nil {
		t.Fatal("отсутствующий сертификат не уронил старт")
	}
	if !strings.Contains(err.Error(), "fullchain.pem") {
		t.Errorf("в ошибке нет пути: %v", err)
	}
}

func TestFilesПредупреждаетОНесовпаденииИмени(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("real.internal", dir, 30); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	_, err := newFiles(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"),
		"other.internal", testLogger(&logs))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "ALTNAME") {
		t.Errorf("нет предупреждения о несовпадении имени: %s", logs.String())
	}
}

func TestFilesПредупреждаетОСкоромИстечении(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateSelfSigned("real.internal", dir, 3); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	if _, err := newFiles(filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"),
		"real.internal", testLogger(&logs)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "истекает") {
		t.Errorf("нет предупреждения об истечении: %s", logs.String())
	}
}

func TestReloaderПодхватываетНовуюПару(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	if err := GenerateSelfSigned("first.internal", dir, 30); err != nil {
		t.Fatal(err)
	}

	cert, stamp, err := loadPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r := &reloader{
		certFile: certFile, keyFile: keyFile,
		cert: cert, stamp: stamp,
		// Проверку не троттлим: имитируем, что интервал уже истёк.
		lastCheck: time.Now().Add(-time.Hour),
	}

	// Пока файлы не менялись — тот же сертификат.
	got, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.Subject.CommonName != "first.internal" {
		t.Fatalf("CN = %q", got.Leaf.Subject.CommonName)
	}

	// Перевыпускаем на другое имя, как это сделал бы certbot.
	if err := GenerateSelfSigned("second.internal", dir, 30); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.lastCheck = time.Now().Add(-time.Hour)
	r.mu.Unlock()

	got, err = r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Leaf.Subject.CommonName != "second.internal" {
		t.Errorf("новый сертификат не подхвачен, CN = %q", got.Leaf.Subject.CommonName)
	}
}

func TestReloaderПереживаетИсчезновениеФайлов(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	if err := GenerateSelfSigned("first.internal", dir, 30); err != nil {
		t.Fatal(err)
	}
	cert, stamp, err := loadPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r := &reloader{
		certFile: certFile, keyFile: keyFile,
		cert: cert, stamp: stamp,
		lastCheck: time.Now().Add(-time.Hour),
	}

	// Момент между удалением и записью новой пары не должен ронять рукопожатия.
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("исчезнувший файл сломал выдачу сертификата: %v", err)
	}
	if got.Leaf.Subject.CommonName != "first.internal" {
		t.Errorf("CN = %q, ожидался прежний сертификат", got.Leaf.Subject.CommonName)
	}
}

func TestNewSelfГенерируетПриПервомЗапуске(t *testing.T) {
	stateDir := t.TempDir()
	var logs bytes.Buffer
	cfg := &config.Config{TLS: config.TLSSelf, Domain: "lab.internal", StateDir: stateDir}

	p, err := New(cfg, testLogger(&logs))
	if err != nil {
		t.Fatal(err)
	}
	if p.TLSConfig.GetCertificate == nil {
		t.Fatal("GetCertificate не задан")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "self-signed", "fullchain.pem")); err != nil {
		t.Errorf("сертификат не создан: %v", err)
	}
	if p.HTTPHandler != nil {
		t.Error("для self не нужен слушатель HTTP-01")
	}
}

func TestNewAutoТребуетHTTPСлушатель(t *testing.T) {
	stateDir := t.TempDir()
	var logs bytes.Buffer
	cfg := &config.Config{
		TLS: config.TLSAuto, Domain: "proxy.example.com",
		StateDir: stateDir, ACMEHTTP: ":80", ACMEEmail: "a@example.com",
	}

	p, err := New(cfg, testLogger(&logs))
	if err != nil {
		t.Fatal(err)
	}
	if p.HTTPHandler == nil || p.HTTPAddr != ":80" {
		t.Error("ACME без слушателя HTTP-01 не выпустит сертификат")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "acme")); err != nil {
		t.Errorf("кэш ACME не создан: %v", err)
	}
}

func TestBaseTLSConfig(t *testing.T) {
	tc := baseTLSConfig()
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, ожидалось TLS 1.2", tc.MinVersion)
	}
	if len(tc.NextProtos) == 0 || tc.NextProtos[0] != "h2" {
		t.Errorf("NextProtos = %v, HTTP/2 должен предлагаться первым", tc.NextProtos)
	}
}
