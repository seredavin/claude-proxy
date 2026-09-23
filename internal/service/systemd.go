// Package service ставит и снимает systemd-юнит шлюза.
package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
)

// ServiceUser — системный пользователь, от которого работает шлюз.
// Он не владеет ничем, кроме каталога состояния, и не имеет shell.
const ServiceUser = "claude-proxy"

// UnitPath — путь юнита. Каталог фиксирован systemd.
const UnitPath = "/etc/systemd/system/" + config.ServiceName + ".service"

// InstallOptions — параметры установки.
type InstallOptions struct {
	// Raw — конфигурация, которая ляжет в EnvironmentFile.
	Raw config.Raw
	// Resolved — та же конфигурация после проверки; нужна для подсказки клиенту.
	Resolved *config.Config
	// RunAs — пользователь юнита. Пусто — ServiceUser.
	RunAs string
	// Out — куда печатать ход установки.
	Out io.Writer
}

// Install раскладывает бинарь, конфигурацию и юнит, затем запускает сервис.
//
// Идемпотентна: повторный запуск сохраняет уже выданные токены шлюза —
// их могли разнести по клиентам.
func Install(opts InstallOptions) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("установка сервиса поддерживается только на Linux с systemd (текущая ОС: %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("нужны права root: sudo claude-proxy install ...")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl не найден — на этой системе нет systemd")
	}

	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	runAs := opts.RunAs
	if runAs == "" {
		runAs = ServiceUser
	}

	binPath, err := placeBinary(out)
	if err != nil {
		return err
	}

	if runAs == ServiceUser {
		if err := ensureUser(out); err != nil {
			return err
		}
	}

	// Файл правил маскирования сервис читает на старте; без доступа он
	// не поднимется — проверяем до записи конфигурации.
	if opts.Resolved.MaskRules != "" {
		if err := checkRulesReadable(opts.Resolved.MaskRules, runAs); err != nil {
			return err
		}
	}
	// Ключ уже проверен при разборе конфигурации (формат и права); здесь —
	// что сервисный пользователь его прочитает.
	if opts.Resolved.MaskKeyFile != "" {
		if err := checkMaskKeyReadable(opts.Resolved.MaskKeyFile, runAs); err != nil {
			return err
		}
	}

	if err := writeEnvFile(opts.Raw, out); err != nil {
		return err
	}

	// Без TLS каталог состояния не нужен и может быть не задан вовсе.
	if opts.Resolved.StateDir != "" {
		if err := prepareStateDir(opts.Resolved.StateDir, runAs, out); err != nil {
			return err
		}
	}

	// В режиме files сервис читает чужие файлы — проверяем это заранее,
	// иначе отказ вылезет уже на первом рукопожатии TLS.
	if opts.Resolved.TLS == config.TLSFiles {
		checkCertReadable(opts.Resolved, runAs, out)
	}

	if err := writeUnit(binPath, runAs, opts.Resolved.StateDir, out); err != nil {
		return err
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", config.ServiceName); err != nil {
		return fmt.Errorf("не удалось запустить сервис: %w (логи: journalctl -u %s -n 50)", err, config.ServiceName)
	}
	fmt.Fprintf(out, "  ok сервис %s запущен\n", config.ServiceName)

	timeout := 30 * time.Second
	if opts.Resolved.TLS == config.TLSAuto {
		// Первое рукопожатие тянет за собой заказ в Let's Encrypt и проверку
		// HTTP-01 — это заметно дольше обычного старта.
		timeout = 3 * time.Minute
		fmt.Fprintf(out, "  .. жду выпуск сертификата для %s, это может занять минуту\n",
			opts.Resolved.Domain)
	}

	plain := opts.Resolved.TLS == config.TLSNone
	if err := waitHealthy(opts.Resolved.Listen, opts.Resolved.Domain, plain, timeout); err != nil {
		if opts.Resolved.TLS == config.TLSAuto {
			return fmt.Errorf("%w\n    частые причины: порт 80 закрыт снаружи, A-запись ведёт не на этот хост, исчерпан лимит Let's Encrypt\n    логи: journalctl -u %s -n 50", err, config.ServiceName)
		}
		return fmt.Errorf("%w (логи: journalctl -u %s -n 50)", err, config.ServiceName)
	}
	fmt.Fprintf(out, "  ok шлюз отвечает на /healthz\n")
	return nil
}

// Uninstall останавливает сервис и убирает юнит.
// Конфигурация и состояние остаются, если не задан purge.
func Uninstall(purge bool, out io.Writer) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("удаление сервиса поддерживается только на Linux с systemd")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("нужны права root: sudo claude-proxy uninstall")
	}
	if out == nil {
		out = io.Discard
	}

	// Ошибки здесь не критичны: сервиса могло уже не быть.
	_ = run("systemctl", "disable", "--now", config.ServiceName)

	if err := os.Remove(UnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление %s: %w", UnitPath, err)
	}
	_ = run("systemctl", "daemon-reload")
	fmt.Fprintf(out, "  ok юнит удалён\n")

	if !purge {
		fmt.Fprintf(out, "  ! конфигурация %s и состояние %s оставлены (удалить: --purge)\n",
			config.DefaultConfigFile, config.DefaultStateDir)
		return nil
	}

	for _, path := range []string{config.DefaultConfigDir, config.DefaultStateDir, config.DefaultBinPath} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("удаление %s: %w", path, err)
		}
		fmt.Fprintf(out, "  ok удалён %s\n", path)
	}
	return nil
}

// --- шаги установки ----------------------------------------------------

// placeBinary копирует запущенный файл в системный каталог, если он
// запущен откуда-то ещё (например из ~/downloads).
func placeBinary(out io.Writer) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("не удалось определить путь к себе: %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", fmt.Errorf("не удалось разрешить путь к себе: %w", err)
	}

	target := config.DefaultBinPath
	if self == target {
		return target, nil
	}

	data, err := os.ReadFile(self)
	if err != nil {
		return "", fmt.Errorf("чтение %s: %w", self, err)
	}
	// Пишем во временный файл рядом и переименовываем: если бинарь сейчас
	// выполняется, перезапись на месте дала бы ETXTBSY.
	tmp := target + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", fmt.Errorf("запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return "", fmt.Errorf("установка %s: %w", target, err)
	}
	fmt.Fprintf(out, "  ok бинарь установлен в %s\n", target)
	return target, nil
}

func ensureUser(out io.Writer) error {
	if _, err := user.Lookup(ServiceUser); err == nil {
		return nil
	}
	err := run("useradd", "--system", "--no-create-home",
		"--home-dir", config.DefaultStateDir,
		"--shell", "/usr/sbin/nologin", ServiceUser)
	if err != nil {
		return fmt.Errorf("не удалось создать пользователя %s: %w", ServiceUser, err)
	}
	fmt.Fprintf(out, "  ok создан системный пользователь %s\n", ServiceUser)
	return nil
}

func prepareStateDir(dir, runAs string, out io.Writer) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("каталог состояния %s: %w", dir, err)
	}
	uid, gid, err := lookupIDs(runAs)
	if err != nil {
		return err
	}
	if err := chownTree(dir, uid, gid); err != nil {
		return fmt.Errorf("владелец %s: %w", dir, err)
	}
	fmt.Fprintf(out, "  ok каталог состояния %s\n", dir)
	return nil
}

// writeEnvFile пишет EnvironmentFile, сохраняя прежние токены шлюза.
func writeEnvFile(raw config.Raw, out io.Writer) error {
	if existing := existingTokens(); existing != "" && raw.Tokens == "" {
		raw.Tokens = existing
		fmt.Fprintf(out, "  ok токены шлюза сохранены из прежней конфигурации\n")
	}

	if err := os.MkdirAll(config.DefaultConfigDir, 0o755); err != nil {
		return fmt.Errorf("каталог %s: %w", config.DefaultConfigDir, err)
	}

	// Читаем прежний файл до записи: своё оператор мог дописать руками.
	foreign := foreignEnvLines(config.DefaultConfigFile)

	var b strings.Builder
	b.WriteString("# Создано claude-proxy install " + time.Now().Format("2006-01-02") + "\n")
	b.WriteString("# Значения отсюда перебивают флаги в ExecStart.\n\n")
	for _, kv := range envLines(raw) {
		b.WriteString(kv + "\n")
	}
	if len(foreign) > 0 {
		b.WriteString("\n# Добавлено оператором — install переносит эти строки как есть.\n")
		for _, line := range foreign {
			b.WriteString(line + "\n")
		}
	}

	// 0600: внутри токены шлюза и, в режиме apikey, ключ Console.
	if err := os.WriteFile(config.DefaultConfigFile, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("запись %s: %w", config.DefaultConfigFile, err)
	}
	// Режим в WriteFile действует только при создании файла. Если он уже
	// существовал с более широкими правами, их надо ужать явно.
	if err := os.Chmod(config.DefaultConfigFile, 0o600); err != nil {
		return fmt.Errorf("права на %s: %w", config.DefaultConfigFile, err)
	}
	fmt.Fprintf(out, "  ok конфигурация %s (режим 600)\n", config.DefaultConfigFile)
	if len(foreign) > 0 {
		fmt.Fprintf(out, "  ok перенесено переменных оператора: %d\n", len(foreign))
	}
	return nil
}

// foreignEnvLines достаёт из прежнего EnvironmentFile строки, которых
// claude-proxy там не писал: их поставил оператор. Типичные примеры —
// SSL_CERT_FILE (доверие следующему звену цепочки) и HTTPS_PROXY (исход
// наружу через корпоративный прокси). Файл перезаписывается целиком,
// поэтому без такого переноса переустановка молча гасила бы эти настройки.
func foreignEnvLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	managed := map[string]bool{}
	for _, key := range config.ManagedEnvKeys() {
		managed[key] = true
	}

	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, found := strings.Cut(line, "=")
		if !found || managed[strings.TrimSpace(key)] {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// envLines превращает Raw в строки EnvironmentFile, пропуская пустые значения.
func envLines(raw config.Raw) []string {
	pairs := []struct{ key, value string }{
		{"CLAUDE_PROXY_MODE", raw.Mode},
		{"CLAUDE_PROXY_LISTEN", raw.Listen},
		{"CLAUDE_PROXY_DOMAIN", raw.Domain},
		{"CLAUDE_PROXY_TOKENS", raw.Tokens},
		{"CLAUDE_PROXY_ANTHROPIC_API_KEY", raw.APIKey},
		{"CLAUDE_PROXY_UPSTREAM", raw.Upstream},
		{"CLAUDE_PROXY_UPSTREAM_KEY", raw.UpstreamKey},
		{"CLAUDE_PROXY_TLS", raw.TLS},
		{"CLAUDE_PROXY_CERT_FILE", raw.CertFile},
		{"CLAUDE_PROXY_KEY_FILE", raw.KeyFile},
		{"CLAUDE_PROXY_ACME_EMAIL", raw.ACMEEmail},
		{"CLAUDE_PROXY_ACME_HTTP", raw.ACMEHTTP},
		{"CLAUDE_PROXY_ACME_DIRECTORY", raw.ACMEDirectory},
		{"CLAUDE_PROXY_STATE_DIR", raw.StateDir},
		{"CLAUDE_PROXY_MAX_BODY", raw.MaxBody},
		{"CLAUDE_PROXY_LOG_FORMAT", raw.LogFormat},
		{"CLAUDE_PROXY_MASK_RULES", raw.MaskRules},
		{"CLAUDE_PROXY_MASK_ON_ERROR", raw.MaskOnError},
		{"CLAUDE_PROXY_MASK_DEBUG", raw.MaskDebug},
		{"CLAUDE_PROXY_MASK_KEY_FILE", raw.MaskKeyFile},
		{"CLAUDE_PROXY_TRACE_DIR", raw.TraceDir},
	}

	var lines []string
	for _, p := range pairs {
		if p.value == "" {
			continue
		}
		lines = append(lines, p.key+"="+quoteEnv(p.value))
	}
	return lines
}

// quoteEnv оборачивает значение в двойные кавычки, экранируя то, что
// systemd разбирает внутри них.
func quoteEnv(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`)
	return `"` + r.Replace(v) + `"`
}

// existingTokens достаёт токены из уже лежащей конфигурации, чтобы
// переустановка не выдала клиентам новый пропуск.
func existingTokens() string {
	data, err := os.ReadFile(config.DefaultConfigFile)
	if err != nil {
		return ""
	}
	for _, key := range []string{"CLAUDE_PROXY_TOKENS", "GATEWAY_TOKEN"} {
		if v := envValue(string(data), key); v != "" {
			return v
		}
	}
	return ""
}

func envValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}
		return strings.Trim(value, `"'`)
	}
	return ""
}

func writeUnit(binPath, runAs, stateDir string, out io.Writer) error {
	// Свой каталог состояния systemd не создаёт: он лишь открывает его на
	// запись, а владельца выставил prepareStateDir. StateDirectory остаётся
	// только для пути по умолчанию, иначе systemd плодил бы рядом пустой
	// /var/lib/claude-proxy, которым никто не пользуется.
	stateLines := "ReadWritePaths=" + stateDir + "\n"
	switch stateDir {
	case config.DefaultStateDir:
		stateLines = fmt.Sprintf("StateDirectory=%s\nStateDirectoryMode=0700\n", config.ServiceName)
	case "":
		// --tls none без каталога состояния: сервису некуда писать.
		stateLines = ""
	}

	unit := fmt.Sprintf(`[Unit]
Description=claude-proxy — TLS-шлюз к Anthropic API
Documentation=https://github.com/seredavin/claude-proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=%s
ExecStart=%s run
Restart=on-failure
RestartSec=5s
EnvironmentFile=%s

# Проверка HTTP-01 идёт по порту 80 — привилегированному.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Каталог состояния: кэш ACME и самоподписанные сертификаты.
%s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
SystemCallArchitectures=native
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, runAs, binPath, config.DefaultConfigFile, stateLines)

	if err := os.WriteFile(UnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("запись %s: %w", UnitPath, err)
	}
	fmt.Fprintf(out, "  ok юнит %s\n", UnitPath)
	return nil
}

// checkCertReadable предупреждает, если сервисный пользователь не сможет
// прочитать сертификат. Обычный случай: privkey.pem с правами 600 root.
func checkCertReadable(cfg *config.Config, runAs string, out io.Writer) {
	uid, gid, err := lookupIDs(runAs)
	if err != nil {
		return
	}
	for _, path := range []string{cfg.CertFile, cfg.KeyFile} {
		if readableBy(path, uid, gid) {
			continue
		}
		fmt.Fprintf(out, "  ! пользователь %s не может прочитать %s\n", runAs, path)
		fmt.Fprintf(out, "    выдайте доступ (setfacl -m u:%s:r %s) или ставьте с --service-user root\n", runAs, path)
	}
}

// checkRulesReadable отказывает, если сервисный пользователь не прочитает
// файл правил маскирования. В отличие от сертификатов это не предупреждение:
// без правил шлюз не стартует вовсе.
func checkRulesReadable(path, runAs string) error {
	uid, gid, err := lookupIDs(runAs)
	if err != nil {
		return nil
	}
	return rulesReadableBy(path, uid, gid, runAs)
}

func rulesReadableBy(path string, uid, gid int, runAs string) error {
	if readableBy(path, uid, gid) {
		return nil
	}
	return fmt.Errorf("пользователь %s не может прочитать файл правил %s\n    выдайте доступ (setfacl -m u:%s:r %s) или ставьте с --service-user root",
		runAs, path, runAs, path)
}

// checkMaskKeyReadable отказывает, если сервисный пользователь не прочитает
// ключ маскирования.
func checkMaskKeyReadable(path, runAs string) error {
	uid, gid, err := lookupIDs(runAs)
	if err != nil {
		return nil
	}
	return maskKeyReadableBy(path, uid, gid, runAs)
}

// maskKeyReadableBy — в отличие от файла правил подсказка не setfacl: ACL
// поднимает групповые биты режима, и ключ перестанет проходить проверку
// прав. Файл передаётся сервисному пользователю во владение.
func maskKeyReadableBy(path string, uid, gid int, runAs string) error {
	if readableBy(path, uid, gid) {
		return nil
	}
	return fmt.Errorf("пользователь %s не может прочитать ключ маскирования %s\n    передайте файл сервису: chown %s %s (права оставьте 600) или ставьте с --service-user root",
		runAs, path, runAs, path)
}

// waitHealthy дожидается ответа шлюза на /healthz.
//
// Соединение идёт на 127.0.0.1, но имя в SNI подставляется настоящее.
// Это обязательно: в режиме auto сертификат выбирает autocert, а без имени
// сервера он не знает, какой выдавать, и рвёт рукопожатие с «missing server
// name». Заодно первый такой запрос и запускает выпуск сертификата, поэтому
// установка честно падает здесь, если Let's Encrypt не может достучаться
// до порта 80.
//
// plain — слушатель без TLS (источник none): запрос идёт по http, имя
// сервера не нужно, а соединение — на тот loopback-адрес, который задан
// слушателю: сокет на [::1] по 127.0.0.1 недоступен.
func waitHealthy(listen, serverName string, plain bool, timeout time.Duration) error {
	listenHost, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("не разобрать адрес %q: %w", listen, err)
	}
	if serverName == "" {
		serverName = "localhost"
	}

	// Стучимся на петлю независимо от того, куда указывает имя:
	// внутренний DNS может не знать его или вести на внешний адрес.
	dialHost := "127.0.0.1"
	if plain {
		dialHost = listenHost
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(dialHost, port))
		},
	}
	scheme := "http://"
	if !plain {
		// Имя проверяем отдельно, после установки. Здесь важно только то,
		// что шлюз поднялся и смог предъявить сертификат.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: serverName} //nolint:gosec
		scheme = "https://"
	}
	client := &http.Client{
		Timeout:   30 * time.Second, // выпуск сертификата идёт внутри рукопожатия
		Transport: transport,
	}
	url := scheme + net.JoinHostPort(serverName, port) + "/healthz"

	var lastErr error
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("ответ %s", resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("шлюз не ответил на %s за %s: %w", url, timeout, lastErr)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, trimmed)
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func lookupIDs(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("пользователь %s не найден: %w", name, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("нечисловой uid у %s: %w", name, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("нечисловой gid у %s: %w", name, err)
	}
	return uid, gid, nil
}

func chownTree(root string, uid, gid int) error {
	return filepath.Walk(root, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}
