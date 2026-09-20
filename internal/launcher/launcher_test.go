package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/seredavin/claude-proxy/internal/auth"
	"github.com/seredavin/claude-proxy/internal/config"
)

// Вместо claude запускается этот же бинарь: режим задаёт LAUNCHER_HELPER,
// результат пишется в HELPER_OUT. Так проверяется настоящее окружение
// настоящего дочернего процесса, а не то, что мы собирались ему передать.
func TestMain(m *testing.M) {
	mode := os.Getenv("LAUNCHER_HELPER")
	if mode == "" {
		os.Exit(m.Run())
	}
	out := os.Getenv("HELPER_OUT")
	switch mode {
	case "env":
		// Окружение и аргументы — как их видит ребёнок.
		body := strings.Join(os.Environ(), "\n") + "\nARGS=" + strings.Join(os.Args[1:], " ") + "\n"
		_ = os.WriteFile(out, []byte(body), 0o600)
		code, _ := strconv.Atoi(os.Getenv("HELPER_EXIT"))
		os.Exit(code)
	case "request":
		// Запрос через звено ровно так, как его сделал бы claude.
		req, err := http.NewRequest(http.MethodPost, os.Getenv("ANTHROPIC_BASE_URL")+"/v1/messages", strings.NewReader("{}"))
		if err != nil {
			os.Exit(2)
		}
		name, value, _ := strings.Cut(os.Getenv("ANTHROPIC_CUSTOM_HEADERS"), ": ")
		req.Header.Set(name, value)
		req.Header.Set("Authorization", "Bearer "+os.Getenv("ANTHROPIC_AUTH_TOKEN"))
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			_ = os.WriteFile(out, []byte("ошибка: "+err.Error()), 0o600)
			os.Exit(2)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = os.WriteFile(out, []byte(fmt.Sprintf("%d %s", resp.StatusCode, body)), 0o600)
		os.Exit(0)
	case "sleep":
		// Диспозиция сигналов — по умолчанию: SIGINT должен убивать.
		_ = os.WriteFile(out, []byte(strconv.Itoa(os.Getpid())), 0o600)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(99)
}

func testConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.Parse("local:secret")
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Mode:         config.ModeOAuth,
		Listen:       "127.0.0.1:0",
		Tokens:       tokens,
		Upstream:     target,
		UpstreamKey:  "EDGE",
		TLS:          config.TLSNone,
		MaxBodyBytes: 1 << 20,
		LogFormat:    "text",
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// helperEnv — окружение ребёнка: наше плюс режим и путь результата.
func helperEnv(mode, out string, extra ...string) []string {
	env := append(os.Environ(), "LAUNCHER_HELPER="+mode, "HELPER_OUT="+out)
	return append(env, extra...)
}

func waitFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("файл %s не появился", path)
	return ""
}

func TestRunПередаётОкружениеАргументыИКодВыхода(t *testing.T) {
	stub := httptest.NewServer(http.NotFoundHandler())
	defer stub.Close()
	out := filepath.Join(t.TempDir(), "env")

	var seenURL string
	code, err := Run(context.Background(), Options{
		Config:     testConfig(t, stub.URL),
		Logger:     discardLogger(),
		Token:      "secret",
		AuthToken:  "sk-ant-oat01-real",
		ClaudePath: os.Args[0],
		ClaudeArgs: []string{"-p", "вопрос"},
		Environ: helperEnv("env", out,
			"HELPER_EXIT=3",
			"EDITOR=vim",
			"CLAUDE_CODE_OAUTH_TOKEN=stale",
			"ANTHROPIC_API_KEY=stale",
			"ANTHROPIC_BASE_URL=https://stale.example.com",
		),
		Ready: func(baseURL string) { seenURL = baseURL },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 3 {
		t.Errorf("код выхода %d, ожидался 3 — как у ребёнка", code)
	}
	if !strings.HasPrefix(seenURL, "http://127.0.0.1:") || strings.HasSuffix(seenURL, ":0") {
		t.Errorf("Ready получил %q, ожидался адрес с настоящим портом", seenURL)
	}

	got := waitFile(t, out)
	want := []string{
		"ANTHROPIC_BASE_URL=" + seenURL + "\n",
		"ANTHROPIC_CUSTOM_HEADERS=X-Gateway-Key: secret\n",
		"ANTHROPIC_AUTH_TOKEN=sk-ant-oat01-real\n",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1\n",
		"EDITOR=vim\n",
		"ARGS=-p вопрос\n",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("нет %q в окружении ребёнка:\n%s", w, got)
		}
	}
	for _, absent := range []string{"CLAUDE_CODE_OAUTH_TOKEN=", "ANTHROPIC_API_KEY=", "stale"} {
		if strings.Contains(got, absent) {
			t.Errorf("%q не должно быть в окружении ребёнка:\n%s", absent, got)
		}
	}
	if strings.Count(got, "ANTHROPIC_BASE_URL=") != 1 {
		t.Errorf("ANTHROPIC_BASE_URL должна быть ровно одна:\n%s", got)
	}
}

func TestRunЗапросРебёнкаДоходитДоАпстримаСПропускомВнешнегоЗвена(t *testing.T) {
	var seenKey, seenAuth string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = r.Header.Get("X-Gateway-Key")
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "edge ok")
	}))
	defer stub.Close()
	out := filepath.Join(t.TempDir(), "resp")

	code, err := Run(context.Background(), Options{
		Config:     testConfig(t, stub.URL),
		Logger:     discardLogger(),
		Token:      "secret",
		AuthToken:  "sk-ant-oat01-real",
		ClaudePath: os.Args[0],
		Environ:    helperEnv("request", out),
	})
	if err != nil || code != 0 {
		t.Fatalf("Run = %d, %v; ответ ребёнка: %s", code, err, waitFile(t, out))
	}
	if got := waitFile(t, out); got != "200 edge ok" {
		t.Errorf("ребёнок получил %q", got)
	}
	if seenKey != "EDGE" {
		t.Errorf("внешнее звено увидело X-Gateway-Key = %q, ожидался EDGE", seenKey)
	}
	if seenAuth != "Bearer sk-ant-oat01-real" {
		t.Errorf("внешнее звено увидело Authorization = %q", seenAuth)
	}
}

// Запуск «спящего» ребёнка: возвращает его pid, адрес звена и канал результата.
func startSleeper(t *testing.T, ctx context.Context, o Options) (pid int, baseURL string, done <-chan struct {
	code int
	err  error
}) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "pid")
	ready := make(chan string, 1)
	o.ClaudePath = os.Args[0]
	o.Environ = helperEnv("sleep", out)
	o.Ready = func(u string) { ready <- u }
	if o.Logger == nil {
		o.Logger = discardLogger()
	}

	result := make(chan struct {
		code int
		err  error
	}, 1)
	go func() {
		code, err := Run(ctx, o)
		result <- struct {
			code int
			err  error
		}{code, err}
	}()

	select {
	case baseURL = <-ready:
	case r := <-result:
		t.Fatalf("Run завершился до готовности: %d, %v", r.code, r.err)
	case <-time.After(5 * time.Second):
		t.Fatal("звено не поднялось")
	}
	pid, err := strconv.Atoi(waitFile(t, out))
	if err != nil {
		t.Fatal(err)
	}
	return pid, baseURL, result
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func healthy(baseURL string) bool {
	resp, err := (&http.Client{Timeout: time.Second}).Get(baseURL + "/healthz")
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func TestRunSIGINTНеГаситЗвеноAСамРебёнокЕгоПолучает(t *testing.T) {
	stub := httptest.NewServer(http.NotFoundHandler())
	defer stub.Close()
	pid, baseURL, result := startSleeper(t, context.Background(), Options{Config: testConfig(t, stub.URL), Token: "secret"})

	// Ctrl+C: терминал шлёт его группе, здесь — самому запускателю.
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if !healthy(baseURL) {
		t.Fatal("после SIGINT запускателю звено должно жить")
	}
	if !alive(pid) {
		t.Fatal("после SIGINT запускателю ребёнок должен жить — сигнал ему не пересылается")
	}

	// А вот сам ребёнок SIGINT игнорировать не должен: диспозиция
	// запускателя ему не достаётся.
	if err := syscall.Kill(pid, syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-result:
		if r.err != nil {
			t.Errorf("Run: %v", r.err)
		}
		if r.code != 1 {
			t.Errorf("ребёнок убит сигналом — код %d, ожидался 1", r.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ребёнок не завершился по SIGINT — унаследовал игнорирование")
	}
	if healthy(baseURL) {
		t.Error("после выхода ребёнка звено должно быть погашено")
	}
}

func TestRunSIGTERMПересылаетсяРебёнку(t *testing.T) {
	stub := httptest.NewServer(http.NotFoundHandler())
	defer stub.Close()
	pid, baseURL, result := startSleeper(t, context.Background(), Options{Config: testConfig(t, stub.URL), Token: "secret"})

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-result:
		if r.err != nil {
			t.Errorf("Run: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился после SIGTERM")
	}
	if alive(pid) {
		t.Error("ребёнок должен был получить SIGTERM")
	}
	if healthy(baseURL) {
		t.Error("звено должно быть погашено")
	}
}

func TestRunПадениеЗвенаЗавершаетРебёнка(t *testing.T) {
	stub := httptest.NewServer(http.NotFoundHandler())
	defer stub.Close()

	// Поддельное звено: занимает порт, сообщает готовность, по команде падает.
	fail := make(chan struct{})
	fake := func(ctx context.Context, _ *config.Config, _ *slog.Logger, ready func(net.Addr)) error {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer ln.Close()
		ready(ln.Addr())
		select {
		case <-fail:
			return errors.New("слушатель упал")
		case <-ctx.Done():
			return nil
		}
	}

	pid, _, result := startSleeper(t, context.Background(), Options{
		Config:     testConfig(t, stub.URL),
		Token:      "secret",
		runGateway: fake,
	})
	close(fail)

	select {
	case r := <-result:
		if r.err == nil || !strings.Contains(r.err.Error(), "слушатель упал") {
			t.Errorf("ожидалась ошибка звена, получено %v", r.err)
		}
		if r.code != 1 {
			t.Errorf("код %d, ожидался 1", r.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run не завершился после падения звена")
	}
	if alive(pid) {
		t.Error("ребёнок должен быть завершён вместе со звеном")
	}
}

func TestRunОтменаКонтекстаГаситОбоих(t *testing.T) {
	stub := httptest.NewServer(http.NotFoundHandler())
	defer stub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	pid, baseURL, result := startSleeper(t, ctx, Options{Config: testConfig(t, stub.URL), Token: "secret"})

	cancel()
	select {
	case r := <-result:
		if r.err != nil {
			t.Errorf("штатная остановка — без ошибки, получено %v", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run не завершился после отмены контекста")
	}
	if alive(pid) || healthy(baseURL) {
		t.Error("после отмены контекста ни ребёнка, ни звена быть не должно")
	}
}

func TestRunЗвеноНеПоднялосьРебёнокНеЗапускается(t *testing.T) {
	fake := func(context.Context, *config.Config, *slog.Logger, func(net.Addr)) error {
		return errors.New("порт занят")
	}
	code, err := Run(context.Background(), Options{
		Config:     &config.Config{},
		Logger:     discardLogger(),
		ClaudePath: "/nonexistent/claude",
		runGateway: fake,
	})
	if err == nil || !strings.Contains(err.Error(), "порт занят") {
		t.Errorf("ожидалась ошибка звена, получено %v", err)
	}
	if code != 1 {
		t.Errorf("код %d, ожидался 1", code)
	}
}

func TestEnvironРежимAPIKeyНеТрогаетТокенПодписки(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeAPIKey, Listen: "127.0.0.1:9443", TLS: config.TLSNone}
	env := Environ([]string{"HOME=/home/u", "ANTHROPIC_API_KEY=console"}, cfg, "pass", "ignored")
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "ANTHROPIC_AUTH_TOKEN=pass\n") && !strings.HasSuffix(joined, "ANTHROPIC_AUTH_TOKEN=pass") {
		t.Errorf("в apikey клиент предъявляет пропуск:\n%s", joined)
	}
	if strings.Contains(joined, "ANTHROPIC_API_KEY=") {
		t.Errorf("ключ Console не должен уходить claude:\n%s", joined)
	}
	if !strings.Contains(joined, "HOME=/home/u") {
		t.Errorf("чужие переменные сохраняются:\n%s", joined)
	}
}
