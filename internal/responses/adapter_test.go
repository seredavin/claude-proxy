package responses

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seredavin/claude-proxy/internal/config"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChatGPTLimitIsReturnedToClaude(t *testing.T) {
	for _, tc := range []struct {
		stream  bool
		request string
		status  int
	}{
		{false, `{"model":"claude-test","messages":[{"role":"user","content":"hello"}]}`, 429},
		{true, `{"model":"claude-test","messages":[{"role":"user","content":"hello"}],"stream":true}`, 200},
	} {
		a := Adapter{
			AccessToken: func(context.Context, string) (string, error) { return "oauth-secret", nil },
			Transport: testTransport(func(req *http.Request) (*http.Response, error) {
				req.Body.Close()
				wire := "data: " + `{"type":"response.failed","response":{"error":{"code":"subscription_sharing_usage_limit_exceeded"}}}` + "\n\n"
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire))}, nil
			}),
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(tc.request))
		got, err := a.RoundTrip(req, &config.OpenAITarget{Profile: "test", Model: "gpt-test"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(got.Body)
		got.Body.Close()
		if err != nil || got.StatusCode != tc.status || !strings.Contains(string(body), `"type":"rate_limit_error"`) ||
			strings.Contains(string(body), "oauth-secret") || (tc.stream && !strings.HasPrefix(string(body), "event: error\n")) {
			t.Fatalf("ошибка лимита: %d %s (%v)", got.StatusCode, body, err)
		}
	}
}
