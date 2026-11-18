package gateway

import (
	"io"
	"net/http"

	"github.com/seredavin/claude-proxy/internal/responses"
	"github.com/seredavin/claude-proxy/internal/trace"
)

func isOpenAIRequest(req *http.Request) bool {
	rt := routeFromContext(req.Context())
	return rt != nil && rt.openAI != nil
}

type providerTransport struct {
	base   http.RoundTripper
	openAI responses.Adapter
}

func (t providerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := routeFromContext(req.Context())
	if rt == nil || rt.openAI == nil {
		return t.base.RoundTrip(req)
	}
	var hooks *responses.Trace
	if ts, _ := req.Context().Value(traceStateKey{}).(*traceState); ts != nil {
		hooks = &responses.Trace{
			Request: func(h http.Header, body []byte) {
				ts.requestHeaders = trace.Headers(h)
				ts.rec.WriteRequest(trace.Upstream, body)
			},
			Response: func(h http.Header, body io.Reader) io.Reader {
				ts.upstreamHeaders = trace.Headers(h)
				return io.TeeReader(body, ts.rec.ResponseWriter(trace.Upstream))
			},
		}
	}
	return t.openAI.RoundTrip(req, rt.openAI, hooks)
}
