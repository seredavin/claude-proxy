package responses

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/seredavin/claude-proxy/internal/config"
)

// Trace принимает запрос и поток ответа на границе Responses API.
type Trace struct {
	Request  func(http.Header, []byte)
	Response func(http.Header, io.Reader) io.Reader
}

type Adapter struct {
	Transport   http.RoundTripper
	AccessToken func(context.Context, string) (string, error)
}

type upstreamFailure struct {
	status  int
	kind    string
	message string
}

func (e upstreamFailure) Error() string { return e.message }

func failure(e event) upstreamFailure {
	code := e.Response.Error.Code
	if code == "" {
		code = e.Code
	}
	switch code {
	case "subscription_sharing_usage_limit_exceeded", "rate_limit_exceeded":
		return upstreamFailure{429, "rate_limit_error", "OpenAI сообщил об ограничении использования плана ChatGPT"}
	case "subscription_sharing_usage_unavailable", "subscription_sharing_user_unavailable":
		return upstreamFailure{503, "overloaded_error", "Проверка доступности плана ChatGPT временно недоступна"}
	case "subscription_sharing_user_not_eligible", "subscription_sharing_route_not_supported":
		return upstreamFailure{403, "permission_error", "Использование плана ChatGPT недоступно для выбранного аккаунта или настроек"}
	case "subscription_sharing_unsupported_capability":
		return upstreamFailure{400, "invalid_request_error", "Запрос использует возможность, недоступную по плану ChatGPT"}
	default:
		return upstreamFailure{502, "api_error", "OpenAI завершил запрос с ошибкой"}
	}
}

func errorMessage(kind, message string) object {
	return object{"type": "error", "error": object{"type": kind, "message": message}}
}

func jsonResponse(req *http.Request, status int, value object) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Request: req, ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}
}

func (a Adapter) RoundTrip(req *http.Request, target *config.OpenAITarget, trace *Trace) (*http.Response, error) {
	if req.Body == nil {
		req.Body = http.NoBody
	}
	defer req.Body.Close()
	if req.Method == http.MethodGet && req.URL.Path == "/v1/models" {
		return listModels(req, target), nil
	}
	native := req.URL.Path == Path
	if req.Method != http.MethodPost || (!native && req.URL.Path != "/v1/messages" && req.URL.Path != "/v1/messages/count_tokens") {
		return jsonResponse(req, 404, errorMessage("not_found_error", "маршрут OpenAI поддерживает Messages, count_tokens, Models и Responses")), nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var client messageRequest
	var payload []byte
	if native {
		payload, err = nativeRequest(body, target)
		if err != nil {
			return nativeError(req, 400, "invalid_request_error", err.Error()), nil
		}
	} else {
		client, payload, err = convertRequest(body, target)
		if err != nil {
			return jsonResponse(req, 400, errorMessage("invalid_request_error", err.Error())), nil
		}
	}
	respondError := func(status int, kind, message string) *http.Response {
		if native {
			return nativeError(req, status, kind, message)
		}
		return jsonResponse(req, status, errorMessage(kind, message))
	}
	if req.URL.Path == "/v1/messages/count_tokens" {
		// Оценка по UTF-8 сериализованного запроса.
		return jsonResponse(req, 200, object{"input_tokens": (len(payload) + 3) / 4}), nil
	}
	var token string
	if target.ClientOAuth {
		values := req.Header.Values("Authorization")
		if len(values) == 1 {
			scheme, value, ok := strings.Cut(values[0], " ")
			if ok && strings.EqualFold(scheme, "Bearer") && !strings.ContainsAny(value, " \t\r\n,") {
				token = value
			}
		}
		if token == "" {
			return respondError(401, "authentication_error", "требуется клиентский OAuth Bearer OpenAI"), nil
		}
	} else {
		if a.AccessToken == nil {
			return respondError(503, "api_error", "профиль ChatGPT недоступен"), nil
		}
		token, err = a.AccessToken(req.Context(), target.Profile)
		if err != nil {
			return respondError(503, "api_error", "профиль ChatGPT недоступен, проверьте локальный вход"), nil
		}
	}
	out, err := http.NewRequestWithContext(req.Context(), http.MethodPost, config.OpenAIResponsesURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	out.Header.Set("Authorization", "Bearer "+token)
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set("Accept", "text/event-stream")
	if trace != nil {
		trace.Request(out.Header, payload)
	}
	upstream, err := a.Transport.RoundTrip(out)
	if err != nil {
		return nil, errors.New("не удалось получить ответ OpenAI")
	}
	var stream io.Reader = upstream.Body
	if trace != nil {
		stream = trace.Response(upstream.Header, stream)
	}
	if native {
		if upstream.StatusCode == http.StatusUnauthorized {
			defer upstream.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(stream, 1<<20))
			return respondError(401, "authentication_error", "OpenAI отклонил токен профиля, проверьте локальный вход"), nil
		}
		contentType := upstream.Header.Get("Content-Type")
		if upstream.StatusCode == http.StatusOK {
			if contentType != "" && !isEventStream(contentType) {
				upstream.Body.Close()
				return nil, errors.New("OpenAI вернул ответ без потока событий")
			}
			contentType = "text/event-stream"
		}
		if contentType == "" {
			contentType = "application/json"
		}
		header := http.Header{"Content-Type": {contentType}}
		if value := upstream.Header.Get("Retry-After"); value != "" {
			header.Set("Retry-After", value)
		}
		return &http.Response{StatusCode: upstream.StatusCode, Header: header,
			Request: req, ContentLength: -1, Body: &nativeBody{Reader: stream, Closer: upstream.Body}}, nil
	}
	if upstream.StatusCode != http.StatusOK {
		defer upstream.Body.Close()
		var payload struct {
			Error apiError `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(stream, 1<<20)).Decode(&payload)
		f := failure(event{Code: payload.Error.Code})
		if upstream.StatusCode == 429 {
			f = failure(event{Code: "rate_limit_exceeded"})
		} else if upstream.StatusCode == 401 {
			f = upstreamFailure{401, "authentication_error", "OpenAI отклонил токен профиля, проверьте локальный вход"}
		} else if upstream.StatusCode == 403 && f.status == 502 {
			f = upstreamFailure{403, "permission_error", "OpenAI отклонил доступ, проверьте разрешение на использование плана ChatGPT"}
		} else if upstream.StatusCode == 400 && f.status == 502 {
			f = upstreamFailure{400, "invalid_request_error", "OpenAI отклонил запрос, проверьте модель и совместимость параметров"}
		} else if upstream.StatusCode == 503 && f.status == 502 {
			f = upstreamFailure{503, "overloaded_error", "OpenAI временно недоступен"}
		}
		return jsonResponse(req, f.status, errorMessage(f.kind, f.message)), nil
	}
	// Responses с ChatGPT OAuth может отдавать SSE без Content-Type.
	// В этом случае сам поток проверяется при разборе событий.
	if contentType := upstream.Header.Get("Content-Type"); contentType != "" && !isEventStream(contentType) {
		upstream.Body.Close()
		return nil, errors.New("OpenAI вернул ответ без потока событий")
	}
	if !client.Stream {
		defer upstream.Body.Close()
		var final responseData
		err := consumeEvents(stream, func(e event) error {
			switch e.Type {
			case "response.failed", "error":
				return failure(e)
			case "response.completed", "response.incomplete":
				final = e.Response
			}
			return nil
		})
		if err != nil {
			var f upstreamFailure
			if errors.As(err, &f) {
				return jsonResponse(req, f.status, errorMessage(f.kind, f.message)), nil
			}
			return nil, fmt.Errorf("поток OpenAI не завершился: %w", err)
		}
		msg, err := finalMessage(final, client.Model)
		if err != nil {
			return nil, err
		}
		return jsonResponse(req, 200, msg), nil
	}
	reader, writer := io.Pipe()
	go func() {
		defer upstream.Body.Close()
		defer writer.Close()
		converted := &messageStream{w: writer, model: client.Model, indices: make(map[streamKey]int)}
		if err := consumeEvents(stream, converted.handle); err != nil {
			f := upstreamFailure{502, "api_error", "поток событий OpenAI прерван"}
			_ = errors.As(err, &f)
			_ = converted.send("error", errorMessage(f.kind, f.message))
		}
	}()
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}},
		Request: req, ContentLength: -1, Body: &streamBody{PipeReader: reader, upstream: upstream.Body}}, nil
}

func isEventStream(contentType string) bool {
	typ, _, err := mime.ParseMediaType(contentType)
	return err == nil && typ == "text/event-stream"
}

type streamBody struct {
	*io.PipeReader
	upstream io.Closer
}

func (s *streamBody) Close() error {
	_ = s.PipeReader.Close()
	return s.upstream.Close()
}

type nativeBody struct {
	io.Reader
	io.Closer
}
