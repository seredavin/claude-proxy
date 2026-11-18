package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const OpenAIResponsesURL = "https://api.openai.com/v1/responses"

// OpenAITarget задаёт локальный профиль и модель Responses API.
type OpenAITarget struct {
	Profile     string
	ClientOAuth bool
	Model       string
	Models      []OpenAIModel
}

type OpenAIModel struct {
	Alias string
	Model string
}

// PickerID учитывает фильтр идентификаторов в меню Claude Code.
func (m OpenAIModel) PickerID() string {
	id := strings.ToLower(m.Alias)
	if strings.Contains(id, "claude") || strings.Contains(id, "anthropic") {
		return m.Alias
	}
	return "claude-" + m.Alias
}

// ResolveModel возвращает модель OpenAI для клиентского идентификатора.
func (t *OpenAITarget) ResolveModel(alias string) (string, bool) {
	if len(t.Models) == 0 {
		return t.Model, true
	}
	for _, model := range t.Models {
		if model.Alias == alias || model.PickerID() == alias {
			return model.Model, true
		}
	}
	return "", false
}

var profileName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func ValidProfileName(name string) bool {
	return profileName.MatchString(name)
}

var modelID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

func parseOpenAITarget(value string) (*OpenAITarget, error) {
	profile, models, ok := strings.Cut(strings.TrimSpace(value), ":")
	profile, models = strings.TrimSpace(profile), strings.TrimSpace(models)
	clientOAuth := profile == "@client"
	if !ok || (!clientOAuth && !ValidProfileName(profile)) || models == "" {
		return nil, fmt.Errorf("ожидается профиль:модель или профиль:псевдоним=модель|псевдоним=модель")
	}
	if clientOAuth {
		profile = ""
	}
	if !strings.ContainsAny(models, "=|") {
		// Сохраняем формат уже настроенной фиксированной модели.
		if strings.ContainsAny(models, " \t\r\n,:") {
			return nil, fmt.Errorf("ожидается профиль:модель")
		}
		return &OpenAITarget{Profile: profile, ClientOAuth: clientOAuth, Model: models}, nil
	}

	target := &OpenAITarget{Profile: profile, ClientOAuth: clientOAuth}
	seen := make(map[string]bool)
	for i, entry := range strings.Split(models, "|") {
		alias, model, ok := strings.Cut(entry, "=")
		alias, model = strings.TrimSpace(alias), strings.TrimSpace(model)
		if !ok || !modelID.MatchString(alias) || !modelID.MatchString(model) {
			return nil, fmt.Errorf("модель %d должна иметь вид псевдоним=модель", i+1)
		}
		entry := OpenAIModel{Alias: alias, Model: model}
		id := entry.PickerID()
		if seen[id] {
			return nil, fmt.Errorf("конфликт псевдонима модели %q с идентификатором %q", alias, id)
		}
		seen[id] = true
		target.Models = append(target.Models, entry)
	}
	return target, nil
}

// OpenAIFor возвращает профиль и модель эффективного апстрима метки.
func (c *Config) OpenAIFor(label string) *OpenAITarget {
	for _, route := range c.Routes {
		if route.Label == label {
			return route.OpenAI
		}
	}
	return c.OpenAI
}

func (c *Config) configureOpenAI(raw Raw) error {
	if strings.TrimSpace(raw.OpenAIUpstream) == "" && strings.TrimSpace(raw.OpenAIRoutes) == "" {
		return nil
	}
	if c.StateDir == "" {
		return fmt.Errorf("для OpenAI требуется каталог состояния --state-dir")
	}
	endpoint, err := url.Parse(OpenAIResponsesURL)
	if err != nil {
		return err
	}
	if value := strings.TrimSpace(raw.OpenAIUpstream); value != "" {
		if c.UpstreamKey != "" || c.Upstream.String() != Defaults().Upstream {
			return fmt.Errorf("--openai-upstream несовместим с настройкой общего --upstream или --upstream-key")
		}
		target, err := parseOpenAITarget(value)
		if err != nil {
			return fmt.Errorf("--openai-upstream: %w", err)
		}
		if err := c.validateOpenAICredentials(target); err != nil {
			return err
		}
		c.OpenAI = target
		c.Upstream = endpoint
	}

	labels := make(map[string]bool)
	for _, label := range c.Tokens.Labels() {
		labels[label] = true
	}
	for _, route := range c.Routes {
		delete(labels, route.Label)
	}
	for i, item := range strings.Split(raw.OpenAIRoutes, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		label, value, ok := strings.Cut(item, "=")
		label = strings.TrimSpace(label)
		if !ok {
			return fmt.Errorf("элемент %d в --openai-routes должен иметь вид метка=профиль:модель", i+1)
		}
		if !labels[label] {
			return fmt.Errorf("--openai-routes: метка %q уже имеет маршрут или отсутствует в --tokens", label)
		}
		target, err := parseOpenAITarget(value)
		if err != nil {
			return fmt.Errorf("--openai-routes, метка %q: %w", label, err)
		}
		if err := c.validateOpenAICredentials(target); err != nil {
			return err
		}
		delete(labels, label)
		c.Routes = append(c.Routes, Route{Label: label, Upstream: endpoint, OpenAI: target})
	}
	return nil
}

// HasOpenAI сообщает, нужен ли шлюзу доступ к профилям ChatGPT.
func (c *Config) HasOpenAI() bool {
	if c.OpenAI != nil {
		return true
	}
	for _, route := range c.Routes {
		if route.OpenAI != nil {
			return true
		}
	}
	return false
}

// ChatGPTRefreshPath используется только для обновления через TLS-шлюз.
const ChatGPTRefreshPath = "/_claude_proxy/chatgpt/refresh"

func (c *Config) validateOpenAICredentials(target *OpenAITarget) error {
	if target.ClientOAuth && (c.Mode != ModeOAuth || c.TLS == TLSNone) {
		return fmt.Errorf("@client для OpenAI требует TLS и режим oauth на внешнем шлюзе")
	}
	return nil
}
