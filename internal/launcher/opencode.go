package launcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/seredavin/claude-proxy/internal/config"
)

func openCodeEnviron(ctx context.Context, base []string, cfg *config.Config, baseURL, token string) ([]string, error) {
	first, _ := cfg.Tokens.First()
	var models []config.OpenAIModel
	if target := cfg.OpenAIFor(first.Label); target != nil {
		for _, model := range target.Models {
			models = append(models, config.OpenAIModel{Alias: model.Alias})
		}
		if len(models) == 0 {
			models = []config.OpenAIModel{{Alias: target.Model}}
		}
	} else {
		var err error
		models, err = discoverOpenCodeModels(ctx, baseURL, token)
		if err != nil {
			return nil, err
		}
	}

	catalog := make(map[string]any, len(models))
	for _, model := range models {
		id := model.Model
		if id == "" {
			id = model.Alias
		}
		catalog[model.Alias] = map[string]any{
			"name": model.Alias, "modelID": id,
			"capabilities": map[string]bool{"tools": true},
		}
	}
	const provider = "claude-proxy"
	content, err := json.Marshal(map[string]any{
		"model":       provider + "/" + models[0].Alias,
		"small_model": provider + "/" + models[0].Alias,
		"providers": map[string]any{provider: map[string]any{
			"name":     "Claude Proxy",
			"package":  "@opencode/ai/providers/openai-compatible/responses",
			"settings": map[string]any{"baseURL": baseURL + "/v1", "apiKey": "local", "store": false},
			"headers":  map[string]string{"X-Gateway-Key": token},
			"body":     map[string]any{"store": false},
			"models":   catalog,
		}},
	})
	if err != nil {
		return nil, err
	}

	const key = "OPENCODE_CONFIG_CONTENT="
	env := make([]string, 0, len(base)+1)
	for _, value := range base {
		if !strings.HasPrefix(value, key) {
			env = append(env, value)
		}
	}
	return append(env, key+string(content)), nil
}

func discoverOpenCodeModels(ctx context.Context, baseURL, token string) ([]config.OpenAIModel, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Gateway-Key", token)
	client := http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("каталог моделей OpenCode: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("каталог моделей OpenCode: HTTP %d", resp.StatusCode)
	}
	var catalog struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("каталог моделей OpenCode: %w", err)
	}
	models := make([]config.OpenAIModel, 0, len(catalog.Data))
	for _, entry := range catalog.Data {
		if entry.ID == "" {
			continue
		}
		alias := entry.DisplayName
		if alias == "" {
			alias = entry.ID
		}
		models = append(models, config.OpenAIModel{Alias: alias, Model: entry.ID})
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("каталог моделей OpenCode пуст")
	}
	return models, nil
}
