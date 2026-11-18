package chatgpt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Model struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Visibility  string `json:"visibility"`
}

func (s *Store) Models(ctx context.Context, profile string) ([]Model, error) {
	token, err := s.AccessToken(ctx, profile)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resource+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить список моделей ChatGPT")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ChatGPT не вернул список моделей (HTTP %d)", resp.StatusCode)
	}
	var payload struct {
		Models []Model `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload) != nil {
		return nil, fmt.Errorf("некорректный список моделей ChatGPT")
	}
	var visible []Model
	for _, model := range payload.Models {
		if model.Visibility == "list" && model.Slug != "" {
			visible = append(visible, model)
		}
	}
	return visible, nil
}
