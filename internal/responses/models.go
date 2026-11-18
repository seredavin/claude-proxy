package responses

import (
	"net/http"

	"github.com/seredavin/claude-proxy/internal/config"
)

func listModels(req *http.Request, target *config.OpenAITarget) *http.Response {
	models := target.Models
	if len(models) == 0 {
		models = []config.OpenAIModel{{Alias: target.Model}}
	}
	data := make([]object, 0, len(models))
	for _, model := range models {
		data = append(data, object{
			"id": model.PickerID(), "display_name": model.Alias, "type": "model",
			"created_at": "1970-01-01T00:00:00Z",
		})
	}
	return jsonResponse(req, http.StatusOK, object{
		"data": data, "first_id": models[0].PickerID(), "last_id": models[len(models)-1].PickerID(), "has_more": false,
	})
}
