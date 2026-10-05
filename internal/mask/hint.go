package mask

import "strings"

// tagsHint — инструкция модели о метках: без неё модель принимает
// <<m:host:…>> за шаблон и подставляет выдуманное значение. Многоточия —
// не символы токена, поэтому образцы в тексте за метки не принимаются.
const tagsHint = "Some values in this conversation — IP addresses, hostnames, secrets — " +
	"are replaced by a privacy proxy with opaque tags like <<m:ip:…>>, <<m:host:…>>, <<m:secret:…>>. " +
	"Treat each tag as the real value it stands for: use it verbatim in commands, files and tool calls — " +
	"it is substituted back before execution, so `ssh <<m:host:…>>` works as is. " +
	"Copy tags exactly; never shorten, alter, quote-escape, decode or invent them. " +
	"The same tag is always the same value, different tags are different values. " +
	"Tags carry no structure: you cannot tell whether two IP tags share a subnet."

// addTagsHint дописывает инструкцию в конец system запроса Messages API.
// Прежние блоки и их cache_control не трогаются, повторно (второе звено
// цепочки) инструкция не добавляется.
func addTagsHint(root any) {
	body, ok := root.(map[string]any)
	if !ok {
		return
	}
	if _, ok := body["messages"]; !ok {
		return
	}
	block := map[string]any{"type": "text", "text": tagsHint}
	switch sys := body["system"].(type) {
	case nil:
		body["system"] = []any{block}
	case string:
		if !strings.HasSuffix(sys, tagsHint) {
			body["system"] = sys + "\n\n" + tagsHint
		}
	case []any:
		if len(sys) > 0 {
			if last, _ := sys[len(sys)-1].(map[string]any); last != nil && last["text"] == tagsHint {
				return
			}
		}
		body["system"] = append(sys, block)
	}
}
