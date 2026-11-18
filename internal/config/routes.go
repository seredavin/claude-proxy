package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/seredavin/claude-proxy/internal/auth"
)

// Route — маршрут апстрима по метке токена: запросы токена с этой меткой
// уходят на свой апстрим со своим пропуском, а не на общий.
type Route struct {
	Label string
	// Upstream — базовый URL апстрима маршрута.
	Upstream *url.URL
	// Key — пропуск на апстрим маршрута (X-Gateway-Key); пусто — заголовок
	// не подставляется. Общий пропуск сюда не переиспользуется: у каждого
	// апстрима свой пропуск.
	Key string
}

// parseRoutes разбирает списки «метка=значение» и проверяет их друг против
// друга и против токенов шлюза. Пустые списки дают пустой набор маршрутов —
// это не ошибка: без маршрутов шлюз работает как прежде.
func parseRoutes(routesSpec, keysSpec string, tokens auth.Set) ([]Route, error) {
	if routesSpec == "" {
		if keysSpec != "" {
			return nil, fmt.Errorf("--upstream-route-keys действует только вместе с --upstream-routes")
		}
		return nil, nil
	}

	// Маршрут для метки без токена — мёртвый груз: его никто не выберет.
	known := map[string]bool{}
	for _, label := range tokens.Labels() {
		known[label] = true
	}

	var routes []Route
	seen := map[string]bool{}
	for _, raw := range strings.Split(routesSpec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		// Делим по первому «=»: в адресе маршрута «=» допустим (query),
		// в метке и пропуске — нет.
		label, value, found := strings.Cut(item, "=")
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if !found || label == "" || value == "" {
			return nil, fmt.Errorf("маршрут %q должен иметь вид метка=https://host", item)
		}
		if seen[label] {
			return nil, fmt.Errorf("метка %q встречается в --upstream-routes дважды", label)
		}
		seen[label] = true
		if !known[label] {
			return nil, fmt.Errorf("маршрут задан для метки %q, которой нет в --tokens", label)
		}
		upstream, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("некорректный апстрим маршрута %q: %w", item, err)
		}
		if upstream.Scheme != "https" || upstream.Host == "" {
			return nil, fmt.Errorf("апстрим маршрута должен быть https://host, получено %q", value)
		}
		routes = append(routes, Route{Label: label, Upstream: upstream})
	}

	byLabel := map[string]*Route{}
	for i := range routes {
		byLabel[routes[i].Label] = &routes[i]
	}
	seenKeys := map[string]bool{}
	for _, raw := range strings.Split(keysSpec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		label, value, found := strings.Cut(item, "=")
		label, value = strings.TrimSpace(label), strings.TrimSpace(value)
		if !found || label == "" || value == "" {
			return nil, fmt.Errorf("ключ маршрута %q должен иметь вид метка=значение", item)
		}
		if seenKeys[label] {
			return nil, fmt.Errorf("ключ маршрута для метки %q встречается дважды", label)
		}
		seenKeys[label] = true
		rt := byLabel[label]
		if rt == nil {
			return nil, fmt.Errorf("ключ маршрута задан для метки %q, у которой нет маршрута", label)
		}
		rt.Key = value
	}

	for _, rt := range routes {
		// Тот же запрет, что и у общего пропуска: Anthropic X-Gateway-Key
		// игнорирует, значит цепочка настроена наполовину.
		if rt.Key != "" && isAnthropicHost(rt.Upstream.Hostname()) {
			return nil, fmt.Errorf("--upstream-route-keys имеет смысл только когда апстрим маршрута — другой claude-proxy; для метки %q и %s он бесполезен",
				rt.Label, UpstreamHost)
		}
	}
	return routes, nil
}
