## Why

Claude Code может отправлять встроенные инструменты Anthropic, которые адаптер OpenAI не поддерживает. OpenCode может обращаться к OpenAI через Responses API и передавать результаты локальных инструментов в родном формате.

## What Changes

- Добавить потоковый POST /v1/responses для маршрутов ChatGPT.
- Добавить выбор OpenCode в команде local и настроить его на фактический адрес loopback.

## Capabilities

### Modified Capabilities

- `openai-chatgpt-upstream`: нативный вход Responses и передача OAuth по цепочке.
- `local-launcher`: запуск OpenCode с конфигурацией провайдера на время процесса.

## Impact

Шлюз, адаптер Responses, локальный лаунчер и документация запуска.
