## MODIFIED Requirements

### Requirement: Credential от предыдущего звена

Для маршрутов по протоколу Anthropic в режиме `oauth` шлюз SHALL считать
наличие credential Anthropic подтверждённым заголовком `Authorization`
или `X-Api-Key`. Второй присылает предыдущее звено в режиме `apikey`.
При отсутствии обоих шлюз SHALL отвечать `401` без обращения к апстриму.
Для OpenAI шлюз SHALL проверять локальный пропуск и использовать OAuth
профиля ChatGPT. Клиентские credentials SHALL оставаться на шлюзе.

#### Scenario: Запрос от звена в режиме apikey принимается

- **WHEN** запрос к апстриму Anthropic с верным пропуском несёт
  `X-Api-Key` и не несёт `Authorization`
- **THEN** шлюз проксирует запрос, сохраняя `X-Api-Key`

#### Scenario: Запрос без credential'а отвергается

- **WHEN** запрос к апстриму Anthropic с верным пропуском не несёт
  ни `Authorization`, ни `X-Api-Key`
- **THEN** шлюз отвечает `401` и к апстриму не обращается

#### Scenario: Запрос OpenAI по пропуску локального шлюза

- **WHEN** запрос выбирает OpenAI и предъявляет верный локальный пропуск
- **THEN** шлюз обращается в OpenAI с OAuth токеном профиля ChatGPT
