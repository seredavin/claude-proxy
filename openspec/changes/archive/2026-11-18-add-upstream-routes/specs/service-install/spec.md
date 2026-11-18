## ADDED Requirements

### Requirement: Маршруты апстримов попадают в конфигурацию сервиса

Установщик SHALL записывать в `EnvironmentFile` маршруты апстримов
(`CLAUDE_PROXY_UPSTREAM_ROUTES`) и их пропуска
(`CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS`), если они заданы при установке;
незаданные значения SHALL НЕ попадать в файл. При переустановке эти
переменные SHALL переноситься наравне с прочими переменными оператора.

#### Scenario: Маршруты сохраняются в конфигурации

- **WHEN** сервис устанавливают с маршрутами и ключами маршрутов
- **THEN** `EnvironmentFile` содержит обе переменные с этими значениями

#### Scenario: Без маршрутов переменных нет

- **WHEN** сервис устанавливают без маршрутов
- **THEN** переменных `CLAUDE_PROXY_UPSTREAM_ROUTES` и
  `CLAUDE_PROXY_UPSTREAM_ROUTE_KEYS` в файле нет
