## ADDED Requirements

### Requirement: Локальный запуск OpenCode
Команда local SHALL запускать OpenCode при выборе --client opencode для маршрута ChatGPT с провайдером Responses на фактическом адресе локального звена.

#### Scenario: Запуск с эфемерным портом
- **WHEN** локальное звено выбирает свободный порт
- **THEN** OpenCode получает этот адрес и пропуск звена в конфигурации процесса
- **AND** звено останавливается после выхода OpenCode
