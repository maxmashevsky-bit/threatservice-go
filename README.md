# Information Exchange Service

[![CI](https://github.com/maxmashevsky-bit/threatservice-go/actions/workflows/ci.yml/badge.svg)](https://github.com/maxmashevsky-bit/threatservice-go/actions/workflows/ci.yml)

REST-сервис на Go и PostgreSQL для обмена сведениями об угрозах по MD5: создание, чтение и полная замена существующей записи.

## Быстрый запуск

Нужны Docker и Docker Compose v2. Используйте полный путь без кириллицы:

```sh
git clone https://github.com/maxmashevsky-bit/threatservice-go.git "$HOME/threatservice-go"
cd "$HOME/threatservice-go"
cp .env.example .env
docker compose up --build -d
docker compose logs migrate
curl --fail --retry 30 --retry-connrefused --retry-delay 1 --retry-max-time 60 \
  http://localhost:8080/health/ready
```

Compose поднимает PostgreSQL 18, создаёт runtime-роль, применяет миграцию и запускает приложение на `127.0.0.1:8080`. Порт БД наружу не опубликован. `docker compose down` сохраняет данные в именованном томе. Dev-пароли и отключённая авторизация подходят только для локального запуска; настройка паролей и TLS описана в [сопровождении](docs/operations.md).

## API

```sh
# Создать: 201, Location и шесть полей записи
curl -i http://localhost:8080/info -H 'Content-Type: application/json' \
  --data '{"md5":"0123456789ABCDEF0123456789ABCDEF","name":"Trojan.Win32.Generic","description":"Описание угрозы","severity":"high"}'

# Получить: 200 или 404
curl -i http://localhost:8080/info/0123456789abcdef0123456789abcdef

# Полностью заменить изменяемые поля существующей записи: 200 или 404
curl -i -X PUT http://localhost:8080/info/0123456789abcdef0123456789abcdef \
  -H 'Content-Type: application/json' --data '{"name":"Trojan.Win32.Updated"}'
```

MD5 хранится в нижнем регистре. Повторное создание возвращает `409`. В PUT пропущенные description и severity сбрасываются в `""` и `unknown`; повтор одинакового PUT сохраняет updated_at. Ответ содержит md5, name, description, severity, created_at и updated_at. JSON обрабатывается строго: неизвестные и повторные поля, null и неверный Unicode отклоняются; максимальное тело — 65 536 байт.

Полный контракт: [OpenAPI](api/openapi.yaml). Внутренние ошибки возвращают безопасный `500`, проверка неготовности — `503`; причины сохраняются в серверных ERROR-логах и связываются с ответом через X-Request-ID.

Пример тела ответа POST; даты формирует сервер:

```json
{"md5":"0123456789abcdef0123456789abcdef","name":"Trojan.Win32.Generic","description":"Описание угрозы","severity":"high","created_at":"2026-10-28T12:00:00Z","updated_at":"2026-10-28T12:00:00Z"}
```

GET возвращает ту же запись. После указанного PUT имя станет `Trojan.Win32.Updated`, description — `""`, severity — `unknown`; created_at сохранится. Неверные данные дают `400`, отсутствующая запись — `404`, повторный POST — `409`. Например, ответ для отсутствующей записи: `{"message":"Threat not found","details":"No threat with the specified MD5 found"}`.

`/health/live` не обращается к БД. `/health/ready` кеширует результат на 1 секунду и объединяет одновременные проверки: частота опроса не вызывает `429`. Бизнес-API имеет отдельный настраиваемый rate limit.

## Основные настройки

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| DATABASE_URL | обязательна | DSN PostgreSQL |
| HTTP_ADDR | `:8080` | Адрес сервера |
| PG_MAX_CONNS | `10` | Размер пула |
| REQUEST_TIMEOUT | `3s` | Deadline запроса |
| QUERY_TIMEOUT | `2s` | Deadline SQL, включая ожидание пула |
| SHUTDOWN_TIMEOUT | `10s` | Время корректной остановки |
| API_TOKEN | пусто | Bearer token68, 16–1024 ASCII-символа; пусто отключает авторизацию |
| RATE_LIMIT_RPS | `0` | Общий лимит бизнес-API на процесс; 0 отключает |
| RATE_LIMIT_BURST | `20` | Burst бизнес-лимитера |
| TLS_CERT_FILE / TLS_KEY_FILE | пусто | Пара PEM-файлов для HTTPS |

Compose также использует POSTGRES_PASSWORD и APP_DB_PASSWORD из `.env`. Если включён API_TOKEN, передавайте `Authorization: Bearer <token>` для `/info` и `/info/{md5}`. Health-маршруты доступны без токена.

## Проверки

Нужны Go 1.27.3; для integration — отдельная PostgreSQL 18 и роль с DDL/CREATEROLE.

```sh
make generate-check   # DTO соответствуют спецификации
make vet
make test             # unit, HTTP и OpenAPI-контрактные тесты
make race
make build
make vuln
make deploy-check     # Docker, Compose, Python 3 и OpenSSL
```

Контрактные тесты используют закреплённый kin-openapi v0.142.0 и httptest: проверяют запросы, статусы, Content-Type, заголовки и JSON ответа для POST/GET/PUT. Они входят в `make test`, `make race` и CI. Неверные запросы проверяются на ожидаемый отказ; строгий JSON дополнительно покрыт отдельными тестами. Дополнительные команды: `make fuzz`, `make smoke`, `make generate`.

Для интеграционного прогона на отдельной временной БД:

```sh
docker run --rm -d --name threatservice-test-db \
  -e POSTGRES_DB=threats_test -e POSTGRES_USER=threat_owner \
  -e POSTGRES_PASSWORD=test-only-password -p 127.0.0.1:55432:5432 postgres:18
until docker exec threatservice-test-db pg_isready -h 127.0.0.1 -U threat_owner -d threats_test; do sleep 1; done
TEST_DATABASE_URL='postgres://threat_owner:test-only-password@127.0.0.1:55432/threats_test?sslmode=disable' make integration
docker stop threatservice-test-db
```

Порт 55432 и имя контейнера должны быть свободны. БД использует парольную аутентификацию: один из тестов намеренно подключается с неверным паролем. Тестовый владелец может создавать и удалять роли; для рабочей БД эти команды не предназначены.

[Архитектура и ограничения схемы](docs/architecture.md) · [Сопровождение и диагностика](docs/operations.md) · [Матрица ошибок](docs/error-scenarios.md) · [Результаты проверок](docs/verification.md).
