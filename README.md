# go-secure-auth-service

![CI](https://github.com/nikolaykonkin/go-secure-auth-service/actions/workflows/ci.yml/badge.svg)

Безопасный REST API сервис регистрации и аутентификации пользователей на Go с bcrypt, JWT и PostgreSQL.

## Что показывает

- Хеширование паролей с помощью bcrypt
- Аутентификация через JWT (генерация и проверка токенов)
- Проверка алгоритма подписи JWT при разборе: токены с не-HMAC алгоритмом (RS256, none) отвергаются — защита от атаки alg confusion
- Fail-fast при старте: приложение не запускается, если `JWT_SECRET` пустой или короче 32 символов
- Строгий разбор JSON: `DisallowUnknownFields` — неизвестные поля в теле запроса отвергаются с 400
- Работа с PostgreSQL через параметризованные запросы (защита от SQL-инъекций)
- Развертывание базы данных через Docker Compose
- Защита от user enumeration на `/login`: одинаковый ответ при неверном пароле и при отсутствии аккаунта
- Валидация входных данных (email, username, надежность пароля)
- Unit- и handler-тесты (table-driven, httptest)

## Что было дано

Учебный проект: в шаблоне были заготовки файлов с `TODO`-комментариями и пошаговыми подсказками — `auth.go`, `database.go`, `handlers.go`, `middleware.go`, `main.go`, а также `docker-compose.yml` и `init.sql`. Требовалось реализовать регистрацию и вход, хеширование паролей (bcrypt), выдачу и проверку JWT, параметризованные SQL-запросы и защищенный эндпоинт профиля.

Все пункты задания выполнены; дополнительно — тесты, CI и описанные ниже меры безопасности.

## Реализовано

### Аутентификация и JWT (`auth.go`)

- `HashPassword` / `CheckPassword` — bcrypt с `bcrypt.DefaultCost` (10)
- `GenerateToken` — JWT (HS256), срок жизни 24 часа, claims: `user_id`, `email`, `username`
- `ValidateToken` — разбор токена с проверкой алгоритма подписи (см. «Ключевые решения»)
- `InitAuth` — fail-fast при пустом или коротком `JWT_SECRET`
- `ValidateEmail`, `ValidateUsername`, `ValidatePassword` — валидация входных данных через регулярные выражения

### Работа с БД (`database.go`)

- `InitDB` / `CloseDB` — подключение к PostgreSQL через `lib/pq`, проверка `Ping`
- `CreateUser`, `GetUserByEmail`, `GetUserByID`, `UserExistsByEmail`, `UserExistsByUsername` — все запросы параметризованы (`$1, $2, $3`)
- `GetUserByID` намеренно не возвращает `password_hash` — профилю он не нужен
- `UserExistsByEmail` и `UserExistsByUsername` используют SQL `EXISTS` — дешевле, чем загружать запись

### HTTP (`handlers.go`, `middleware.go`)

- 4 обработчика: `RegisterHandler`, `LoginHandler`, `ProfileHandler`, `HealthHandler`
- Проверка HTTP-метода в каждом хендлере → 405
- `parseJSONRequest` — `DisallowUnknownFields` для строгого разбора JSON
- `AuthMiddleware` — проверка заголовка `Authorization: Bearer <token>`
- `contextKey` — типизированный ключ контекста для избежания коллизий

### Точка входа (`main.go`)

- Загрузка `.env` через `godotenv`
- `InitAuth` → `InitDB` → регистрация маршрутов → запуск сервера
- Порт читается из `SERVER_PORT` (fallback `8080`)

### Тесты

- `auth_test.go` — bcrypt, валидация, JWT (включая expired token и wrong signature)
- `handlers_test.go` — сценарии HTTP-валидации и три сценария с реальной БД (успешная регистрация, дубликаты email и username)
- Тесты с БД локально пропускаются через `t.Skipf`, если БД недоступна; в CI падают через `t.Fatalf`, чтобы зеленый job не скрывал пропущенные тесты

## Ключевые решения

**Проверка алгоритма подписи JWT.** В `ValidateToken` в `keyFunc` проверяется `token.Method.(*jwt.SigningMethodHMAC)`. Токены с не-HMAC алгоритмом (`none`, RS256) отвергаются. Это защита от классической атаки alg confusion, когда атакующий подменяет `alg` в заголовке.

**Fail-fast при старте.** `InitAuth` вызывается в `main` первым и паникует, если `JWT_SECRET` пустой или короче 32 символов. Это осознанный выбор в пользу безопасности: лучше явная ошибка при старте, чем работа с пустым или коротким секретом.

**Параметризованные SQL-запросы везде.** Ни один запрос не строится через `fmt.Sprintf` или конкатенацию строк. Все значения передаются через плейсхолдеры `$1, $2, $3`.

**`EXISTS` вместо `SELECT`.** Для проверки существования пользователя не нужно загружать всю запись — достаточно `SELECT EXISTS(SELECT 1 FROM users WHERE ...)`. Возвращает `bool`, работает быстрее.

**`GetUserByID` без `password_hash`.** Хендлер профиля возвращает только публичные данные. `password_hash` не включается в SELECT — даже случайно не утечет.

**`DisallowUnknownFields`.** `json.Decoder` настроен на отказ при неизвестных полях: клиент не может прислать лишние данные в обход валидации.

## Безопасность

- **Пароли хранятся как bcrypt-хеши** (`bcrypt.DefaultCost`). Открытый пароль нигде не сохраняется и не сериализуется — на поле `PasswordHash` стоит `json:"-"`.
- **JWT подписывается HS256**, при разборе принимается любое HMAC-семейство (`HS256`, `HS384`, `HS512`); токены с не-HMAC алгоритмом (`none`, `RS256`) отвергаются.
- **`JWT_SECRET` обязателен**, минимум 32 символа; пустой или короткий секрет приводит к `panic` при старте, приложение не поднимается.
- **Все SQL-запросы параметризованы** — SQL-инъекции исключены.
- **Одинаковый ответ при неверном пароле и при отсутствии аккаунта** (`/login`) — защита от user enumeration. На `/register` email и username по-прежнему сообщают о занятости (409) — типичный компромисс между удобством и приватностью.
- **`DisallowUnknownFields`** в JSON-декодере отвергает неизвестные поля.
- **Валидация email, username и пароля** на входе: длина, разрешенные символы, наличие цифры и заглавной буквы в пароле.

## Обработка ошибок

Хендлеры возвращают HTTP-статусы напрямую; единого маппинга ошибок в проекте нет — каждая ветка решает сама.

| Ситуация | HTTP |
|---|---|
| Неподдерживаемый HTTP-метод | 405 |
| Невалидное тело / JSON / поля | 400 |
| Неверные учетные данные (`/login`) | 401 |
| Отсутствует или невалиден JWT (`/profile`) | 401 |
| Email или username уже занят | 409 |
| Пользователь не найден в профиле | 404 |
| Неожиданная ошибка БД | 500 |
| БД недоступна при `/health` | 503 |

Все ошибки возвращаются в формате `{"error":"..."}`.

## Переменные окружения

Приложение читает конфигурацию из переменных окружения. Значения по умолчанию — из `getEnv` в `main.go`.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `JWT_SECRET` | — (обязательна) | секрет подписи JWT; минимум 32 символа |
| `DB_HOST` | `localhost` | хост PostgreSQL |
| `DB_PORT` | `5432` | порт PostgreSQL |
| `DB_USER` | `postgres` | пользователь БД |
| `DB_PASSWORD` | `postgres` | пароль БД |
| `DB_NAME` | `secure_service` | имя базы данных |
| `SERVER_PORT` | `8080` | порт HTTP-сервера |

Для тестов дополнительно используются переменные (см. раздел «Тесты»): `TEST_DB_HOST`, `TEST_DB_PORT`, `TEST_DB_USER`, `TEST_DB_PASSWORD`, `TEST_DB_NAME`.

## Ограничения

- **Нет rate limiting** на `/login` и `/register` — оставляет пространство для brute-force атак на пароли
- **JWT живет 24 часа без отзыва**: нет blacklist отозванных токенов и refresh-механизма
- **bcrypt с `DefaultCost` (10)** — для production можно поднять до 12 ценой более медленного логина
- **`/register` отвечает 409 при занятых email/username** — позволяет проверить, зарегистрирован ли адрес (защита от enumeration есть только на `/login`)

## Запуск

```bash
cp .env.example .env
# открой .env и замени JWT_SECRET на свой ключ (минимум 32 символа)
docker compose up -d
go run .
```

После запуска сервер слушает `http://localhost:8080`. Проверка:

```bash
curl http://localhost:8080/health
# {"status":"ok","message":"Service is running"}
```

## API эндпоинты

| Метод | Путь        | Требует токен |
| ----- | ----------- | ------------- |
| POST  | `/register` | Нет           |
| POST  | `/login`    | Нет           |
| GET   | `/profile`  | Да            |
| GET   | `/health`   | Нет           |

## Пример работы

Регистрация пользователя:

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"testuser","password":"SecurePass123"}'
```

```
{"token":"eyJhbGciOiJIUzI1NiIs...","user":{"id":1,"email":"user@example.com","username":"testuser","created_at":"2026-09-26T12:00:00Z"}}
```

Вход в систему:

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123"}'
```

```
{"token":"eyJhbGciOiJIUzI1NiIs...","user":{"id":1,"email":"user@example.com","username":"testuser","created_at":"2026-09-26T12:00:00Z"}}
```

Профиль без токена:

```bash
curl http://localhost:8080/profile
```

```
{"error":"Authorization header is required"}
```

Профиль с токеном:

```bash
curl http://localhost:8080/profile \
  -H "Authorization: Bearer <токен из ответа /login>"
```

```
{"id":1,"email":"user@example.com","username":"testuser","created_at":"2026-09-26T12:00:00Z"}
```

## Тесты

```bash
go test ./... -v
```

- `auth_test.go` — unit-тесты: bcrypt, валидация email/username/пароля, генерация и проверка JWT (включая wrong signature и expired token).
- `handlers_test.go` — HTTP-тесты через `httptest`: валидация запросов и сценарии с БД (успешная регистрация, дубликаты email и username).

Тесты, требующие PostgreSQL, подключаются к БД через переменные `TEST_DB_HOST`, `TEST_DB_PORT`, `TEST_DB_USER`, `TEST_DB_PASSWORD`, `TEST_DB_NAME`. Значения по умолчанию совпадают с `docker-compose.yml`: `localhost`, `5432`, `postgres`, `postgres`, `secure_service`. Поведение при недоступной БД зависит от окружения:

- **локально** (`CI` не задана) — тест пропускается через `t.Skipf`;
- **в CI** (`CI=true`, GitHub Actions выставляет автоматически) — тест падает через `t.Fatalf`.

Это защищает от ситуации, когда в CI Postgres не поднялся, интеграционные тесты молча пропустились, а job остался зеленым.

### CI

GitHub Actions (`.github/workflows/ci.yml`) на каждый `push` и `pull_request`:

1. Поднимает `postgres:15-alpine` как service-контейнер с healthcheck через `pg_isready`.
2. Применяет `init.sql`.
3. `go vet ./...`
4. `go test -race -cover ./...`

Версия Go берется из `go.mod` через `go-version-file`.

## Структура

```
main.go                          — запуск сервера и маршрутизация
handlers.go                      — HTTP-обработчики (register, login, profile, health)
models.go                        — структуры данных
database.go                      — работа с PostgreSQL
auth.go                          — хеширование паролей, JWT, валидация
middleware.go                    — проверка JWT-токена
auth_test.go                     — unit-тесты (хеширование, валидация, JWT)
handlers_test.go                 — тесты обработчиков (httptest)
.github/workflows/ci.yml         — GitHub Actions: PostgreSQL service + go test
docker-compose.yml               — PostgreSQL в Docker
init.sql                         — схема базы данных
.env.example                     — пример конфигурации
.gitignore                       — игнорирование .env и бинарников
go.mod                           — зависимости
```

Реализовано в рамках курса «Go-разработчик с нуля» (Нетология).