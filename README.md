# go-secure-auth-service

Безопасный REST API сервис регистрации и аутентификации пользователей на Go с bcrypt, JWT и PostgreSQL.

## Что показывает

- Хеширование паролей с помощью bcrypt
- Аутентификация через JWT (генерация и проверка токенов)
- Работа с PostgreSQL через параметризованные запросы (защита от SQL-инъекций)
- Развёртывание базы данных через Docker Compose
- Защита от user enumeration: одинаковый ответ при неверном пароле и при отсутствии аккаунта
- Валидация входных данных (email, username, надёжность пароля)
- Unit- и handler-тесты (table-driven, httptest)

## Запуск

```bash
cp .env.example .env
# открой .env и замени JWT_SECRET на свой ключ (минимум 32 символа)
docker-compose up -d
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

```
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"testuser","password":"SecurePass123"}'
```

```
{"token":"eyJhbGciOiJIUzI1NiIs...","user":{"id":1,"email":"user@example.com","username":"testuser","created_at":"2026-09-26T12:00:00Z"}}
```

Вход в систему:

```
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"SecurePass123"}'
```

```
{"token":"eyJhbGciOiJIUzI1NiIs...","user":{"id":1,"email":"user@example.com","username":"testuser","created_at":"2026-09-26T12:00:00Z"}}
```

Профиль без токена:

```
curl http://localhost:8080/profile
```

```
{"error":"Authorization header is required"}
```

Профиль с токеном:

```
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

Тесты, требующие PostgreSQL, автоматически пропускаются, если БД не поднята через `docker-compose up -d`.

## Структура

```
main.go              — запуск сервера и маршрутизация
handlers.go          — HTTP-обработчики (register, login, profile, health)
models.go            — структуры данных
database.go          — работа с PostgreSQL
auth.go              — хеширование паролей, JWT, валидация
middleware.go        — проверка JWT-токена
auth_test.go         — unit-тесты (хеширование, валидация, JWT)
handlers_test.go     — тесты обработчиков (httptest)
docker-compose.yml   — PostgreSQL в Docker
init.sql             — схема базы данных
.env.example         — пример конфигурации
.gitignore           — игнорирование .env и бинарников
go.mod               — зависимости
```

Реализовано в рамках курса «Go-разработчик с нуля» (Нетология).
