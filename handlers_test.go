package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// setupTestDB пытается поднять подключение к тестовой базе данных
// Если БД недоступна, тест, вызвавший эту функцию, пропускается — сценарии, требующие реальной БД
// (успешная регистрация, дубликаты email/username), не могут быть проверены без поднятого PostgreSQL
func setupTestDB(t *testing.T) {
	t.Helper()

	if db != nil {
		if err := db.Ping(); err == nil {
			return
		}
	}

	os.Setenv("DB_HOST", getEnv("TEST_DB_HOST", "localhost"))
	os.Setenv("DB_PORT", getEnv("TEST_DB_PORT", "5432"))
	os.Setenv("DB_USER", getEnv("TEST_DB_USER", "postgres"))
	os.Setenv("DB_PASSWORD", getEnv("TEST_DB_PASSWORD", "postgres"))
	os.Setenv("DB_NAME", getEnv("TEST_DB_NAME", "secure_service"))

	if err := InitDB(); err != nil {
		t.Skip("skipping: test database is not available (" + err.Error() + ")")
	}
}

func registerRequestBody(email, username, password string) *bytes.Buffer {
	body, _ := json.Marshal(RegisterRequest{
		Email:    email,
		Username: username,
		Password: password,
	})
	return bytes.NewBuffer(body)
}

// Тесты ниже проверяют только путь валидации запроса: RegisterHandler возвращает ошибку раньше,
// чем обращается к базе данных, поэтому эти сценарии не требуют поднятой БД

func TestRegisterHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRegisterHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{not valid json"))
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRegisterHandler_InvalidEmail(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody("not-an-email", "validuser", "SecurePass123"))
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRegisterHandler_InvalidUsername(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody("valid@example.com", "bad user!", "SecurePass123"))
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRegisterHandler_WeakPassword(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody("valid@example.com", "validuser", "weak"))
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// Тесты ниже требуют реальной базы данных (поднятой через docker-compose up -d)
// Если БД недоступна, они пропускаются

func TestRegisterHandler_Success(t *testing.T) {
	setupTestDB(t)
	initTestAuth(t)

	email := fmt.Sprintf("success_%d@example.com", os.Getpid())
	username := fmt.Sprintf("success_%d", os.Getpid())

	req := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody(email, username, "SecurePass123"))
	rec := httptest.NewRecorder()

	RegisterHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp AuthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected a non-empty token in response")
	}
	if resp.User.Email != email {
		t.Errorf("response user email = %q, want %q", resp.User.Email, email)
	}
}

func TestRegisterHandler_DuplicateEmail(t *testing.T) {
	setupTestDB(t)
	initTestAuth(t)

	email := fmt.Sprintf("dupemail_%d@example.com", os.Getpid())

	first := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody(email, fmt.Sprintf("dupemail1_%d", os.Getpid()), "SecurePass123"))
	RegisterHandler(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody(email, fmt.Sprintf("dupemail2_%d", os.Getpid()), "SecurePass123"))
	rec := httptest.NewRecorder()
	RegisterHandler(rec, second)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestRegisterHandler_DuplicateUsername(t *testing.T) {
	setupTestDB(t)
	initTestAuth(t)

	username := fmt.Sprintf("dupuser_%d", os.Getpid())

	first := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody(fmt.Sprintf("dupuser1_%d@example.com", os.Getpid()), username, "SecurePass123"))
	RegisterHandler(httptest.NewRecorder(), first)

	second := httptest.NewRequest(http.MethodPost, "/register", registerRequestBody(fmt.Sprintf("dupuser2_%d@example.com", os.Getpid()), username, "SecurePass123"))
	rec := httptest.NewRecorder()
	RegisterHandler(rec, second)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}
