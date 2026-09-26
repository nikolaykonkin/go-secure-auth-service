package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	emailExists, err := UserExistsByEmail(req.Email)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if emailExists {
		sendErrorResponse(w, "User with this email already exists", http.StatusConflict)
		return
	}

	usernameExists, err := UserExistsByUsername(req.Username)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if usernameExists {
		sendErrorResponse(w, "User with this username already exists", http.StatusConflict)
		return
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user, err := CreateUser(req.Email, req.Username, passwordHash)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusCreated)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Одинаковое сообщение об ошибке для неверного email и неверного пароля,
	// чтобы не раскрывать факт существования email в системе
	user, err := GetUserByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusOK)
}

// ProfileHandler возвращает профиль текущего пользователя
// Вызывается только после AuthMiddleware — контекст уже содержит userID
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := GetUserByID(userID)
	if err != nil {
		sendErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}

	sendJSONResponse(w, user, http.StatusOK)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if err := ValidateEmail(req.Email); err != nil {
		return err
	}

	if err := ValidateUsername(req.Username); err != nil {
		return err
	}

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
