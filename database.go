package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Глобальная переменная для подключения к БД
var db *sql.DB

// InitDB инициализирует подключение к базе данных
func InitDB() error {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", "postgres"),
		getEnv("DB_NAME", "secure_service"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// CreateUser создает нового пользователя в базе данных
// Используется параметризованный запрос ($1, $2, $3) для защиты от SQL-инъекций
func CreateUser(email, username, passwordHash string) (*User, error) {
	query := `INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id, created_at`

	user := &User{
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
	}

	err := db.QueryRow(query, email, username, passwordHash).Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return user, nil
}

// GetUserByEmail находит пользователя по email
// Используется параметризованный запрос для защиты от SQL-инъекций
func GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, username, password_hash, created_at FROM users WHERE email = $1`

	user := &User{}
	err := db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Username, &user.PasswordHash, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by email: %v", err)
	}

	return user, nil
}

// GetUserByID находит пользователя по ID
// password_hash намеренно не включен в SELECT — он не нужен для профиля
func GetUserByID(userID int) (*User, error) {
	query := `SELECT id, email, username, created_at FROM users WHERE id = $1`

	user := &User{}
	err := db.QueryRow(query, userID).Scan(
		&user.ID, &user.Email, &user.Username, &user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user by id: %v", err)
	}

	return user, nil
}

// UserExistsByEmail проверяет, существует ли пользователь с данным email
// Использует SQL EXISTS для эффективной проверки без загрузки полной записи
func UserExistsByEmail(email string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	var exists bool
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %v", err)
	}

	return exists, nil
}

// UserExistsByUsername проверяет, существует ли пользователь с данным username
// Использует SQL EXISTS для эффективной проверки без загрузки полной записи
func UserExistsByUsername(username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`

	var exists bool
	err := db.QueryRow(query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %v", err)
	}

	return exists, nil
}

// GetDB возвращает подключение к базе данных (для тестирования)
func GetDB() *sql.DB {
	return db
}
