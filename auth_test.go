package main

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// initTestAuth инициализирует jwtSecret для тестов, не затрагивая переменные окружения приложения
func initTestAuth(t *testing.T) {
	t.Helper()
	os.Setenv("JWT_SECRET", "test-secret-key-at-least-32-characters-long")
	InitAuth()
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("SecurePass123")
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword() returned empty hash")
	}
	if hash == "SecurePass123" {
		t.Fatal("HashPassword() returned the plain password instead of a hash")
	}
}

func TestCheckPassword(t *testing.T) {
	hash, err := HashPassword("SecurePass123")
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	if !CheckPassword("SecurePass123", hash) {
		t.Error("CheckPassword() = false for correct password, want true")
	}

	if CheckPassword("WrongPassword1", hash) {
		t.Error("CheckPassword() = true for incorrect password, want false")
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid simple email", "user@example.com", false},
		{"valid with subdomain", "user@mail.example.co.uk", false},
		{"valid with plus tag", "user+tag@example.com", false},
		{"empty email", "", true},
		{"missing at sign", "userexample.com", true},
		{"missing domain", "user@", true},
		{"missing local part", "@example.com", true},
		{"missing tld", "user@example", true},
		{"spaces in email", "user name@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid username", "john_doe", false},
		{"valid alphanumeric", "user123", false},
		{"minimum length", "abc", false},
		{"maximum length", "a234567890123456789012345678z", false},
		{"empty username", "", true},
		{"too short", "ab", true},
		{"too long", "a2345678901234567890123456789zz", true},
		{"contains space", "bad user", true},
		{"contains special char", "bad!user", true},
		{"contains dash", "bad-user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%q) error = %v, wantErr %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid password", "SecurePass123", false},
		{"too short", "Pass1", true},
		{"no digit", "SecurePassword", true},
		{"no uppercase", "securepass123", true},
		{"minimum valid length", "Passw0rd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	initTestAuth(t)

	user := User{ID: 1, Email: "user@example.com", Username: "testuser"}
	token, err := GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned an empty token")
	}
}

func TestValidateToken(t *testing.T) {
	initTestAuth(t)

	user := User{ID: 1, Email: "user@example.com", Username: "testuser"}
	token, err := GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		claims, err := ValidateToken(token)
		if err != nil {
			t.Fatalf("ValidateToken() unexpected error: %v", err)
		}
		if claims.UserID != user.ID || claims.Email != user.Email || claims.Username != user.Username {
			t.Errorf("ValidateToken() claims = %+v, want matching user %+v", claims, user)
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		if _, err := ValidateToken("not-a-valid-token"); err == nil {
			t.Error("ValidateToken() expected error for malformed token, got nil")
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		badClaims := &Claims{
			UserID:   user.ID,
			Email:    user.Email,
			Username: user.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}
		badToken := jwt.NewWithClaims(jwt.SigningMethodHS256, badClaims)
		signedWithWrongKey, err := badToken.SignedString([]byte("a-completely-different-secret-key"))
		if err != nil {
			t.Fatalf("failed to sign test token: %v", err)
		}

		if _, err := ValidateToken(signedWithWrongKey); err == nil {
			t.Error("ValidateToken() expected error for token signed with wrong key, got nil")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		expiredClaims := &Claims{
			UserID:   user.ID,
			Email:    user.Email,
			Username: user.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
		}
		expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
		signed, err := expiredToken.SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("failed to sign test token: %v", err)
		}

		if _, err := ValidateToken(signed); err == nil {
			t.Error("ValidateToken() expected error for expired token, got nil")
		}
	})
}
