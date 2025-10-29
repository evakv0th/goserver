package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashAndCheckPassword(t *testing.T) {
	password := "mysecretpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword returned empty string")
	}

	// Correct password
	match, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error: %v", err)
	}
	if !match {
		t.Fatal("CheckPasswordHash failed for correct password")
	}

	// Wrong password
	match, err = CheckPasswordHash("wrongpassword", hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash returned error for wrong password: %v", err)
	}
	if match {
		t.Fatal("CheckPasswordHash returned true for wrong password")
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "testsecret"
	exp := time.Hour

	token, err := MakeJWT(userID, secret, exp)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}
	if token == "" {
		t.Fatal("MakeJWT returned empty token")
	}

	// Valid token
	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT returned error for valid token: %v", err)
	}
	if parsedID != userID {
		t.Fatalf("ValidateJWT returned wrong userID: got %v, want %v", parsedID, userID)
	}

	// Tampered token
	_, err = ValidateJWT(token+"tampered", secret)
	if err == nil {
		t.Fatal("ValidateJWT did not return error for tampered token")
	}

	// Wrong secret
	_, err = ValidateJWT(token, "wrongsecret")
	if err == nil {
		t.Fatal("ValidateJWT did not return error for wrong secret")
	}
}

func TestJWTExpired(t *testing.T) {
	userID := uuid.New()
	secret := "testsecret"

	// Token that expires immediately
	token, err := MakeJWT(userID, secret, -time.Second)
	if err != nil {
		t.Fatalf("MakeJWT returned error: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("ValidateJWT did not return error for expired token")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expected    string
		expectError bool
	}{
		{
			name: "valid token",
			headers: http.Header{
				"Authorization": []string{"Bearer mytoken123"},
			},
			expected:    "mytoken123",
			expectError: false,
		},
		{
			name:        "missing header",
			headers:     http.Header{},
			expected:    "",
			expectError: true,
		},
		{
			name: "wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Token mytoken123"},
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "short string",
			headers: http.Header{
				"Authorization": []string{"Be"},
			},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.headers)
			if tt.expectError && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != tt.expected {
				t.Fatalf("expected token %q, got %q", tt.expected, token)
			}
		})
	}
}
