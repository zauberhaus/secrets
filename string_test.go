package secrets

import (
	"testing"
)

func TestSecret_UnmarshalText(t *testing.T) {
	var s PlainSecret[string]
	err := s.UnmarshalText([]byte("my-secret"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if s.Secret() != "my-secret" {
		t.Errorf("Expected 'my-secret', got '%s'", s)
	}
}

func TestSecret_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		secret   Secret[string]
		expected string
	}{
		{"Empty secret", NewSecret(""), ""},
		{"Non-empty secret", NewSecret("password123"), "*****"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.secret.MarshalText()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if string(b) != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, string(b))
			}
		})
	}
}

func TestSecret_Secret(t *testing.T) {
	s := NewSecret("super-secret-value")
	if val := s.Secret(); val != "super-secret-value" {
		t.Errorf("Expected 'super-secret-value', got '%s'", val)
	}
}

func TestSecret_Empty(t *testing.T) {
	var nilSecret PlainSecret[string]
	if !nilSecret.Empty() {
		t.Error("Expected nil secret to be empty")
	}

	emptySecret := NewSecret("")
	if !emptySecret.Empty() {
		t.Error("Expected empty string secret to be empty")
	}

	nonEmptySecret := NewSecret("value")
	if nonEmptySecret.Empty() {
		t.Error("Expected non-empty secret to not be empty")
	}
}
