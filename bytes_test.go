// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"bytes"
	"testing"
)

func TestBytesSecret_UnmarshalText(t *testing.T) {
	var s PlainSecret[[]byte]
	err := s.UnmarshalText([]byte("my-secret"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !bytes.Equal(s.Secret(), []byte("my-secret")) {
		t.Errorf("Expected 'my-secret', got '%s'", s)
	}
}

func TestBytesSecret_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		secret   Secret[[]byte]
		expected []byte
	}{
		{"Empty secret", NewSecret([]byte{}), []byte("")},
		{"Non-empty secret", NewSecret([]byte("password123")), []byte("*****")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.secret.MarshalText()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !bytes.Equal(b, tt.expected) {
				t.Errorf("Expected '%s', got '%s'", tt.expected, string(b))
			}
		})
	}
}

func TestBytesSecret_Secret(t *testing.T) {
	s := NewSecret([]byte("super-secret-value"))
	if val := s.Secret(); !bytes.Equal(val, []byte("super-secret-value")) {
		t.Errorf("Expected 'super-secret-value', got '%s'", val)
	}
}

func TestBytesSecret_Empty(t *testing.T) {
	var nilSecret PlainSecret[[]byte]
	if !nilSecret.Empty() {
		t.Error("Expected nil secret to be empty")
	}

	emptySecret := NewSecret([]byte{})
	if !emptySecret.Empty() {
		t.Error("Expected empty string secret to be empty")
	}

	nonEmptySecret := NewSecret([]byte("value"))
	if nonEmptySecret.Empty() {
		t.Error("Expected non-empty secret to not be empty")
	}
}
