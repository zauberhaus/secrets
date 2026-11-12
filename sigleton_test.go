// Copyright 2026 Zauberhaus
// Licensed to Zauberhaus under one or more agreements.
// Zauberhaus licenses this file to you under the Apache 2.0 License.
// See the LICENSE file in the project root for more information.

package secrets

import (
	"testing"
)

func TestSingleton_String(t *testing.T) {
	initCount := 0
	s := NewSingleton(func() string {
		initCount++
		return "hello"
	})

	val1 := s.Get()
	if val1 != "hello" {
		t.Errorf("Expected 'hello', got '%s'", val1)
	}
	if initCount != 1 {
		t.Errorf("Expected initCount to be 1, got %d", initCount)
	}

	// Get again, should not call init()
	val2 := s.Get()
	if val2 != "hello" {
		t.Errorf("Expected 'hello', got '%s'", val2)
	}
	if initCount != 1 {
		t.Errorf("Expected initCount to still be 1, got %d", initCount)
	}
}

func TestSingleton_Int(t *testing.T) {
	initCount := 0
	s := NewSingleton(func() int {
		initCount++
		return 42
	})

	val1 := s.Get()
	if val1 != 42 {
		t.Errorf("Expected 42, got %d", val1)
	}
	if initCount != 1 {
		t.Errorf("Expected initCount to be 1, got %d", initCount)
	}

	// Get again, should not call init()
	val2 := s.Get()
	if val2 != 42 {
		t.Errorf("Expected 42, got %d", val2)
	}
	if initCount != 1 {
		t.Errorf("Expected initCount to still be 1, got %d", initCount)
	}
}
