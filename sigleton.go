package secrets

import (
	"sync"

	"github.com/zauberhaus/reflect_utils"
)

type Singleton[T any] struct {
	value T
	init  func() T

	lock sync.Mutex
}

func NewSingleton[T any](init func() T) Singleton[T] {
	return Singleton[T]{init: init}
}

func (s *Singleton[T]) Get() T {
	s.lock.Lock()
	defer s.lock.Unlock()

	if reflect_utils.IsEmpty(s.value) {
		s.value = s.init()
	}

	return s.value
}
