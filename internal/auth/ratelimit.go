package auth

import (
	"sync"
	"time"
)

// LoginLimiter blocks a key after too many failures inside a sliding window.
// It is in-memory and per process, which is enough to slow down online guessing.
type LoginLimiter struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	failures    map[string][]time.Time
	// Now is overridable in tests.
	Now func() time.Time
}

// NewLoginLimiter creates a limiter allowing maxFailures per window.
func NewLoginLimiter(maxFailures int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{maxFailures: maxFailures, window: window, failures: map[string][]time.Time{}, Now: time.Now}
}

// Blocked reports whether the key has reached the failure budget.
func (l *LoginLimiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(key, l.Now())
	return len(l.failures[key]) >= l.maxFailures
}

// RecordFailure adds a failed attempt for the key.
func (l *LoginLimiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now()
	l.prune(key, now)
	l.failures[key] = append(l.failures[key], now)
}

// Reset forgets the failures of the key, after a successful login.
func (l *LoginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *LoginLimiter) prune(key string, now time.Time) {
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return
	}
	l.failures[key] = kept
}
