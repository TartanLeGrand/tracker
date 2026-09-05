package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoginLimiter(t *testing.T) {
	l := NewLoginLimiter(3, time.Minute)
	now := time.Now()
	l.Now = func() time.Time { return now }

	assert.False(t, l.Blocked("alice|1.1.1.1"))
	l.RecordFailure("alice|1.1.1.1")
	l.RecordFailure("alice|1.1.1.1")
	assert.False(t, l.Blocked("alice|1.1.1.1"))
	l.RecordFailure("alice|1.1.1.1")
	assert.True(t, l.Blocked("alice|1.1.1.1"))
	assert.False(t, l.Blocked("bob|1.1.1.1"), "keys are independent")

	now = now.Add(61 * time.Second)
	assert.False(t, l.Blocked("alice|1.1.1.1"), "failures expire with the window")

	l.RecordFailure("alice|1.1.1.1")
	l.RecordFailure("alice|1.1.1.1")
	l.RecordFailure("alice|1.1.1.1")
	assert.True(t, l.Blocked("alice|1.1.1.1"))
	l.Reset("alice|1.1.1.1")
	assert.False(t, l.Blocked("alice|1.1.1.1"))
}
