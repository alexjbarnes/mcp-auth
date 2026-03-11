package mcpauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- loginRateLimiter tests ---

func TestLoginRateLimiter_NotLimitedInitially(t *testing.T) {
	rl := newLoginRateLimiter()
	assert.False(t, rl.check("1.2.3.4"))
}

func TestLoginRateLimiter_RecordFailure(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	for i := 0; i < rateLimitMaxFail-1; i++ {
		rl.record(ip)
		assert.False(t, rl.check(ip), "should not be limited at %d failures", i+1)
	}

	// One more failure should trigger rate limit
	rl.record(ip)
	assert.True(t, rl.check(ip))
}

func TestLoginRateLimiter_MultipleIPs(t *testing.T) {
	rl := newLoginRateLimiter()
	ip1 := "1.2.3.4"
	ip2 := "5.6.7.8"

	// Rate limit ip1
	for i := 0; i < rateLimitMaxFail; i++ {
		rl.record(ip1)
	}

	// ip1 should be limited, ip2 should not
	assert.True(t, rl.check(ip1))
	assert.False(t, rl.check(ip2))

	// Rate limit ip2
	for i := 0; i < rateLimitMaxFail; i++ {
		rl.record(ip2)
	}

	// Both should be limited
	assert.True(t, rl.check(ip1))
	assert.True(t, rl.check(ip2))
}

func TestLoginRateLimiter_SlidingWindow(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	// Add old failures that should expire
	rl.mu.Lock()
	rl.failures[ip] = []time.Time{
		time.Now().Add(-rateLimitWindow - time.Minute),
		time.Now().Add(-rateLimitWindow - time.Minute),
	}
	rl.mu.Unlock()

	// Should not be limited (old failures expired)
	assert.False(t, rl.check(ip))

	// Verify expired entries were cleaned up
	rl.mu.Lock()
	assert.Empty(t, rl.failures[ip])
	rl.mu.Unlock()
}

func TestLoginRateLimiter_PartialExpiry(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	// Add some old and some recent failures
	rl.mu.Lock()
	rl.failures[ip] = []time.Time{
		time.Now().Add(-rateLimitWindow - time.Minute), // Expired
		time.Now().Add(-rateLimitWindow - time.Minute), // Expired
		time.Now().Add(-time.Minute),                   // Recent
		time.Now().Add(-time.Minute),                   // Recent
	}
	rl.mu.Unlock()

	// Should not be limited (only 2 recent failures)
	assert.False(t, rl.check(ip))

	// Verify only recent failures remain
	rl.mu.Lock()
	assert.Len(t, rl.failures[ip], 2)
	rl.mu.Unlock()
}

func TestLoginRateLimiter_PruneThreshold(t *testing.T) {
	rl := newLoginRateLimiter()

	// Add many expired entries to trigger pruning
	rl.mu.Lock()
	for i := 0; i < rateLimitPruneThreshold+100; i++ {
		ip := "1.2.3." + string(rune(i))
		rl.failures[ip] = []time.Time{
			time.Now().Add(-rateLimitWindow - time.Minute),
		}
	}
	initialCount := len(rl.failures)
	rl.mu.Unlock()

	// Check should trigger pruning
	rl.check("test-ip")

	rl.mu.Lock()
	finalCount := len(rl.failures)
	rl.mu.Unlock()

	// Should have pruned expired entries
	assert.Less(t, finalCount, initialCount)
}

func TestLoginRateLimiter_RecordMultipleSimultaneous(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	// Record multiple failures at once
	for i := 0; i < rateLimitMaxFail; i++ {
		rl.record(ip)
	}

	assert.True(t, rl.check(ip))

	rl.mu.Lock()
	assert.Len(t, rl.failures[ip], rateLimitMaxFail)
	rl.mu.Unlock()
}

func TestLoginRateLimiter_CheckDoesNotModifyState(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	// Record some failures
	for i := 0; i < 5; i++ {
		rl.record(ip)
	}

	// Multiple checks should return same result
	result1 := rl.check(ip)
	result2 := rl.check(ip)
	result3 := rl.check(ip)

	assert.Equal(t, result1, result2)
	assert.Equal(t, result2, result3)
}

func TestLoginRateLimiter_EmptyIP(t *testing.T) {
	rl := newLoginRateLimiter()

	rl.record("")
	assert.False(t, rl.check(""))
}

func TestLoginRateLimiter_ResetAfterWindow(t *testing.T) {
	rl := newLoginRateLimiter()
	ip := "1.2.3.4"

	// Rate limit the IP
	for i := 0; i < rateLimitMaxFail; i++ {
		rl.record(ip)
	}
	assert.True(t, rl.check(ip))

	// Manually expire all failures
	rl.mu.Lock()
	for i := range rl.failures[ip] {
		rl.failures[ip][i] = time.Now().Add(-rateLimitWindow - time.Minute)
	}
	rl.mu.Unlock()

	// Should no longer be limited
	assert.False(t, rl.check(ip))
}

// --- tokenRateLimiter tests ---

func TestTokenRateLimiter_IPNotLimitedInitially(t *testing.T) {
	trl := newTokenRateLimiter()
	assert.False(t, trl.checkIP("1.2.3.4"))
}

func TestTokenRateLimiter_IPRateLimit(t *testing.T) {
	trl := newTokenRateLimiter()
	ip := "1.2.3.4"

	// Record failures up to limit
	for i := 0; i < tokenRateLimitMaxFail; i++ {
		trl.recordFailure(ip, "")
		if i < tokenRateLimitMaxFail-1 {
			assert.False(t, trl.checkIP(ip))
		}
	}

	// Should be rate limited
	assert.True(t, trl.checkIP(ip))
}

func TestTokenRateLimiter_IPSlidingWindow(t *testing.T) {
	trl := newTokenRateLimiter()
	ip := "1.2.3.4"

	// Add old failures
	trl.mu.Lock()
	trl.ipFails[ip] = []time.Time{
		time.Now().Add(-tokenRateLimitWindow - time.Minute),
	}
	trl.mu.Unlock()

	// Should not be limited (old failures expired)
	assert.False(t, trl.checkIP(ip))
}

func TestTokenRateLimiter_LockoutNotSetInitially(t *testing.T) {
	trl := newTokenRateLimiter()
	assert.False(t, trl.checkLockout("client1"))
}

func TestTokenRateLimiter_LockoutAfterThreshold(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Record failures up to threshold
	for i := 0; i < lockoutThreshold; i++ {
		trl.recordFailure(ip, clientID)
	}

	// Should be locked out
	assert.True(t, trl.checkLockout(clientID))
}

func TestTokenRateLimiter_LockoutExpiresAfterDuration(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Trigger lockout
	for i := 0; i < lockoutThreshold; i++ {
		trl.recordFailure(ip, clientID)
	}
	assert.True(t, trl.checkLockout(clientID))

	// Manually expire the lockout
	trl.mu.Lock()
	entry := trl.lockouts[clientID]
	entry.lockedAt = time.Now().Add(-lockoutDuration - time.Minute)
	trl.lockouts[clientID] = entry
	trl.mu.Unlock()

	// Should no longer be locked out
	assert.False(t, trl.checkLockout(clientID))

	// Should have been cleaned up
	trl.mu.Lock()
	_, exists := trl.lockouts[clientID]
	trl.mu.Unlock()
	assert.False(t, exists)
}

func TestTokenRateLimiter_ClearLockout(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Trigger lockout
	for i := 0; i < lockoutThreshold; i++ {
		trl.recordFailure(ip, clientID)
	}
	assert.True(t, trl.checkLockout(clientID))

	// Clear the lockout
	trl.clearLockout(clientID)

	// Should no longer be locked out
	assert.False(t, trl.checkLockout(clientID))
}

func TestTokenRateLimiter_ClearLockoutEmptyClientID(t *testing.T) {
	trl := newTokenRateLimiter()

	// Should not panic
	trl.clearLockout("")
}

func TestTokenRateLimiter_RecordFailureIPOnly(t *testing.T) {
	trl := newTokenRateLimiter()
	ip := "1.2.3.4"

	// Record IP-only failures
	for i := 0; i < tokenRateLimitMaxFail; i++ {
		trl.recordFailure(ip, "")
	}

	// IP should be rate limited
	assert.True(t, trl.checkIP(ip))

	// No client lockout should be created
	trl.mu.Lock()
	assert.Empty(t, trl.lockouts)
	trl.mu.Unlock()
}

func TestTokenRateLimiter_MultipleClients(t *testing.T) {
	trl := newTokenRateLimiter()
	ip := "1.2.3.4"

	// Lock out client1
	for i := 0; i < lockoutThreshold; i++ {
		trl.recordFailure(ip, "client1")
	}

	// Lock out client2
	for i := 0; i < lockoutThreshold; i++ {
		trl.recordFailure(ip, "client2")
	}

	// Both should be locked out
	assert.True(t, trl.checkLockout("client1"))
	assert.True(t, trl.checkLockout("client2"))

	// client3 should not be locked out
	assert.False(t, trl.checkLockout("client3"))
}

func TestTokenRateLimiter_LockoutPruning(t *testing.T) {
	trl := newTokenRateLimiter()

	// Add many expired lockouts
	trl.mu.Lock()
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		clientID := "client" + string(rune(i))
		trl.lockouts[clientID] = &lockoutEntry{
			failures:      1,
			lockedAt:      time.Now().Add(-lockoutDuration - time.Minute),
			lastFailureAt: time.Now().Add(-lockoutDuration - time.Minute),
		}
	}
	initialCount := len(trl.lockouts)
	trl.mu.Unlock()

	// Check should trigger pruning
	trl.checkLockout("test-client")

	trl.mu.Lock()
	finalCount := len(trl.lockouts)
	trl.mu.Unlock()

	// Should have pruned expired entries
	assert.Less(t, finalCount, initialCount)
}

func TestTokenRateLimiter_IPPruning(t *testing.T) {
	trl := newTokenRateLimiter()

	// Add many expired IP failures
	trl.mu.Lock()
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		ip := "1.2.3." + string(rune(i))
		trl.ipFails[ip] = []time.Time{
			time.Now().Add(-tokenRateLimitWindow - time.Minute),
		}
	}
	initialCount := len(trl.ipFails)
	trl.mu.Unlock()

	// Check should trigger pruning
	trl.checkIP("test-ip")

	trl.mu.Lock()
	finalCount := len(trl.ipFails)
	trl.mu.Unlock()

	// Should have pruned expired entries
	assert.Less(t, finalCount, initialCount)
}

func TestTokenRateLimiter_LockoutKeepsRecentFailures(t *testing.T) {
	trl := newTokenRateLimiter()

	// Add active lockout
	trl.mu.Lock()
	trl.lockouts["active"] = &lockoutEntry{
		failures:      lockoutThreshold,
		lockedAt:      time.Now(),
		lastFailureAt: time.Now(),
	}

	// Add stale lockout
	trl.lockouts["stale"] = &lockoutEntry{
		failures:      1,
		lockedAt:      time.Now().Add(-lockoutDuration - time.Minute),
		lastFailureAt: time.Now().Add(-lockoutDuration - time.Minute),
	}

	// Add entry with recent failure but no lockout
	trl.lockouts["recent-failure"] = &lockoutEntry{
		failures:      5,
		lockedAt:      time.Time{},
		lastFailureAt: time.Now(),
	}

	// Fill to trigger pruning
	for i := 0; i < tokenLimiterPruneThreshold+100; i++ {
		clientID := "client" + string(rune(i))
		trl.lockouts[clientID] = &lockoutEntry{
			failures:      1,
			lockedAt:      time.Now().Add(-lockoutDuration - time.Minute),
			lastFailureAt: time.Now().Add(-lockoutDuration - time.Minute),
		}
	}
	trl.mu.Unlock()

	// Trigger pruning
	trl.checkLockout("active")

	trl.mu.Lock()
	_, activeExists := trl.lockouts["active"]
	_, staleExists := trl.lockouts["stale"]
	_, recentExists := trl.lockouts["recent-failure"]
	trl.mu.Unlock()

	// Active lockout should be kept
	assert.True(t, activeExists)

	// Stale lockout should be pruned
	assert.False(t, staleExists)

	// Recent failure (no lockout) should be kept
	assert.True(t, recentExists)
}

func TestTokenRateLimiter_IncrementalFailures(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Record failures incrementally
	for i := 0; i < lockoutThreshold-1; i++ {
		trl.recordFailure(ip, clientID)

		trl.mu.Lock()
		entry := trl.lockouts[clientID]
		trl.mu.Unlock()

		assert.Equal(t, i+1, entry.failures)
		assert.False(t, trl.checkLockout(clientID))
	}

	// One more should trigger lockout
	trl.recordFailure(ip, clientID)
	assert.True(t, trl.checkLockout(clientID))
}

func TestTokenRateLimiter_ClearResetsFailureCount(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Record some failures
	for i := 0; i < 5; i++ {
		trl.recordFailure(ip, clientID)
	}

	// Clear the lockout
	trl.clearLockout(clientID)

	// Record more failures (should start from 0 again)
	for i := 0; i < lockoutThreshold-1; i++ {
		trl.recordFailure(ip, clientID)
	}

	// Should not be locked out yet
	assert.False(t, trl.checkLockout(clientID))
}

func TestTokenRateLimiter_MultipleIPsSameClient(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"

	// Record failures from different IPs
	for i := 0; i < lockoutThreshold; i++ {
		ip := "1.2.3." + string(rune(i+4))
		trl.recordFailure(ip, clientID)
	}

	// Client should be locked out regardless of IP
	assert.True(t, trl.checkLockout(clientID))

	// None of the individual IPs should be rate limited
	for i := 0; i < lockoutThreshold; i++ {
		ip := "1.2.3." + string(rune(i+4))
		assert.False(t, trl.checkIP(ip))
	}
}

func TestTokenRateLimiter_LockoutEntry_UpdatesLastFailureTime(t *testing.T) {
	trl := newTokenRateLimiter()
	clientID := "client1"
	ip := "1.2.3.4"

	// Record first failure
	trl.recordFailure(ip, clientID)

	trl.mu.Lock()
	entry1 := trl.lockouts[clientID]
	firstFailureTime := entry1.lastFailureAt
	trl.mu.Unlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Record second failure
	trl.recordFailure(ip, clientID)

	trl.mu.Lock()
	entry2 := trl.lockouts[clientID]
	secondFailureTime := entry2.lastFailureAt
	trl.mu.Unlock()

	// Last failure time should have been updated
	assert.True(t, secondFailureTime.After(firstFailureTime))
}