package mcpauth

import (
	"sync"
	"time"
)

const (
	// rateLimitWindow is the sliding window for login rate limiting.
	rateLimitWindow = 5 * time.Minute

	// rateLimitMaxFail is the maximum failed login attempts per IP
	// within the window before requests are rejected.
	rateLimitMaxFail = 10

	// rateLimitPruneThreshold is the number of tracked IPs above which
	// the rate limiter prunes expired entries to prevent unbounded growth.
	rateLimitPruneThreshold = 1000

	// tokenRateLimitWindow is the sliding window for per-IP rate
	// limiting on the token endpoint.
	tokenRateLimitWindow = time.Minute

	// tokenRateLimitMaxFail is the maximum failed attempts per IP
	// within the window before requests are rejected.
	tokenRateLimitMaxFail = 5

	// lockoutThreshold is the number of consecutive failed attempts
	// per client_id before the account is locked.
	lockoutThreshold = 10

	// lockoutDuration is how long a locked account stays locked.
	lockoutDuration = 15 * time.Minute

	// tokenLimiterPruneThreshold triggers pruning of stale entries
	// to prevent unbounded map growth.
	tokenLimiterPruneThreshold = 1000
)

// loginRateLimiter tracks failed login attempts per IP with a sliding
// window. After maxFailures within the window, further attempts are
// rejected until the window expires.
type loginRateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		failures: make(map[string][]time.Time),
	}
}

// check returns true if the IP is currently rate-limited.
func (rl *loginRateLimiter) check(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rateLimitWindow)

	if len(rl.failures) > rateLimitPruneThreshold {
		for k, times := range rl.failures {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(rl.failures, k)
			}
		}
	}

	recent := rl.failures[ip][:0]
	for _, t := range rl.failures[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) == 0 {
		delete(rl.failures, ip)
	} else {
		rl.failures[ip] = recent
	}

	return len(recent) >= rateLimitMaxFail
}

// record adds a failed attempt for the IP.
func (rl *loginRateLimiter) record(ip string) {
	rl.mu.Lock()
	rl.failures[ip] = append(rl.failures[ip], time.Now())
	rl.mu.Unlock()
}

// lockoutEntry tracks consecutive failures and lockout state for a
// single client_id.
type lockoutEntry struct {
	failures      int
	lockedAt      time.Time
	lastFailureAt time.Time
}

// tokenRateLimiter combines per-IP sliding window rate limiting with
// per-client_id account lockout.
type tokenRateLimiter struct {
	mu       sync.Mutex
	ipFails  map[string][]time.Time
	lockouts map[string]*lockoutEntry
}

func newTokenRateLimiter() *tokenRateLimiter {
	return &tokenRateLimiter{
		ipFails:  make(map[string][]time.Time),
		lockouts: make(map[string]*lockoutEntry),
	}
}

// checkIP returns true if the IP is currently rate-limited.
func (trl *tokenRateLimiter) checkIP(ip string) bool {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-tokenRateLimitWindow)

	if len(trl.ipFails) > tokenLimiterPruneThreshold {
		for k, times := range trl.ipFails {
			if len(times) == 0 || times[len(times)-1].Before(cutoff) {
				delete(trl.ipFails, k)
			}
		}
	}

	recent := trl.ipFails[ip][:0]
	for _, t := range trl.ipFails[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) == 0 {
		delete(trl.ipFails, ip)
	} else {
		trl.ipFails[ip] = recent
	}

	return len(recent) >= tokenRateLimitMaxFail
}

// checkLockout returns true if the client_id is currently locked out.
func (trl *tokenRateLimiter) checkLockout(clientID string) bool {
	if clientID == "" {
		return false
	}

	trl.mu.Lock()
	defer trl.mu.Unlock()

	now := time.Now()

	if len(trl.lockouts) > tokenLimiterPruneThreshold {
		for k, e := range trl.lockouts {
			activeLock := !e.lockedAt.IsZero() && now.Before(e.lockedAt.Add(lockoutDuration))
			recentFailure := now.Before(e.lastFailureAt.Add(lockoutDuration))
			if !activeLock && !recentFailure {
				delete(trl.lockouts, k)
			}
		}
	}

	entry, ok := trl.lockouts[clientID]
	if !ok {
		return false
	}

	if !entry.lockedAt.IsZero() && now.Before(entry.lockedAt.Add(lockoutDuration)) {
		return true
	}

	if !entry.lockedAt.IsZero() {
		delete(trl.lockouts, clientID)
	}

	return false
}

// recordFailure records a failed attempt for both IP and client_id.
func (trl *tokenRateLimiter) recordFailure(ip, clientID string) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	trl.ipFails[ip] = append(trl.ipFails[ip], time.Now())

	if clientID == "" {
		return
	}

	entry, ok := trl.lockouts[clientID]
	if !ok {
		entry = &lockoutEntry{}
		trl.lockouts[clientID] = entry
	}

	entry.failures++
	entry.lastFailureAt = time.Now()

	if entry.failures >= lockoutThreshold {
		entry.lockedAt = time.Now()
	}
}

// clearLockout resets the failure counter for a client_id on successful auth.
func (trl *tokenRateLimiter) clearLockout(clientID string) {
	if clientID == "" {
		return
	}

	trl.mu.Lock()
	delete(trl.lockouts, clientID)
	trl.mu.Unlock()
}
