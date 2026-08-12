package cf_http_ratelimiter

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// memEntry is one key's fixed-window counter in the in-process map. The window
// is fixed from the call that created the entry; a later call with a different
// window only redefines it after the current one expires.
type memEntry struct {
	count       int64
	windowStart time.Time
	window      time.Duration
}

// memoryLimiter is the process-local fixed-window counter used when the
// sticky-note path is active (use_memory_fallback / force_memory / MemoryFallback). The
// component owns one shared instance, so "the map" is one thing with one
// http_ratelimiter_memory_entries gauge. Sizing (cap, map-full policy) is
// passed per call so reload tunables apply without rebuilding the map.
type memoryLimiter struct {
	mu        sync.Mutex
	entries   map[string]*memEntry
	fullAllow atomic.Uint64
	fullDeny  atomic.Uint64
}

func newMemoryLimiter() *memoryLimiter {
	return &memoryLimiter{entries: make(map[string]*memEntry)}
}

// sweepExpiredLocked deletes entries whose window has ended. Call with mu held.
// Running this before the map-full check frees slots from expired keys so a
// full map of stale counters does not spuriously deny or skip new keys.
func (m *memoryLimiter) sweepExpiredLocked(now time.Time) {
	for k, e := range m.entries {
		if now.Sub(e.windowStart) >= e.window {
			delete(m.entries, k)
		}
	}
}

// Allow increments the fixed-window counter for key. When the key is new and
// the map is at its MaxEntries cap, the configured WhenMapFull policy applies;
// the outcome is counted in FullAllow/FullDeny so the component can expose
// http_ratelimiter_map_full_total. Expired entries are swept before the cap
// check so they do not occupy slots forever.
func (m *memoryLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration, cfg MemoryFallbackConfig) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.MaxEntries <= 0 {
		// Misconfigured cap (should not happen: the component defaults it).
		// Permissive: allow without counting.
		return Result{Allowed: true}, nil
	}
	now := time.Now()
	m.sweepExpiredLocked(now)
	e, ok := m.entries[key]
	if !ok {
		if len(m.entries) >= cfg.MaxEntries {
			if cfg.WhenMapFull == MapFullDeny {
				m.fullDeny.Add(1)
				return Result{Allowed: false}, nil
			}
			m.fullAllow.Add(1)
			return Result{Allowed: true}, nil
		}
		e = &memEntry{windowStart: now, window: window}
		m.entries[key] = e
	}
	if now.Sub(e.windowStart) >= e.window {
		e.count = 0
		e.windowStart = now
		e.window = window
	}
	e.count++
	res := Result{Count: e.count, ResetIn: e.windowStart.Add(e.window).Sub(now)}
	res.Allowed = res.Count <= limit
	return res, nil
}

// Peek reads the counter and reset-in without incrementing. A missing or
// expired key reports an empty Result; expired entries are cleaned up lazily.
func (m *memoryLimiter) Peek(ctx context.Context, key string) Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e, ok := m.entries[key]
	if !ok {
		return Result{}
	}
	if now.Sub(e.windowStart) >= e.window {
		delete(m.entries, key)
		return Result{}
	}
	return Result{Count: e.count, ResetIn: e.windowStart.Add(e.window).Sub(now)}
}

// Reset deletes the counter for key (idempotent).
func (m *memoryLimiter) Reset(ctx context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

// Len returns the current number of distinct keys in the map.
func (m *memoryLimiter) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// FullAllow returns how many times a new key was allowed because the map was
// full (permissive).
func (m *memoryLimiter) FullAllow() uint64 { return m.fullAllow.Load() }

// FullDeny returns how many times a new key was denied because the map was
// full (MapFullDeny).
func (m *memoryLimiter) FullDeny() uint64 { return m.fullDeny.Load() }
