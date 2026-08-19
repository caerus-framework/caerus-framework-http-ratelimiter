package cf_http_ratelimiter

import (
	"errors"
	"net"
	"net/http"
)

// Middleware builds a stdlib middleware (func(http.Handler) http.Handler) from
// cfg. It errors when Limiter, KeyFunc, or OnStoreError are nil, or when
// Window <= 0. OnStoreError is required: choosing this module means tuning
// store-error policy — there is no silent FailOpen. StorageMemoryFallback
// requires the limiter's use_memory_fallback capability to be on. MiddlewareConfig.Memory
// is wired into AllowWithPolicyOpts for per-route sizing overrides.
//
// The middleware never sleeps. On denial it answers immediately: 429 with a
// Retry-After header from Result.ResetIn (or 503 for a FailClosed store error,
// with Retry-After: 1). Default body is plain http.Error; set ErrorWriter
// (e.g. problem.ErrorWriter) or OnDenied for custom responses. RateLimitHeaders
// is opt-in. The client is responsible for waiting.
func Middleware(cfg MiddlewareConfig) (func(http.Handler) http.Handler, error) {
	if cfg.Limiter == nil {
		return nil, errors.New("cf_http_ratelimiter: Middleware: Limiter is required")
	}
	if cfg.OnStoreError == nil {
		return nil, errors.New("cf_http_ratelimiter: Middleware: OnStoreError is required — choosing this module means tuning store-error policy")
	}
	if *cfg.OnStoreError == StorageMemoryFallback {
		return nil, errors.New("cf_http_ratelimiter: Middleware: StorageMemoryFallback is removed; set rate_limit memory on valkey-state")
	}
	if cfg.KeyFunc == nil {
		return nil, errors.New("cf_http_ratelimiter: Middleware: KeyFunc is required — use a trusted client identity (e.g. RemoteAddrKey or your mesh's normalized IP), not a client-supplied header")
	}
	if cfg.Window <= 0 {
		return nil, errors.New("cf_http_ratelimiter: Middleware: Window must be > 0")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := cfg.KeyFunc(r)
			res, err := cfg.Limiter.AllowWithPolicyOpts(r.Context(), key, cfg.Limit, cfg.Window, *cfg.OnStoreError, cfg.Memory)
			if err != nil {
				// FailClosed store error (or a memory error): the store could
				// not answer. 503, not 429 — the limiter itself is down.
				writeDefaultDenied(w, r, cfg, res, http.StatusServiceUnavailable)
				return
			}
			if !res.Allowed {
				writeDefaultDenied(w, r, cfg, res, http.StatusTooManyRequests)
				return
			}
			if cfg.RateLimitHeaders {
				setRateLimitHeaders(w, cfg.Limit, res)
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// RemoteAddrKey returns the host (IP) from r.RemoteAddr with the port stripped.
// It is a footnote helper for local demos only — behind a load balancer use
// identity your ingress/mesh already normalized (e.g. Echo RealIP() under a
// correct proxy contract), not a client-supplied X-Forwarded-For.
func RemoteAddrKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
