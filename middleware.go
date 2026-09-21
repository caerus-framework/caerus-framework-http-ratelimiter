package cf_http_ratelimiter

import (
	"errors"
	"net"
	"net/http"
)

// Middleware builds a stdlib middleware (func(http.Handler) http.Handler) from
// cfg. It errors when Limiter, KeyFunc, or OnStoreError are nil, when Window
// is <= 0, or when OnStoreError is zero / MemoryFallback. OnStoreError is
// required: there is no silent FailOpen, and the zero value is not FailOpen.
//
// The middleware never sleeps. On denial it answers immediately: 429 with a
// Retry-After header from Result.ResetIn; 503 for a FailClosed store error or
// uninitialized limiter (Retry-After: 1); 400 when KeyFunc returns an empty
// or over-long key. FailOpen applies only to store errors, not to those
// programmer/key failures. Default body is plain http.Error; set ErrorWriter
// (e.g. problem.ErrorWriter) or OnDenied for custom responses. RateLimitHeaders
// is opt-in. The client is responsible for waiting.
func Middleware(cfg MiddlewareConfig) (func(http.Handler) http.Handler, error) {
	if cfg.Limiter == nil {
		return nil, errors.New("cf_http_ratelimiter: Middleware: Limiter is required")
	}
	if cfg.OnStoreError == nil {
		return nil, errors.New("cf_http_ratelimiter: Middleware: OnStoreError is required — choosing this module means tuning store-error policy")
	}
	switch *cfg.OnStoreError {
	case StorageFailOpen, StorageFailClosed:
	case StorageMemoryFallback:
		return nil, errors.New("cf_http_ratelimiter: Middleware: StorageMemoryFallback is removed; set rate_limit memory on valkey-state")
	default:
		return nil, errors.New("cf_http_ratelimiter: Middleware: OnStoreError must be StorageFailOpen or StorageFailClosed (zero is not FailOpen)")
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
				status := http.StatusServiceUnavailable
				if errors.Is(err, ErrEmptyKey) || errors.Is(err, ErrKeyTooLong) {
					status = http.StatusBadRequest
				}
				writeDefaultDenied(w, r, cfg, res, status)
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
