package cf_http_ratelimiter

import (
	"math"
	"net/http"
	"strconv"
	"time"

	cf_http "github.com/caerus-framework/caerus-framework-http"
)

const (
	// ErrCodeRateLimitExceeded is the stable Failure.Code for HTTP 429 denials
	// when MiddlewareConfig.ErrorWriter is set (e.g. problem.ErrorWriter).
	ErrCodeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"

	// ErrCodeRateLimitStoreUnavailable is the stable Failure.Code for HTTP 503
	// when the counter store could not answer and OnStoreError is FailClosed.
	ErrCodeRateLimitStoreUnavailable = "RATE_LIMIT_STORE_UNAVAILABLE"
)

func retryAfterSeconds(resetIn time.Duration) int64 {
	secs := int64(math.Ceil(resetIn.Seconds()))
	if secs <= 0 {
		return 1
	}
	return secs
}

func setRateLimitHeaders(w http.ResponseWriter, limit int64, res Result) {
	remaining := limit - res.Count
	if remaining < 0 {
		remaining = 0
	}
	resetUnix := time.Now().Add(res.ResetIn).Unix()
	w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(limit, 10))
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnix, 10))
}

func writeDefaultDenied(w http.ResponseWriter, r *http.Request, cfg MiddlewareConfig, res Result, status int) {
	if cfg.RateLimitHeaders {
		setRateLimitHeaders(w, cfg.Limit, res)
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(res.ResetIn), 10))
	} else if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}

	if cfg.OnDenied != nil {
		cfg.OnDenied(w, r, res, status)
		return
	}

	if cfg.ErrorWriter != nil {
		code := ErrCodeRateLimitExceeded
		if status == http.StatusServiceUnavailable {
			code = ErrCodeRateLimitStoreUnavailable
		}
		cfg.ErrorWriter(w, r, cf_http.Failure{
			Status:    status,
			Code:      code,
			RequestID: cf_http.RequestIDFrom(r),
		})
		return
	}

	http.Error(w, http.StatusText(status), status)
}
