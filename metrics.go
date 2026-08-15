package cf_http_ratelimiter

import (
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
)

func (c *RateLimiter) Metrics() []cf_observability.Metric {
	if !c.initialized.Load() {
		return nil
	}
	if !c.metricsEnabledValue() {
		return nil
	}
	labels := map[string]string{"component": c.Name(), "state": c.peerName()}
	ms := []cf_observability.Metric{
		{
			Name:   "http_ratelimiter_info",
			Help:   "HTTP rate limiter descriptor; 1 while initialized.",
			Value:  1,
			Labels: copyLabels(labels),
		},
		{
			Name:   "http_ratelimiter_allows_total",
			Help:   "Total number of Allow / successful Wait grants (Allowed=true).",
			Value:  float64(c.allows.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_denies_total",
			Help:   "Total number of Allow calls over the limit (Allowed=false).",
			Value:  float64(c.denies.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_resets_total",
			Help:   "Total number of Reset calls.",
			Value:  float64(c.resets.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_peeks_total",
			Help:   "Total number of Peek calls.",
			Value:  float64(c.peeks.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_storage_errors_total",
			Help:   "Store errors returned by valkey-state before fail-open/fail-closed.",
			Value:  float64(c.storageErrors.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_fail_open_total",
			Help:   "Times a store error was treated as allowed (FailOpen).",
			Value:  float64(c.fbOpen.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_fail_closed_total",
			Help:   "Times a store error was returned (FailClosed).",
			Value:  float64(c.fbClosed.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_key_rejected_empty_total",
			Help:   "Allow/Peek/Reset/Wait rejected because the logical key was empty.",
			Value:  float64(c.rejectedEmpty.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_key_rejected_long_total",
			Help:   "Allow/Peek/Reset/Wait rejected because the logical key was too long.",
			Value:  float64(c.rejectedLong.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_disabled_total",
			Help:   "Calls with limit <= 0 (rate limiting disabled for that call).",
			Value:  float64(c.disabled.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
	}
	return ms
}

func copyLabels(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
