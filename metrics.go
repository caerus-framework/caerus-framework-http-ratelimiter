package cf_http_ratelimiter

import (
	cf_observability "github.com/caerus-framework/caerus-framework-observability"
)

// Metrics implements cf_observability.MetricsProvider. It returns nil before
// Init / after Shutdown, and also when metrics_enabled is false (a reload can
// flip enablement live). Low-cardinality labels only — never raw keys, IPs, or
// emails. Counters appear at zero until first fired so the series are always
// present while initialized.
func (c *RateLimiter) Metrics() []cf_observability.Metric {
	if !c.initialized.Load() {
		return nil
	}
	if !c.metricsEnabledValue() {
		return nil
	}
	backend := "valkey"
	if c.memoryBackend {
		backend = "memory"
	}
	labels := map[string]string{"component": c.Name()}
	ms := []cf_observability.Metric{
		{
			Name:   "http_ratelimiter_info",
			Help:   "HTTP rate limiter descriptor; 1 while initialized.",
			Value:  1,
			Labels: copyLabels(labels, map[string]string{"backend": backend}),
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
			Name:   "http_ratelimiter_waits_total",
			Help:   "Finished Wait calls by result.",
			Value:  float64(c.waitsOK.Load()),
			Labels: copyLabels(labels, map[string]string{"result": "ok"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_waits_total",
			Help:   "Finished Wait calls by result.",
			Value:  float64(c.waitsCanceled.Load()),
			Labels: copyLabels(labels, map[string]string{"result": "canceled"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_waits_total",
			Help:   "Finished Wait calls by result.",
			Value:  float64(c.waitsErr.Load()),
			Labels: copyLabels(labels, map[string]string{"result": "error"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_wait_duration_seconds_sum",
			Help:   "Total seconds spent sleeping inside Wait (completed sleeps only).",
			Value:  float64(c.waitSleepNS.Load()) / 1e9,
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_wait_duration_seconds_count",
			Help:   "Number of completed Wait sleep intervals (for mean latency).",
			Value:  float64(c.waitSleepCnt.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_storage_errors_total",
			Help:   "Total number of primary store (Valkey) errors.",
			Value:  float64(c.storageErrors.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_policy_fallbacks_total",
			Help:   "Times a storage-error policy was applied, by policy.",
			Value:  float64(c.fbOpen.Load()),
			Labels: copyLabels(labels, map[string]string{"policy": "fail_open"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_policy_fallbacks_total",
			Help:   "Times a storage-error policy was applied, by policy.",
			Value:  float64(c.fbClosed.Load()),
			Labels: copyLabels(labels, map[string]string{"policy": "fail_closed"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_policy_fallbacks_total",
			Help:   "Times a storage-error policy was applied, by policy.",
			Value:  float64(c.fbMemory.Load()),
			Labels: copyLabels(labels, map[string]string{"policy": "memory_fallback"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_map_full_total",
			Help:   "Fallback/memory map hit its max entries, by action.",
			Value:  float64(c.memory.FullAllow()),
			Labels: copyLabels(labels, map[string]string{"action": "allow"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_map_full_total",
			Help:   "Fallback/memory map hit its max entries, by action.",
			Value:  float64(c.memory.FullDeny()),
			Labels: copyLabels(labels, map[string]string{"action": "deny"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_memory_entries",
			Help:   "Current distinct keys in the in-process map (0 if unused).",
			Value:  float64(c.memory.Len()),
			Labels: copyLabels(labels),
		},
		{
			Name:   "http_ratelimiter_config_reloads_total",
			Help:   "Total number of successful tunable reloads after a configuration reload.",
			Value:  float64(c.reloads.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_disabled_total",
			Help:   "Times Allow/Wait/AllowWithPolicy short-circuited because limit <= 0 (limiter off for that call).",
			Value:  float64(c.disabled.Load()),
			Labels: copyLabels(labels),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_key_rejected_total",
			Help:   "Logical keys rejected before storage, by reason.",
			Value:  float64(c.rejectedEmpty.Load()),
			Labels: copyLabels(labels, map[string]string{"reason": "empty"}),
			Type:   cf_observability.MetricTypeCounter,
		},
		{
			Name:   "http_ratelimiter_key_rejected_total",
			Help:   "Logical keys rejected before storage, by reason.",
			Value:  float64(c.rejectedLong.Load()),
			Labels: copyLabels(labels, map[string]string{"reason": "too_long"}),
			Type:   cf_observability.MetricTypeCounter,
		},
	}
	return ms
}

// copyLabels merges base and extra into a fresh map so callers cannot mutate
// the component's internal state.
func copyLabels(base map[string]string, extra ...map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for _, m := range extra {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
