package plugin

import "testing"

func TestPriorityAndAction(t *testing.T) {
	// KEV (actively exploited) must outrank a higher-EPSS non-KEV finding.
	kevLowEpss := priorityScore(3, 0.10, true)
	noKevHighEpss := priorityScore(4, 0.99, false)
	if kevLowEpss <= noKevHighEpss {
		t.Errorf("KEV (%d) should outrank non-KEV high-EPSS (%d)", kevLowEpss, noKevHighEpss)
	}
	if got := actionLabel(0.9, true); got != "now" {
		t.Errorf("KEV action = %q, want now", got)
	}
	if got := actionLabel(0.6, false); got != "urgent" {
		t.Errorf("high EPSS action = %q, want urgent", got)
	}
	if got := actionLabel(0.01, false); got != "backlog" {
		t.Errorf("low EPSS action = %q, want backlog", got)
	}
}

func TestPriorityIsStrictlyKevThenEpssThenSeverity(t *testing.T) {
	const critical, high, low = 4, 3, 1
	// A higher EPSS wins over a higher severity, however small the gap.
	if a, b := priorityScore(high, 0.083, false), priorityScore(critical, 0.014, false); a <= b {
		t.Errorf("HIGH at 8.3%% (%d) should outrank CRITICAL at 1.4%% (%d)", a, b)
	}
	if a, b := priorityScore(low, 0.0091, false), priorityScore(critical, 0.0090, false); a <= b {
		t.Errorf("LOW at 0.91%% (%d) should outrank CRITICAL at 0.90%% (%d)", a, b)
	}
	// With the same EPSS, severity decides.
	if a, b := priorityScore(critical, 0.5, false), priorityScore(high, 0.5, false); a <= b {
		t.Errorf("CRITICAL (%d) should outrank HIGH (%d) at equal EPSS", a, b)
	}
	// KEV beats the best possible non-KEV finding.
	if a, b := priorityScore(low, 0, true), priorityScore(critical, 1, false); a <= b {
		t.Errorf("KEV LOW at 0%% (%d) should outrank non-KEV CRITICAL at 100%% (%d)", a, b)
	}
}
