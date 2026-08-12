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
