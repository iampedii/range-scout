package dnsttembed

import (
	"testing"
	"time"
)

func TestDNSPacketConnConfigMatchesSlipNetDefaults(t *testing.T) {
	nonAuthoritative := dnsPacketConnConfig(false)
	if nonAuthoritative == nil || nonAuthoritative.PollLimit != 8 {
		t.Fatalf("expected non-authoritative PollLimit 8, got %#v", nonAuthoritative)
	}
	if nonAuthoritative.InitPollDelay != 0 || nonAuthoritative.MaxPollDelay != 0 {
		t.Fatalf("expected default poll delays for non-authoritative mode, got %#v", nonAuthoritative)
	}

	authoritative := dnsPacketConnConfig(true)
	if authoritative == nil || authoritative.PollLimit != 16 {
		t.Fatalf("expected authoritative PollLimit 16, got %#v", authoritative)
	}
	if authoritative.InitPollDelay != 200*time.Millisecond || authoritative.MaxPollDelay != 4*time.Second {
		t.Fatalf("unexpected authoritative poll timings: %#v", authoritative)
	}
}

func TestEffectiveMaxPayloadIgnoresTinyOrOversizedValues(t *testing.T) {
	if got := effectiveMaxPayload(49, 120); got != 0 {
		t.Fatalf("expected tiny payload to be ignored, got %d", got)
	}
	if got := effectiveMaxPayload(120, 120); got != 0 {
		t.Fatalf("expected mtu-sized payload to be ignored, got %d", got)
	}
	if got := effectiveMaxPayload(200, 120); got != 0 {
		t.Fatalf("expected oversized payload to be ignored, got %d", got)
	}
	if got := effectiveMaxPayload(96, 120); got != 96 {
		t.Fatalf("expected valid capped payload, got %d", got)
	}
}
