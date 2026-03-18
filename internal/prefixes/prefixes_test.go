package prefixes

import (
	"net/netip"
	"testing"
)

func TestMergeGroupsPrefixesAndASNs(t *testing.T) {
	entries, totalAddresses, totalScanHosts, err := Merge([]SourcePrefix{
		{ASN: "AS1", Prefix: "10.0.0.0/30"},
		{ASN: "AS2", Prefix: "10.0.0.0/30"},
		{ASN: "AS2", Prefix: "10.0.1.0/31"},
	})
	if err != nil {
		t.Fatalf("Merge returned error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 merged entries, got %d", len(entries))
	}
	if totalAddresses != 6 {
		t.Fatalf("expected 6 total addresses, got %d", totalAddresses)
	}
	if totalScanHosts != 4 {
		t.Fatalf("expected 4 scan hosts, got %d", totalScanHosts)
	}
	if got := CompactASNLabel(entries[0].SourceASNs); got != "AS1, AS2" {
		t.Fatalf("unexpected ASN label: %s", got)
	}
}

func TestWalkHostsRespectsUsableRangeAndLimit(t *testing.T) {
	entries, _, _, err := Merge([]SourcePrefix{
		{ASN: "AS1", Prefix: "192.0.2.0/30"},
		{ASN: "AS2", Prefix: "192.0.2.10/31"},
	})
	if err != nil {
		t.Fatalf("Merge returned error: %v", err)
	}

	var visited []netip.Addr
	count, err := WalkHosts(entries, 3, func(addr netip.Addr, prefix string) bool {
		visited = append(visited, addr)
		return true
	})
	if err != nil {
		t.Fatalf("WalkHosts returned error: %v", err)
	}

	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}

	expected := []string{"192.0.2.1", "192.0.2.2", "192.0.2.10"}
	for i, addr := range visited {
		if got := addr.String(); got != expected[i] {
			t.Fatalf("visited[%d] = %s, want %s", i, got, expected[i])
		}
	}
}
