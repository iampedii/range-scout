package prefixes

import (
	"net/netip"
	"strings"
	"testing"

	"range-scout/internal/model"
)

func TestMergeGroupsPrefixesAndASNs(t *testing.T) {
	entries, totalAddresses, totalScanHosts, _, err := Merge([]SourcePrefix{
		{ASN: "AS1", Prefix: "8.8.8.0/30"},
		{ASN: "AS2", Prefix: "8.8.8.0/30"},
		{ASN: "AS2", Prefix: "8.8.8.4/31"},
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
	entries, _, _, _, err := Merge([]SourcePrefix{
		{ASN: "AS1", Prefix: "8.8.8.0/30"},
		{ASN: "AS2", Prefix: "8.8.8.10/31"},
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

	expected := []string{"8.8.8.1", "8.8.8.2", "8.8.8.10"}
	for i, addr := range visited {
		if got := addr.String(); got != expected[i] {
			t.Fatalf("visited[%d] = %s, want %s", i, got, expected[i])
		}
	}
}

func TestWalkHostsSkipsBogons(t *testing.T) {
	entries := []model.PrefixEntry{
		{Prefix: "10.0.0.0/30"}, // entirely bogon
		{Prefix: "8.8.8.0/30"},  // public
	}
	var walked []string
	_, skipped, err := WalkHostsCounted(entries, 0, func(addr netip.Addr, prefix string) bool {
		walked = append(walked, addr.String())
		return true
	})
	if err != nil {
		t.Fatalf("WalkHostsCounted err: %v", err)
	}
	if skipped == 0 {
		t.Fatalf("expected skipped > 0 for 10.0.0.0/30, got 0")
	}
	for _, ip := range walked {
		if ip == "10.0.0.1" || ip == "10.0.0.2" {
			t.Fatalf("WalkHostsCounted yielded a bogon: %s", ip)
		}
	}
	got := map[string]bool{}
	for _, ip := range walked {
		got[ip] = true
	}
	if !got["8.8.8.1"] || !got["8.8.8.2"] {
		t.Fatalf("expected 8.8.8.1 and 8.8.8.2 to be walked, got %v", walked)
	}
}

func TestParseTXTTargetsAcceptsCIDRsSingleIPsAndComments(t *testing.T) {
	entries, totalAddresses, totalScanHosts, warnings, err := ParseTXTTargets(strings.Join([]string{
		"# imported targets",
		"8.8.8.0/30",
		"8.8.8.10",
		"2001:db8::1",
		"not-a-target",
		"8.8.8.10 # duplicate single IP",
	}, "\n"))
	if err != nil {
		t.Fatalf("ParseTXTTargets returned error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 parsed entries, got %d", len(entries))
	}
	if entries[0].Prefix != "8.8.8.0/30" {
		t.Fatalf("unexpected first prefix: %s", entries[0].Prefix)
	}
	if entries[1].Prefix != "8.8.8.10/32" {
		t.Fatalf("unexpected second prefix: %s", entries[1].Prefix)
	}
	if totalAddresses != 5 {
		t.Fatalf("expected 5 total addresses, got %d", totalAddresses)
	}
	if totalScanHosts != 3 {
		t.Fatalf("expected 3 total scan hosts, got %d", totalScanHosts)
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(warnings))
	}
}

func TestParseTXTTargetsFailsWhenNoValidIPv4TargetsExist(t *testing.T) {
	_, _, _, warnings, err := ParseTXTTargets("not-a-target\n2001:db8::/32\n")
	if err == nil {
		t.Fatal("expected an error when no valid targets exist")
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(warnings))
	}
}

func TestMergeDropsFullyBogonPrefixes(t *testing.T) {
	records := []SourcePrefix{
		{ASN: "1", Prefix: "10.0.0.0/24"},    // fully bogon → dropped
		{ASN: "2", Prefix: "192.168.1.0/24"}, // fully bogon → dropped
		{ASN: "3", Prefix: "8.8.8.0/24"},     // public → kept
	}
	entries, _, _, dropped, err := Merge(records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(entries) != 1 || entries[0].Prefix != "8.8.8.0/24" {
		t.Fatalf("expected only 8.8.8.0/24 to remain, got %+v", entries)
	}
	if len(dropped) != 2 {
		t.Fatalf("expected 2 dropped bogon prefixes, got %d: %v", len(dropped), dropped)
	}
}
