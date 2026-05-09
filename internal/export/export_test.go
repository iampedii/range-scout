package export

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"range-scout/internal/model"
)

func TestSavePrefixesCSV(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "prefixes.csv")

	result := model.LookupResult{
		Operator: model.Operator{Name: "MCI"},
		Entries: []model.PrefixEntry{
			{Prefix: "1.1.1.0/24", SourceASNs: []string{"AS1", "AS2"}, TotalAddresses: 256, ScanHosts: 254},
		},
		FetchedAt: time.Now(),
	}

	if err := SavePrefixes(path, FormatCSV, result); err != nil {
		t.Fatalf("SavePrefixes returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	text := string(data)
	if !strings.Contains(text, "operator,prefix,source_asns,total_addresses,scan_hosts") {
		t.Fatalf("csv header missing: %s", text)
	}
	if !strings.Contains(text, "MCI,1.1.1.0/24,\"AS1, AS2\",256,254") {
		t.Fatalf("csv row missing: %s", text)
	}
}

func TestSaveResolversTXT(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "resolvers.txt")

	result := model.ScanResult{
		Operator: model.Operator{Name: "Irancell"},
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", Transport: "UDP", DNSReachable: true, RecursionAvailable: true, RecursionAdvertised: true, ResponseCode: "NOERROR", LatencyMillis: 21, Prefix: "198.51.100.0/24"},
			{IP: "198.51.100.11", Transport: "TCP", DNSReachable: true, RecursionAvailable: false, RecursionAdvertised: false, ResponseCode: "REFUSED", LatencyMillis: 33, Prefix: "198.51.100.0/24"},
		},
	}

	if err := SaveResolvers(path, FormatTXT, result); err != nil {
		t.Fatalf("SaveResolvers returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	if got := string(data); got != "198.51.100.10\n198.51.100.11\n" {
		t.Fatalf("unexpected txt output: %q", got)
	}
}

func TestSaveResolversCSVIncludesTransportAndStableColumns(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "resolvers.csv")

	result := model.ScanResult{
		Operator: model.Operator{Name: "TIC"},
		Resolvers: []model.Resolver{
			{
				IP:                  "198.51.100.10",
				Transport:           "TCP",
				DNSReachable:        true,
				RecursionAvailable:  true,
				RecursionAdvertised: true,
				Stable:              true,
				ResponseCode:        "NOERROR",
				LatencyMillis:       21,
				Prefix:              "198.51.100.0/24",
				StormDNSChecked:     true,
				StormDNSPassed:      true,
				StormDNSLatencyMS:   285,
			},
		},
	}

	if err := SaveResolvers(path, FormatCSV, result); err != nil {
		t.Fatalf("SaveResolvers returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	text := string(data)
	if !strings.Contains(text, "operator,ip,transport,dns_reachable,scan_status,scan_error,tunnel_score,tunnel_ns_support,tunnel_txt_support,tunnel_random_sub,tunnel_realism,tunnel_edns0_support,tunnel_edns_max_payload,tunnel_nxdomain,recursion_available,recursion_advertised,stable,response_code,latency_ms,prefix,stormdns_checked,stormdns_passed,stormdns_latency_ms,stormdns_error") {
		t.Fatalf("csv header missing transport/stable/stormdns columns: %s", text)
	}
	if !strings.Contains(text, "TIC,198.51.100.10,TCP,true,,,0,false,false,false,false,false,0,false,true,true,true,NOERROR,21,198.51.100.0/24,true,true,285,") {
		t.Fatalf("csv row missing transport/stable/stormdns value: %s", text)
	}
}

func TestSaveResolversJSONOmitsPrefixes(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "resolvers.json")

	result := model.ScanResult{
		Operator: model.Operator{Name: "TCI"},
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, RecursionAvailable: true, Prefix: "198.51.100.0/24"},
		},
	}

	if err := SaveResolvers(path, FormatJSON, result); err != nil {
		t.Fatalf("SaveResolvers returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	text := string(data)
	if strings.Contains(text, "\"prefixes\"") {
		t.Fatalf("json unexpectedly included prefixes field: %s", text)
	}
	if !strings.Contains(text, "\"resolvers\"") {
		t.Fatalf("json missing resolvers field: %s", text)
	}
}

func TestSaveFailedHostsTXT(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "failed.txt")

	result := FailedHostResult{
		Operator: model.Operator{Name: "MCI"},
		FailedHosts: []FailedHost{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24"},
			{IP: "198.51.100.11", Prefix: "198.51.100.0/24"},
		},
		TotalTargets:   4,
		ScannedTargets: 4,
		FailedCount:    2,
	}

	if err := SaveFailedHosts(path, FormatTXT, result); err != nil {
		t.Fatalf("SaveFailedHosts returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	if got := string(data); got != "198.51.100.10\n198.51.100.11\n" {
		t.Fatalf("unexpected txt output: %q", got)
	}
}

func TestSaveFailedHostsCSV(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "failed.csv")

	result := FailedHostResult{
		Operator: model.Operator{Name: "Irancell"},
		FailedHosts: []FailedHost{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24"},
		},
		TotalTargets:   4,
		ScannedTargets: 4,
		FailedCount:    1,
	}

	if err := SaveFailedHosts(path, FormatCSV, result); err != nil {
		t.Fatalf("SaveFailedHosts returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	text := string(data)
	if !strings.Contains(text, "operator,ip,prefix") {
		t.Fatalf("csv header missing: %s", text)
	}
	if !strings.Contains(text, "Irancell,198.51.100.10,198.51.100.0/24") {
		t.Fatalf("csv row missing: %s", text)
	}
}

func TestWriteStormDNSCacheLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.log")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true,  UpMTUBytes: 64, DownMTUBytes: 120},
		{IP: "8.8.8.8", StormDNSPassed: true,  UpMTUBytes: 60, DownMTUBytes: 110},
		{IP: "9.9.9.9", StormDNSPassed: false, UpMTUBytes: 0,  DownMTUBytes: 0},
	}
	if err := WriteStormDNSCacheLog(path, resolvers, "t.example.com", 53); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (only passed resolvers), got %d:\n%s", len(lines), body)
	}
	want := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z 1\.1\.1\.1:53 t\.example\.com UP=64 DOWN=120$`)
	if !want.MatchString(lines[0]) {
		t.Fatalf("line 0 wrong format:\n  got: %q", lines[0])
	}
}

func TestWriteStormDNSCacheLogRetainsNonDefaultPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.log")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true, UpMTUBytes: 64, DownMTUBytes: 120},
	}
	if err := WriteStormDNSCacheLog(path, resolvers, "t.example.com", 5353); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "1.1.1.1:5353") {
		t.Fatalf("expected ip:5353 in output, got %q", body)
	}
}

func TestWriteStormDNSResolversSimple(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.simple")
	resolvers := []model.Resolver{
		{IP: "1.1.1.1", StormDNSPassed: true},
		{IP: "8.8.8.8", StormDNSPassed: true},
		{IP: "9.9.9.9", StormDNSPassed: false},
	}
	if err := WriteStormDNSResolversSimple(path, resolvers, 53); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (only passed), got %d:\n%s", len(lines), body)
	}
	if lines[0] != "1.1.1.1" {
		t.Fatalf("port 53 should be omitted, got %q", lines[0])
	}
}

func TestWriteStormDNSResolversSimpleNonDefaultPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client_resolvers.simple")
	resolvers := []model.Resolver{{IP: "8.8.8.8", StormDNSPassed: true}}
	if err := WriteStormDNSResolversSimple(path, resolvers, 5353); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, _ := os.ReadFile(path)
	if strings.TrimSpace(string(body)) != "8.8.8.8:5353" {
		t.Fatalf("expected 8.8.8.8:5353, got %q", body)
	}
}
