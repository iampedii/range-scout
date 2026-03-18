package export

import (
	"os"
	"path/filepath"
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
	if !strings.Contains(text, "operator,ip,transport,dns_reachable,recursion_available,recursion_advertised,stable,response_code,latency_ms,prefix") {
		t.Fatalf("csv header missing transport/stable columns: %s", text)
	}
	if !strings.Contains(text, "TIC,198.51.100.10,TCP,true,true,true,true,NOERROR,21,198.51.100.0/24") {
		t.Fatalf("csv row missing transport/stable value: %s", text)
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
