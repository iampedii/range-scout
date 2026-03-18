package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"range-scout/internal/export"
	"range-scout/internal/model"
	"range-scout/internal/scanner"
)

func TestFilterScanResultRecursiveOnly(t *testing.T) {
	result := model.ScanResult{
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, RecursionAvailable: true},
			{IP: "198.51.100.11", DNSReachable: true, RecursionAvailable: false},
		},
		ReachableCount: 2,
		RecursiveCount: 1,
	}

	filtered := filterScanResult(result, scanSaveRecursiveOnly)
	if len(filtered.Resolvers) != 1 {
		t.Fatalf("expected 1 resolver after filtering, got %d", len(filtered.Resolvers))
	}
	if filtered.Resolvers[0].IP != "198.51.100.10" {
		t.Fatalf("unexpected resolver kept: %s", filtered.Resolvers[0].IP)
	}
	if filtered.ReachableCount != 1 || filtered.RecursiveCount != 1 {
		t.Fatalf("unexpected counts: reachable=%d recursive=%d", filtered.ReachableCount, filtered.RecursiveCount)
	}
}

func TestFilterScanResultAllDNSHosts(t *testing.T) {
	result := model.ScanResult{
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, RecursionAvailable: true},
			{IP: "198.51.100.11", DNSReachable: true, RecursionAvailable: false},
		},
	}

	filtered := filterScanResult(result, scanSaveAllDNSHosts)
	if len(filtered.Resolvers) != 2 {
		t.Fatalf("expected 2 resolvers after filtering, got %d", len(filtered.Resolvers))
	}
	if filtered.ReachableCount != 2 || filtered.RecursiveCount != 1 {
		t.Fatalf("unexpected counts: reachable=%d recursive=%d", filtered.ReachableCount, filtered.RecursiveCount)
	}
}

func TestPrefixesFormShowsScanButtonsOnlyAfterFetch(t *testing.T) {
	u := newUI()
	u.mode = screenOperators
	u.rebuildForm()

	if u.hasButton("Scan Setup") {
		t.Fatal("expected no Scan Setup button before fetch")
	}
	if u.hasButton("Start Scan") {
		t.Fatal("expected no Start Scan button before fetch")
	}

	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24"},
		},
	}
	u.rebuildForm()

	if !u.hasButton("Scan Setup") {
		t.Fatal("expected Scan Setup button after fetch")
	}
	if u.hasButton("Start Scan") {
		t.Fatal("expected Start Scan button to stay hidden on the prefixes page")
	}
}

func TestRebuildFormUpdatesPathForSelectedOperator(t *testing.T) {
	u := newUI()
	u.mode = screenOperators
	u.selected = 1
	u.updateDefaultPaths()
	u.rebuildForm()

	field, ok := u.form.GetFormItem(1).(*tview.InputField)
	if !ok {
		t.Fatalf("expected path form item to be an input field, got %T", u.form.GetFormItem(1))
	}

	pattern := regexp.MustCompile(`^exports/irancell_prefixes_\d{8}_\d{6}_\d{6}\.csv$`)
	if got := field.GetText(); !pattern.MatchString(got) {
		t.Fatalf("unexpected path field text: %q", got)
	}
}

func TestDefaultOutputPathIncludesTimestamp(t *testing.T) {
	ts := time.Date(2026, time.March, 18, 12, 34, 56, 789000000, time.UTC)
	got := defaultOutputPathAt("mci", "prefixes", export.FormatCSV, ts)
	want := "exports/mci_prefixes_20260318_123456_789000.csv"
	if got != want {
		t.Fatalf("unexpected timestamped output path: got %q want %q", got, want)
	}
}

func TestSelectedScanEntriesUsesMultipleChosenRanges(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
			{Prefix: "198.51.101.0/24", ScanHosts: 254},
		},
	}

	u.ensureScanRangeSelection(operator.Key)
	selected := u.selectedScanPrefixes(operator.Key)
	if len(selected) != 1 || selected[0] != "198.51.100.0/24" {
		t.Fatalf("unexpected default scan selection: %#v", selected)
	}

	u.scanRanges[operator.Key] = []string{"198.51.100.0/24", "198.51.101.0/24"}
	entries, err := u.selectedScanEntries(operator.Key)
	if err != nil {
		t.Fatalf("selectedScanEntries returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected exactly two selected entries, got %d", len(entries))
	}
	if entries[0].Prefix != "198.51.100.0/24" || entries[1].Prefix != "198.51.101.0/24" {
		t.Fatalf("unexpected selected prefixes: %#v", entries)
	}
	if got := u.selectedScanSummary(operator.Key); got != "2 ranges selected" {
		t.Fatalf("unexpected scan summary: %s", got)
	}
}

func TestScanConfigNormalizesProbeURLs(t *testing.T) {
	u := newUI()
	u.scanPort = "5353"
	u.scanProtocol = string(scanner.ProtocolBoth)
	u.scanProbeURL1 = "https://github.com/login"
	u.scanProbeURL2 = "example.com/docs"

	cfg, err := u.scanConfig()
	if err != nil {
		t.Fatalf("scanConfig returned error: %v", err)
	}
	if len(cfg.StabilityDomains) != 2 {
		t.Fatalf("expected 2 stability domains, got %d", len(cfg.StabilityDomains))
	}
	if cfg.StabilityDomains[0] != "github.com." {
		t.Fatalf("unexpected first stability domain: %s", cfg.StabilityDomains[0])
	}
	if cfg.StabilityDomains[1] != "example.com." {
		t.Fatalf("unexpected second stability domain: %s", cfg.StabilityDomains[1])
	}
	if cfg.Port != 5353 {
		t.Fatalf("unexpected scan port: %d", cfg.Port)
	}
	if cfg.Protocol != scanner.ProtocolBoth {
		t.Fatalf("unexpected scan protocol: %s", cfg.Protocol)
	}
}

func TestNewUIDefaultsScannerPortAndProtocol(t *testing.T) {
	u := newUI()

	if u.scanPort != "53" {
		t.Fatalf("unexpected default scan port: %q", u.scanPort)
	}
	if u.scanProtocol != string(scanner.ProtocolUDP) {
		t.Fatalf("unexpected default scan protocol: %q", u.scanProtocol)
	}
}

func TestHandleKeysDoesNotTriggerHotkeysWhileEditingProbeField(t *testing.T) {
	u := newUI()
	u.mode = screenScanner
	u.rebuildForm()

	probeFieldIndex := 7
	u.form.SetFocus(probeFieldIndex)
	u.app.SetFocus(u.form)

	if !u.focusIsEditable() {
		t.Fatal("expected probe field focus to be treated as editable")
	}

	event := tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone)
	if got := u.handleKeys(event); got != event {
		t.Fatal("expected key event to be passed through while editing")
	}
	if u.mode != screenScanner {
		t.Fatalf("expected mode to stay on scanner while editing, got %q", u.mode)
	}
}

func TestScannerFormHidesPrefixActionsAndShowsBack(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}

	u.mode = screenScanner
	u.rebuildForm()

	if u.hasButton("Fetch") {
		t.Fatal("expected scanner form to hide Fetch button")
	}
	if u.hasButton("Save Pfx") {
		t.Fatal("expected scanner form to hide Save Pfx button")
	}
	if !u.hasButton("Back") {
		t.Fatal("expected scanner form to show Back button")
	}
	if !u.hasButton("Start Scan") {
		t.Fatal("expected scanner form to show Start Scan button")
	}
}

func TestScannerDetailsShowGuideBeforeFirstScan(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256, ScanHosts: 254},
		},
	}

	u.mode = screenScanner
	u.ensureScanRangeSelection(operator.Key)
	u.renderDetails()

	text := u.details.GetText(true)
	if !strings.Contains(text, "Commands - DNS Scan") {
		t.Fatalf("expected pre-scan guide in details pane, got: %s", text)
	}
	if !strings.Contains(text, "Port: DNS port to test. Default is 53.") {
		t.Fatalf("expected port guide in details pane, got: %s", text)
	}
}

func TestScannerDetailsHideGuideAfterCachedScan(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256, ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:      operator,
		FinishedAt:    time.Now(),
		Protocol:      string(scanner.ProtocolUDP),
		Port:          53,
		Workers:       256,
		TimeoutMillis: 1200,
	}

	u.mode = screenScanner
	u.ensureScanRangeSelection(operator.Key)
	u.renderDetails()

	text := u.details.GetText(true)
	if strings.Contains(text, "Commands - DNS Scan") {
		t.Fatalf("expected pre-scan guide to be hidden after a cached scan, got: %s", text)
	}
}

func TestRenderStatusShowsLiveScanMetrics(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.mode = screenScanner
	u.lastStatusLine = "Scanning MCI..."
	u.activeScanOperator = operator.Key
	u.scanCancel = func() {}
	u.liveProgress = scanProgress{
		Scanned:   25,
		Total:     100,
		Reachable: 6,
		Recursive: 3,
	}
	u.liveResolvers = []model.Resolver{
		{IP: "198.51.100.10", Stable: true},
		{IP: "198.51.100.11", Stable: false},
	}

	u.renderStatus()

	text := u.status.GetText(true)
	if !strings.Contains(text, "Scanning MCI... (dns mode)") {
		t.Fatalf("expected status headline, got: %s", text)
	}
	if !strings.Contains(text, "scanned 25/100") {
		t.Fatalf("expected live scan counters in status, got: %s", text)
	}
	if !strings.Contains(text, "reachable 6") || !strings.Contains(text, "recursive 3") || !strings.Contains(text, "stable 1") {
		t.Fatalf("expected live metrics in status, got: %s", text)
	}
}

func TestScannerDetailsHideCachedResultsWhileNewScanIsRunning(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256, ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:      operator,
		FinishedAt:    time.Now(),
		Resolvers:     []model.Resolver{{IP: "198.51.100.10", Prefix: "198.51.100.0/24"}},
		Protocol:      string(scanner.ProtocolUDP),
		Port:          53,
		Workers:       256,
		TimeoutMillis: 1200,
	}
	u.mode = screenScanner
	u.activeScanOperator = operator.Key
	u.scanCancel = func() {}
	u.liveProgress = scanProgress{Total: 254}
	u.liveResolvers = nil
	u.ensureScanRangeSelection(operator.Key)

	u.renderDetails()

	text := u.details.GetText(true)
	if strings.Contains(text, "Last finished:") {
		t.Fatalf("expected cached result header to be hidden during active scan, got: %s", text)
	}
	if strings.Contains(text, "198.51.100.10") {
		t.Fatalf("expected old resolver rows to be hidden during active scan, got: %s", text)
	}
	if !strings.Contains(text, "Live scan progress is shown in Status.") {
		t.Fatalf("expected active scan note in details, got: %s", text)
	}
}

func TestFilterPrefixEntryIndexes(t *testing.T) {
	entries := []model.PrefixEntry{
		{Prefix: "198.51.100.0/24"},
		{Prefix: "198.51.101.0/24"},
		{Prefix: "203.0.113.0/24"},
	}

	indexes := filterPrefixEntryIndexes(entries, "198.51.10")
	if len(indexes) != 2 {
		t.Fatalf("expected 2 matching indexes, got %d", len(indexes))
	}
	if indexes[0] != 0 || indexes[1] != 1 {
		t.Fatalf("unexpected indexes: %#v", indexes)
	}

	indexes = filterPrefixEntryIndexes(entries, "/24")
	if len(indexes) != 3 {
		t.Fatalf("expected 3 slash-filter matches, got %d", len(indexes))
	}
}

func TestScanRangeLabelShowsHighlight(t *testing.T) {
	entry := model.PrefixEntry{Prefix: "198.51.100.0/24", TotalAddresses: 256}

	if got := scanRangeLabel(entry, false); got != "         256 IPs  198.51.100.0/24" {
		t.Fatalf("unexpected plain label: %q", got)
	}
	if got := scanRangeLabel(entry, true); got != "[black:lightskyblue]         256 IPs  198.51.100.0/24[-:-:-]" {
		t.Fatalf("unexpected highlighted label: %q", got)
	}
}
