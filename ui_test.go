package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"range-scout/internal/dnstt"
	"range-scout/internal/export"
	"range-scout/internal/model"
	"range-scout/internal/scanner"
)

func TestFilterScanResultRecursiveOnly(t *testing.T) {
	result := model.ScanResult{
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 2},
			{IP: "198.51.100.11", DNSReachable: true, TunnelScore: 0},
		},
		ReachableCount: 2,
		RecursiveCount: 1,
		ScoreThreshold: 2,
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
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 2},
			{IP: "198.51.100.11", DNSReachable: true, TunnelScore: 0},
		},
		ScoreThreshold: 2,
	}

	filtered := filterScanResult(result, scanSaveAllDNSHosts)
	if len(filtered.Resolvers) != 2 {
		t.Fatalf("expected 2 resolvers after filtering, got %d", len(filtered.Resolvers))
	}
	if filtered.ReachableCount != 2 || filtered.RecursiveCount != 1 {
		t.Fatalf("unexpected counts: reachable=%d recursive=%d", filtered.ReachableCount, filtered.RecursiveCount)
	}
}

func TestBuildScanFailureExportUsesExportedSuccessSet(t *testing.T) {
	result := model.ScanResult{
		Operator: model.Operator{Name: "MCI"},
		Prefixes: []model.PrefixEntry{
			{Prefix: "198.51.100.10/32", ScanHosts: 1},
			{Prefix: "198.51.100.11/32", ScanHosts: 1},
			{Prefix: "198.51.100.12/32", ScanHosts: 1},
		},
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 2},
			{IP: "198.51.100.11", DNSReachable: true, TunnelScore: 0},
		},
		TotalTargets:   3,
		ScannedTargets: 3,
		HostLimit:      10,
		ScoreThreshold: 2,
	}

	successes := filterScanResult(result, scanSaveRecursiveOnly)
	failed, ready, err := buildScanFailureExport(result, successes.Resolvers)
	if err != nil {
		t.Fatalf("buildScanFailureExport returned error: %v", err)
	}
	if !ready {
		t.Fatal("expected failure export to be ready for a completed scan")
	}
	if failed.FailedCount != 2 {
		t.Fatalf("expected 2 failed hosts, got %d", failed.FailedCount)
	}
	if len(failed.FailedHosts) != 2 || failed.FailedHosts[0].IP != "198.51.100.11" || failed.FailedHosts[1].IP != "198.51.100.12" {
		t.Fatalf("unexpected failure hosts: %+v", failed.FailedHosts)
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
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24"},
		},
	}
	u.updateDefaultPaths()
	u.rebuildForm()

	field, ok := u.form.GetFormItem(2).(*tview.InputField)
	if !ok {
		t.Fatalf("expected path form item to be an input field, got %T", u.form.GetFormItem(2))
	}

	pattern := regexp.MustCompile(`^exports/cidr-irancell_\d{8}_\d{6}_\d{6}\.txt$`)
	if got := field.GetText(); !pattern.MatchString(got) {
		t.Fatalf("unexpected path field text: %q", got)
	}
}

func TestDefaultOutputPathIncludesTimestamp(t *testing.T) {
	ts := time.Date(2026, time.March, 18, 12, 34, 56, 789000000, time.UTC)
	got := defaultOutputPathAt("mci", "cidr", export.FormatCSV, ts)
	want := "exports/cidr-mci_20260318_123456_789000.csv"
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
	if len(selected) != 2 || selected[0] != "198.51.100.0/24" || selected[1] != "198.51.101.0/24" {
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
	if got := u.selectedScanSummary(operator.Key); got != "2 targets selected" {
		t.Fatalf("unexpected scan summary: %s", got)
	}
}

func TestSelectAllAndClearScanRangeSelection(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
			{Prefix: "198.51.101.0/24", ScanHosts: 254},
			{Prefix: "198.51.102.0/24", ScanHosts: 254},
		},
	}

	u.selectAllScanRanges(operator.Key)
	selected := u.selectedScanPrefixes(operator.Key)
	if len(selected) != 3 {
		t.Fatalf("expected all targets to be selected, got %#v", selected)
	}

	u.clearScanRangeSelection(operator.Key)
	selected = u.selectedScanPrefixes(operator.Key)
	if len(selected) != 0 {
		t.Fatalf("expected empty target selection after clear, got %#v", selected)
	}
	if got := u.selectedScanSummary(operator.Key); got != "No targets selected" {
		t.Fatalf("unexpected empty selection summary: %s", got)
	}
}

func TestSelectedScanEntriesRequireAtLeastOneTarget(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.clearScanRangeSelection(operator.Key)

	_, err := u.selectedScanEntries(operator.Key)
	if err == nil || err.Error() != "select at least one target before starting a scan" {
		t.Fatalf("unexpected error for empty target selection: %v", err)
	}
}

func TestRenderDetailsShowsSelectedTargetPreview(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256},
			{Prefix: "198.51.101.10/32", TotalAddresses: 1},
			{Prefix: "198.51.102.0/24", TotalAddresses: 256},
			{Prefix: "198.51.103.0/24", TotalAddresses: 256},
		},
	}
	u.mode = screenScanner
	u.scanRanges[operator.Key] = []string{"198.51.100.0/24", "198.51.101.10/32", "198.51.102.0/24", "198.51.103.0/24"}

	u.renderDetails()

	text := u.details.GetText(true)
	if !strings.Contains(text, "Selected targets: 4 targets selected") {
		t.Fatalf("expected selected targets summary, got: %s", text)
	}
	if !strings.Contains(text, "Target preview: 198.51.100.0/24, 198.51.101.10/32, 198.51.102.0/24, +1 more") {
		t.Fatalf("expected compact target preview, got: %s", text)
	}
	if !strings.Contains(text, "Use Pick Targets for the full list.") {
		t.Fatalf("expected Pick Targets hint, got: %s", text)
	}
}

func TestScanConfigNormalizesProbeURLs(t *testing.T) {
	u := newUI()
	u.scanPort = "5353"
	u.dnsttDomain = "dns.google"
	u.dnsttQuerySize = "1400"
	u.dnsttScoreThreshold = "3"
	entries := []model.PrefixEntry{
		{Prefix: "198.51.100.0/24", ScanHosts: 254},
		{Prefix: "198.51.101.10/32", ScanHosts: 1},
	}

	cfg, err := u.scanConfig(entries)
	if err != nil {
		t.Fatalf("scanConfig returned error: %v", err)
	}
	if cfg.Domain != "dns.google." {
		t.Fatalf("unexpected tunnel domain: %s", cfg.Domain)
	}
	if cfg.Port != 5353 {
		t.Fatalf("unexpected scan port: %d", cfg.Port)
	}
	if cfg.Protocol != scanner.ProtocolUDP {
		t.Fatalf("unexpected scan protocol: %s", cfg.Protocol)
	}
	if cfg.QuerySize != 1400 {
		t.Fatalf("unexpected query size: %d", cfg.QuerySize)
	}
	if cfg.ScoreThreshold != 3 {
		t.Fatalf("unexpected score threshold: %d", cfg.ScoreThreshold)
	}
	if cfg.HostLimit != 255 {
		t.Fatalf("expected host limit to match selected scan hosts, got %d", cfg.HostLimit)
	}
}

func TestNewUIDefaultsScannerPortAndProtocol(t *testing.T) {
	u := newUI()

	if u.scanPort != "53" {
		t.Fatalf("unexpected default scan port: %q", u.scanPort)
	}
	if u.scanTimeoutMS != "15000" {
		t.Fatalf("unexpected default scan timeout: %q", u.scanTimeoutMS)
	}
	if u.scanProtocol != string(scanner.ProtocolUDP) {
		t.Fatalf("unexpected default scan protocol: %q", u.scanProtocol)
	}
	if u.scanRecursionURL != "google.com" {
		t.Fatalf("unexpected default recursion url: %q", u.scanRecursionURL)
	}
	if u.dnsttTimeoutMS != "15000" {
		t.Fatalf("unexpected default DNSTT timeout: %q", u.dnsttTimeoutMS)
	}
	if u.dnsttE2EURL != dnstt.DefaultE2ETestURL {
		t.Fatalf("unexpected default DNSTT e2e url: %q", u.dnsttE2EURL)
	}
	if u.dnsttNearbyIPs != noOption {
		t.Fatalf("unexpected default DNSTT nearby setting: %q", u.dnsttNearbyIPs)
	}
}

func TestUILayoutModeForSizeSwitchesToCompactOnSmallScreens(t *testing.T) {
	u := newUI()

	if got := u.layoutModeForSize(160, 40); got != layoutCompact {
		t.Fatalf("expected compact layout for small screen, got %s", got)
	}
	if got := u.layoutModeForSize(190, 45); got != layoutWide {
		t.Fatalf("expected wide layout for larger screen, got %s", got)
	}
}

func TestApplyLayoutCompactPrioritizesCommandsPane(t *testing.T) {
	u := newUI()

	u.applyLayout(layoutCompact)

	if u.layout != layoutCompact {
		t.Fatalf("expected compact layout to be active, got %s", u.layout)
	}
	if got := u.body.GetItemCount(); got != 2 {
		t.Fatalf("expected compact body to have 2 columns, got %d", got)
	}
	if got := u.contentPanel.GetItemCount(); got != 2 {
		t.Fatalf("expected compact content panel to stack commands and footer, got %d items", got)
	}
	if got := u.footerPanel.GetItemCount(); got != 2 {
		t.Fatalf("expected compact footer to show details and activity, got %d items", got)
	}
	if got := u.formSidebarWrapWidth(); got <= formSidebarWrapWidth {
		t.Fatalf("expected compact sidebar wrap width to expand beyond wide width, got %d", got)
	}
}

func TestApplyLayoutWideRestoresThreePaneShell(t *testing.T) {
	u := newUI()
	u.applyLayout(layoutCompact)

	u.applyLayout(layoutWide)

	if u.layout != layoutWide {
		t.Fatalf("expected wide layout to be active, got %s", u.layout)
	}
	if got := u.body.GetItemCount(); got != 3 {
		t.Fatalf("expected wide body to restore 3 panes, got %d", got)
	}
	if got := u.rightColumn.GetItemCount(); got != 2 {
		t.Fatalf("expected wide right column to contain commands and activity, got %d items", got)
	}
	if got := u.formSidebarWrapWidth(); got != formSidebarWrapWidth {
		t.Fatalf("expected wide sidebar wrap width %d, got %d", formSidebarWrapWidth, got)
	}
}

func TestApplyLayoutMetricsRebuildsFormWhenSwitchingToCompact(t *testing.T) {
	u := newUI()
	u.mode = screenOperators
	u.rebuildForm()

	wideCount := u.form.GetFormItemCount()
	u.applyLayoutMetrics(u.calculateLayoutMetrics(160, 40))
	compactCount := u.form.GetFormItemCount()

	if compactCount >= wideCount {
		t.Fatalf("expected compact layout to rebuild the form with fewer wrapped rows, got wide=%d compact=%d", wideCount, compactCount)
	}
	if u.layout != layoutCompact {
		t.Fatalf("expected compact layout after metrics apply, got %s", u.layout)
	}
}

func TestApplyLayoutMetricsUpdatesCompactWidthsOnResize(t *testing.T) {
	u := newUI()

	u.applyLayoutMetrics(u.calculateLayoutMetrics(160, 40))
	firstWidth := u.layoutState.formSidebarWidth
	u.applyLayoutMetrics(u.calculateLayoutMetrics(120, 40))
	secondWidth := u.layoutState.formSidebarWidth

	if secondWidth >= firstWidth {
		t.Fatalf("expected compact form width to shrink on narrower resize, got first=%d second=%d", firstWidth, secondWidth)
	}
}

func TestDNSTTConfigUsesConfiguredE2EURL(t *testing.T) {
	u := newUI()
	u.dnsttDomain = "d.example.com"
	u.dnsttPubkey = "deadbeef"
	u.dnsttE2EURL = "https://example.com/generate_204"
	u.dnsttNearbyIPs = yesOption

	cfg, err := u.dnsttConfig(53)
	if err != nil {
		t.Fatalf("dnsttConfig returned error: %v", err)
	}
	if cfg.E2EURL != "https://example.com/generate_204" {
		t.Fatalf("unexpected e2e url: %q", cfg.E2EURL)
	}
	if !cfg.TestNearbyIPs {
		t.Fatal("expected nearby IP testing to be enabled")
	}
}

func TestDNSTTFormRemovesStageRows(t *testing.T) {
	u := newUI()
	operator := u.currentTargetOperator()
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 1,
		FinishedAt:     time.Now(),
	}
	u.mode = screenDNSTT

	u.rebuildForm()

	var texts []string
	for i := 0; i < u.form.GetFormItemCount(); i++ {
		field, ok := u.form.GetFormItem(i).(*tview.InputField)
		if !ok {
			continue
		}
		texts = append(texts, field.GetText())
	}

	joined := strings.Join(texts, "\n")
	if hasFormItemLabel(u, "DNSTT Tunnel") || hasFormItemLabel(u, "DNSTT E2E") {
		t.Fatalf("expected DNSTT form to remove tunnel/e2e section rows, got: %s", joined)
	}
	if hasFormItemLabel(u, "Tunnel Stage") || hasFormItemLabel(u, "E2E Stage") {
		t.Fatalf("expected DNSTT form to remove stage rows, got: %s", joined)
	}
	if strings.Contains(joined, "Save current stage results") {
		t.Fatalf("expected DNSTT form headers to omit description text, got: %s", joined)
	}
}

func TestDNSTTFormPlacesPubkeyUnderDomainInCompactLayout(t *testing.T) {
	u := newUI()
	operator := u.currentTargetOperator()
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 1,
		FinishedAt:     time.Now(),
	}
	u.mode = screenDNSTT
	u.applyLayout(layoutCompact)

	u.rebuildForm()

	domainIndex := findFormItemIndexByLabel(u, "DNSTT Domain")
	pubkeyIndex := findFormItemIndexByLabel(u, "DNSTT Pubkey")
	timeoutIndex := findFormItemIndexByLabel(u, "DNSTT Timeout")
	if domainIndex == -1 || pubkeyIndex == -1 || timeoutIndex == -1 {
		t.Fatalf("expected domain, pubkey, and timeout fields in compact layout")
	}
	if pubkeyIndex != domainIndex+1 {
		t.Fatalf("expected pubkey directly after domain, got domain=%d pubkey=%d", domainIndex, pubkeyIndex)
	}
	if timeoutIndex != pubkeyIndex+1 {
		t.Fatalf("expected timeout after pubkey, got pubkey=%d timeout=%d", pubkeyIndex, timeoutIndex)
	}
}

func TestEffectiveScanSaveScopeStaysScanScopedOnScannerScreenAfterDNSTT(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.scanSaveScope = scanSaveAllDNSHosts
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    2,
		DNSTTFinishedAt: time.Now(),
	}
	u.mode = screenScanner

	if got := u.effectiveScanSaveScope(operator.Key); got != scanSaveAllDNSHosts {
		t.Fatalf("unexpected scanner save scope: %s", got)
	}
}

func TestEffectiveScanSaveScopeUsesDNSTTPassedOnDNSTTScreen(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.scanSaveScope = scanSaveAllDNSHosts
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    2,
		DNSTTFinishedAt: time.Now(),
	}
	u.mode = screenDNSTT

	if got := u.effectiveScanSaveScope(operator.Key); got != scanSaveDNSTTPassed {
		t.Fatalf("unexpected effective save scope: %s", got)
	}
}

func TestUpdateDefaultPathsKeepsScanExportPrefixOnScannerScreenAfterDNSTT(t *testing.T) {
	u := newUI()
	u.selected = 0
	operator := u.selectedOperator()
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    1,
		DNSTTFinishedAt: time.Now(),
	}
	u.mode = screenScanner

	u.updateDefaultPaths()

	if !strings.Contains(u.scanPath, "exports/dns-scan-success-"+operator.Key+"_") {
		t.Fatalf("expected scanner export path, got %q", u.scanPath)
	}
}

func TestUpdateDefaultPathsUsesDNSTTExportPrefixOnDNSTTScreen(t *testing.T) {
	u := newUI()
	u.selected = 0
	operator := u.selectedOperator()
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    1,
		DNSTTFinishedAt: time.Now(),
	}
	u.mode = screenDNSTT

	u.updateDefaultPaths()

	if !strings.Contains(u.scanPath, "exports/dnstt-scan-success-"+operator.Key+"_") {
		t.Fatalf("expected dnstt success export path, got %q", u.scanPath)
	}
}

func TestFilterScanResultDNSTTPassedUsesE2EWhenEnabled(t *testing.T) {
	result := model.ScanResult{
		DNSTTE2ERequested: true,
		DNSTTE2EEnabled:   true,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSTTE2EOK: true, DNSTTTunnelOK: true},
			{IP: "198.51.100.11", DNSTTE2EOK: false, DNSTTTunnelOK: true},
		},
	}

	filtered := filterScanResult(result, scanSaveDNSTTPassed)
	if len(filtered.Resolvers) != 1 {
		t.Fatalf("expected exactly one DNSTT-passed resolver, got %d", len(filtered.Resolvers))
	}
	if filtered.Resolvers[0].IP != "198.51.100.10" {
		t.Fatalf("unexpected resolver kept: %s", filtered.Resolvers[0].IP)
	}
}

func TestFilterScanResultDNSTTPassedUsesTunnelWhenE2EDisabled(t *testing.T) {
	result := model.ScanResult{
		DNSTTE2EEnabled: false,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSTTTunnelOK: true},
			{IP: "198.51.100.11", DNSTTTunnelOK: false},
		},
	}

	filtered := filterScanResult(result, scanSaveDNSTTPassed)
	if len(filtered.Resolvers) != 1 {
		t.Fatalf("expected exactly one tunnel-passed resolver, got %d", len(filtered.Resolvers))
	}
	if filtered.Resolvers[0].IP != "198.51.100.10" {
		t.Fatalf("unexpected resolver kept: %s", filtered.Resolvers[0].IP)
	}
}

func TestFilterScanResultExcludesNearbyResolversFromScanExports(t *testing.T) {
	result := model.ScanResult{
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", TunnelScore: 6},
			{IP: "198.51.100.11", DNSTTNearby: true},
		},
	}

	filtered := filterScanResult(result, scanSaveAllDNSHosts)
	if len(filtered.Resolvers) != 1 {
		t.Fatalf("expected nearby DNSTT resolvers to stay out of scan exports, got %d resolvers", len(filtered.Resolvers))
	}
	if filtered.Resolvers[0].IP != "198.51.100.10" {
		t.Fatalf("unexpected resolver kept in scan export: %s", filtered.Resolvers[0].IP)
	}
}

func TestFilterScanResultDNSTTPassedRequiresE2EWhenRequestedButSkipped(t *testing.T) {
	result := model.ScanResult{
		DNSTTE2ERequested: true,
		DNSTTE2EEnabled:   false,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSTTTunnelOK: true, DNSTTE2EOK: false},
			{IP: "198.51.100.11", DNSTTTunnelOK: false, DNSTTE2EOK: false},
		},
	}

	filtered := filterScanResult(result, scanSaveDNSTTPassed)
	if len(filtered.Resolvers) != 0 {
		t.Fatalf("expected no DNSTT-passed resolvers when e2e was requested but skipped, got %d", len(filtered.Resolvers))
	}
}

func TestBuildDNSTTFailureExportUsesCheckedFailures(t *testing.T) {
	result := model.ScanResult{
		Operator:          model.Operator{Name: "MCI"},
		ScoreThreshold:    2,
		DNSTTCandidates:   4,
		DNSTTChecked:      2,
		DNSTTE2ERequested: true,
		DNSTTE2EEnabled:   true,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24", TunnelScore: 6, DNSTTChecked: true, DNSTTE2EOK: true, DNSTTTunnelOK: true},
			{IP: "198.51.100.11", Prefix: "198.51.100.0/24", TunnelScore: 6, DNSTTChecked: true, DNSTTE2EOK: false, DNSTTTunnelOK: true},
			{IP: "198.51.100.12", Prefix: "198.51.100.0/24", TunnelScore: 6, DNSTTChecked: false, DNSTTE2EOK: false, DNSTTTunnelOK: false},
		},
	}

	failed, ready := buildDNSTTFailureExport(result)
	if !ready {
		t.Fatal("expected DNSTT failure export to be ready")
	}
	if failed.TotalTargets != 4 {
		t.Fatalf("expected 4 DNSTT targets, got %d", failed.TotalTargets)
	}
	if failed.ScannedTargets != 2 {
		t.Fatalf("expected 2 checked targets, got %d", failed.ScannedTargets)
	}
	if failed.FailedCount != 1 {
		t.Fatalf("expected 1 DNSTT failure, got %d", failed.FailedCount)
	}
	if len(failed.FailedHosts) != 1 || failed.FailedHosts[0].IP != "198.51.100.11" {
		t.Fatalf("unexpected DNSTT failures: %+v", failed.FailedHosts)
	}
}

func TestHandleKeysDoesNotTriggerHotkeysWhileEditingScanField(t *testing.T) {
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

	probeFieldIndex := findFormItemIndexByLabel(u, "DNSTT Domain")
	if probeFieldIndex == -1 {
		t.Fatal("expected DNSTT Domain field to be present")
	}
	u.form.SetFocus(probeFieldIndex)
	u.app.SetFocus(u.form)

	if !u.focusIsEditable() {
		t.Fatal("expected scan field focus to be treated as editable")
	}

	event := tcell.NewEventKey(tcell.KeyRune, 'p', tcell.ModNone)
	if got := u.handleKeys(event); got != event {
		t.Fatal("expected key event to be passed through while editing")
	}
	if u.mode != screenScanner {
		t.Fatalf("expected mode to stay on scanner while editing, got %q", u.mode)
	}
}

func TestHandleKeysPastesClipboardIntoFocusedInputField(t *testing.T) {
	u := newUI()

	field := u.newInput("Test", "", func(string) {})
	u.form.Clear(true)
	u.form.AddFormItem(field)
	u.form.SetFocus(0)
	u.app.SetFocus(u.form)

	originalReader := clipboardReader
	clipboardReader = func() (string, error) {
		return "198.51.100.10", nil
	}
	defer func() {
		clipboardReader = originalReader
	}()

	event := tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone)
	if got := u.handleKeys(event); got != nil {
		t.Fatal("expected clipboard paste shortcut to be consumed")
	}
	if got := field.GetText(); got != "198.51.100.10" {
		t.Fatalf("expected clipboard text to be pasted into input field, got %q", got)
	}
}

func TestHandleKeysPastesClipboardIntoFocusedModalTextArea(t *testing.T) {
	u := newUI()
	u.openPasteTargetsModal()

	textArea := findTextArea(u.pages)
	if textArea == nil {
		t.Fatal("expected paste modal text area to be present")
	}
	u.app.SetFocus(textArea)

	if !u.focusIsEditable() {
		t.Fatal("expected modal text area focus to be treated as editable")
	}

	originalReader := clipboardReader
	clipboardReader = func() (string, error) {
		return "198.51.100.0/24\r\n198.51.100.11", nil
	}
	defer func() {
		clipboardReader = originalReader
	}()

	event := tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone)
	if got := u.handleKeys(event); got != nil {
		t.Fatal("expected clipboard paste shortcut to be consumed in modal text area")
	}
	if got := textArea.GetText(); got != "198.51.100.0/24\n198.51.100.11" {
		t.Fatalf("expected normalized clipboard text in modal text area, got %q", got)
	}
}

func TestConfiguredInputFieldUsesSystemClipboardForCtrlV(t *testing.T) {
	originalReader := clipboardReader
	clipboardReader = func() (string, error) {
		return "203.0.113.9", nil
	}
	defer func() {
		clipboardReader = originalReader
	}()

	field := configureInputFieldClipboard(tview.NewInputField())
	handler := field.InputHandler()
	handler(tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone), func(tview.Primitive) {})

	if got := field.GetText(); got != "203.0.113.9" {
		t.Fatalf("expected configured input field to paste from system clipboard, got %q", got)
	}
}

func TestNewUIDoesNotSelectOperatorByDefaultAndUsesGenericPaths(t *testing.T) {
	u := newUI()

	if u.hasSelectedOperator() {
		t.Fatal("expected no operator to be selected by default")
	}
	if got := u.operatorList.GetCurrentItem(); got != 0 {
		t.Fatalf("expected placeholder operator row to be selected, got %d", got)
	}
	if !strings.Contains(u.prefixPath, "exports/cidr-custom_") {
		t.Fatalf("expected generic target path before operator selection, got %q", u.prefixPath)
	}
	if !strings.Contains(u.scanPath, "exports/dns-scan-success-custom_") {
		t.Fatalf("expected generic scan path before operator selection, got %q", u.scanPath)
	}
}

func TestNewUIShowsSaveConfigButton(t *testing.T) {
	u := newUI()

	if !u.hasButton("Save Config") {
		t.Fatal("expected Save Config button to be present")
	}
}

func TestRenderHeaderShowsVersionLabel(t *testing.T) {
	u := newUI()
	u.renderHeader()

	text := u.header.GetText(true)
	if !strings.Contains(text, uiVersionLabel) {
		t.Fatalf("expected header to include version label, got: %s", text)
	}
}

func TestPreferredScreenForRunUsesConsoleScreenOnWindows(t *testing.T) {
	previousFactory := preferredWindowsScreenFactory
	expectedScreen := tcell.NewSimulationScreen("")
	called := false
	preferredWindowsScreenFactory = func() (tcell.Screen, error) {
		called = true
		return expectedScreen, nil
	}
	defer func() {
		preferredWindowsScreenFactory = previousFactory
	}()

	screen := preferredScreenForRun("windows")
	if !called {
		t.Fatal("expected Windows startup to request a preferred Windows screen")
	}
	if screen != expectedScreen {
		t.Fatal("expected Windows startup to use the preferred Windows screen returned by the factory")
	}
}

func TestPreferredScreenForRunFallsBackWhenPreferredWindowsScreenFails(t *testing.T) {
	previousFactory := preferredWindowsScreenFactory
	called := false
	preferredWindowsScreenFactory = func() (tcell.Screen, error) {
		called = true
		return nil, errors.New("console backend unavailable")
	}
	defer func() {
		preferredWindowsScreenFactory = previousFactory
	}()

	screen := preferredScreenForRun("windows")
	if !called {
		t.Fatal("expected Windows startup to try the preferred Windows screen")
	}
	if screen != nil {
		t.Fatal("expected Windows startup to fall back to the default screen when the preferred screen fails")
	}
}

func TestPreferredScreenForRunLeavesNonWindowsUnchanged(t *testing.T) {
	previousFactory := preferredWindowsScreenFactory
	called := false
	preferredWindowsScreenFactory = func() (tcell.Screen, error) {
		called = true
		return tcell.NewSimulationScreen(""), nil
	}
	defer func() {
		preferredWindowsScreenFactory = previousFactory
	}()

	screen := preferredScreenForRun("darwin")
	if screen != nil {
		t.Fatal("expected no preferred screen outside Windows")
	}
	if called {
		t.Fatal("did not expect non-Windows startup to request a preferred Windows screen")
	}
}

func TestApplyScreenFeaturesEnablesMouseAndPaste(t *testing.T) {
	u := newUI()
	screen := &recordingScreen{Screen: tcell.NewSimulationScreen("")}

	u.applyScreenFeatures(screen)

	if !screen.mouseEnabled {
		t.Fatal("expected preferred screen to have mouse enabled")
	}
	if !screen.pasteEnabled {
		t.Fatal("expected preferred screen to have paste enabled")
	}
}

func TestIsClipboardPasteEvent(t *testing.T) {
	tests := []struct {
		name  string
		event *tcell.EventKey
		want  bool
	}{
		{name: "ctrl-v", event: tcell.NewEventKey(tcell.KeyCtrlV, 0, tcell.ModNone), want: true},
		{name: "shift-insert", event: tcell.NewEventKey(tcell.KeyInsert, 0, tcell.ModShift), want: true},
		{name: "ctrl-shift-v-rune", event: tcell.NewEventKey(tcell.KeyRune, 'V', tcell.ModCtrl|tcell.ModShift), want: true},
		{name: "plain-v", event: tcell.NewEventKey(tcell.KeyRune, 'v', tcell.ModNone), want: false},
	}

	for _, tt := range tests {
		if got := isClipboardPasteEvent(tt.event); got != tt.want {
			t.Fatalf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestTargetFormAllowsManualTargetsWithoutOperator(t *testing.T) {
	u := newUI()
	u.mode = screenOperators
	u.rebuildForm()

	if !hasFormItemLabel(u, "Load From") {
		t.Fatal("expected load source dropdown without operator selection")
	}
	if !hasFormItemLabel(u, "Load Note") {
		t.Fatal("expected API availability note without operator selection")
	}
	if !u.hasButton("Paste Targets") {
		t.Fatal("expected paste action to stay available without operator selection")
	}
	if u.hasButton("Load Targets") {
		t.Fatal("expected automatic API fetch to stay unavailable without operator selection")
	}
}

func TestTargetSourceDropdownKeepsAllOptionsAfterSelectingImport(t *testing.T) {
	u := newUI()
	u.mode = screenOperators
	u.setSelectedTargetSource(customOperatorKey, targetSourceImportTXT)

	u.rebuildForm()

	sourceField, ok := u.form.GetFormItem(0).(*tview.DropDown)
	if !ok {
		t.Fatalf("expected source dropdown at form item 0, got %T", u.form.GetFormItem(0))
	}

	if got := sourceField.GetOptionCount(); got != 2 {
		t.Fatalf("expected 2 target-source options, got %d", got)
	}
	index, text := sourceField.GetCurrentOption()
	if index != 0 || text != string(targetSourceImportTXT) {
		t.Fatalf("unexpected selected target-source option: index=%d text=%q", index, text)
	}
}

func TestScannerFormHidesHostLimitField(t *testing.T) {
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

	if hasFormItemLabel(u, "Host Limit") {
		t.Fatal("expected host limit field to be removed from scan form")
	}
}

func TestLoadTargetsWithoutOperatorBlocksAutomaticAPIFetch(t *testing.T) {
	u := newUI()
	u.setSelectedTargetSource(customOperatorKey, targetSourceRIPE)

	u.loadTargets()

	if u.pages.HasPage("paste-targets") {
		t.Fatal("expected no paste modal when automatic API fetch is blocked")
	}
	if !strings.Contains(u.lastStatusLine, "Automatic API Fetch requires selecting an operator") {
		t.Fatalf("unexpected status after blocked API fetch: %q", u.lastStatusLine)
	}
}

func TestOpenScannerWorksWithCustomTargetsWithoutOperator(t *testing.T) {
	u := newUI()
	custom := customTargetsOperator()
	u.lookupCache[custom.Key] = model.LookupResult{
		Operator: custom,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.10/32", TotalAddresses: 1, ScanHosts: 1},
		},
		SourceLabel: string(targetSourcePaste),
	}

	u.openScanner()

	if u.mode != screenScanner {
		t.Fatalf("expected custom targets to open scanner mode, got %q", u.mode)
	}
	if !u.hasButton("Start Scan") {
		t.Fatal("expected scan controls for custom targets without operator selection")
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
	if u.hasButton("Test DNSTT") {
		t.Fatal("expected scanner form to hide Test DNSTT before a scan completes")
	}
	if u.hasButton("Export") || u.hasButton("Export Passed") {
		t.Fatal("expected scanner form to hide export before a scan completes")
	}
	if !u.hasButton("Pick Targets") {
		t.Fatal("expected scanner form to show Pick Targets button")
	}
	if !hasFormItemLabel(u, "DNS Scan") || !hasFormItemLabel(u, "Next Step") {
		t.Fatal("expected scanner form to show separate command sections")
	}
	if !hasFormItemLabel(u, "DNSTT Domain") {
		t.Fatal("expected scanner form to show DNSTT domain before a scan completes")
	}
	if !hasFormItemLabel(u, "DNSTT Setup") {
		t.Fatal("expected scanner form to show DNSTT setup lock message before a scan completes")
	}
}

func TestScannerFormShowsDNSTTAndExportAfterCompletedScan(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 10,
		FinishedAt:     time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 6},
		},
	}

	u.mode = screenScanner
	u.rebuildForm()

	if !u.hasButton("Test DNSTT") {
		t.Fatal("expected scanner form to show Test DNSTT after a scan completes")
	}
	if !u.hasButton("Export") {
		t.Fatal("expected scanner form to show Export after a scan completes")
	}
	if !hasFormItemLabel(u, "DNS Scan") || !hasFormItemLabel(u, "Next Step") {
		t.Fatal("expected scanner form to keep separate command sections after a scan completes")
	}
	if !hasFormItemLabel(u, "DNSTT Domain") {
		t.Fatal("expected scanner form to keep the DNSTT domain field visible")
	}
}

func TestScannerFormKeepsExportAfterCompletedDNSTT(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    1,
		DNSTTFinishedAt: time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 6, DNSTTTunnelOK: true},
		},
	}

	u.mode = screenScanner
	u.rebuildForm()

	if !u.hasButton("Export") {
		t.Fatal("expected scanner form to keep Export after DNSTT completes")
	}
	if !u.hasButton("Test DNSTT") {
		t.Fatal("expected scanner form to keep Test DNSTT after DNSTT completes")
	}
}

func TestScannerScreenKeepsCommandRowCountStableAcrossCompletion(t *testing.T) {
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

	if got := u.commands.GetItemCount(); got != 4 {
		t.Fatalf("expected scanner command layout to reserve 4 items before completion, got %d", got)
	}
	if u.buttonRows[1].GetButtonCount() != 0 {
		t.Fatalf("expected scanner action row to stay empty before completion, got %d button(s)", u.buttonRows[1].GetButtonCount())
	}

	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 10,
		FinishedAt:     time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 6},
		},
	}

	u.rebuildForm()

	if got := u.commands.GetItemCount(); got != 4 {
		t.Fatalf("expected scanner command layout to stay at 4 items after completion, got %d", got)
	}
	if !u.hasButton("Export") || !u.hasButton("Test DNSTT") {
		t.Fatal("expected scanner actions after completion")
	}
}

func TestOpenDNSTTSetupShowsDedicatedScreen(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    1,
		DNSTTFinishedAt: time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 6, DNSTTTunnelOK: true},
		},
	}

	u.openDNSTTSetup()

	if u.mode != screenDNSTT {
		t.Fatalf("expected DNSTT setup screen, got %q", u.mode)
	}
	if !u.hasButton("Start DNSTT") {
		t.Fatal("expected DNSTT screen to show Start DNSTT")
	}
	if !hasFormItemLabel(u, "DNSTT Domain") {
		t.Fatal("expected DNSTT config fields on DNSTT screen")
	}
	if !hasFormItemLabel(u, "DNSTT Pubkey") {
		t.Fatal("expected DNSTT pubkey field on DNSTT screen")
	}
	if !hasFormItemLabel(u, "Test Nearby IPs") {
		t.Fatal("expected DNSTT nearby IP dropdown on DNSTT screen")
	}
	if hasFormItemLabel(u, "DNSTT Tunnel") || hasFormItemLabel(u, "DNSTT E2E") || hasFormItemLabel(u, "Tunnel Stage") || hasFormItemLabel(u, "E2E Stage") {
		t.Fatal("expected DNSTT screen to omit tunnel/e2e section and stage rows")
	}
}

func TestDNSTTNearbyIPsFieldIsDropdownWithNoDefault(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 10,
		FinishedAt:     time.Now(),
	}

	u.mode = screenDNSTT
	u.rebuildForm()

	index := findFormItemIndexByLabel(u, "Test Nearby IPs")
	if index == -1 {
		t.Fatal("expected nearby IP field on DNSTT form")
	}
	dropdown, ok := u.form.GetFormItem(index).(*tview.DropDown)
	if !ok {
		t.Fatalf("expected nearby IP field to be a dropdown, got %T", u.form.GetFormItem(index))
	}
	_, current := dropdown.GetCurrentOption()
	if current != noOption {
		t.Fatalf("expected nearby IP dropdown to default to %q, got %q", noOption, current)
	}
}

func TestDNSTTScreenShowsExportPassedAfterCompletedDNSTT(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		ScannedTargets:  10,
		FinishedAt:      time.Now(),
		DNSTTChecked:    1,
		DNSTTFinishedAt: time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, RecursionAvailable: true, Stable: true, DNSTTTunnelOK: true},
		},
	}

	u.mode = screenDNSTT
	u.rebuildForm()

	if !u.hasButton("Export Passed") {
		t.Fatal("expected DNSTT screen to show Export Passed after DNSTT completes")
	}
	if !u.hasButton("Copy Passed") {
		t.Fatal("expected DNSTT screen to show Copy Passed after DNSTT completes")
	}
	if !u.hasButton("Start DNSTT") {
		t.Fatal("expected DNSTT screen to keep Start DNSTT visible")
	}
}

func TestDNSTTScreenKeepsCommandRowCountStableAcrossCompletion(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator: operator,
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		ScannedTargets: 10,
		FinishedAt:     time.Now(),
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, TunnelScore: 6},
		},
	}

	u.mode = screenDNSTT
	u.rebuildForm()

	if got := u.commands.GetItemCount(); got != 4 {
		t.Fatalf("expected DNSTT command layout to reserve 4 items before completion, got %d", got)
	}
	if u.buttonRows[1].GetButtonCount() != 0 {
		t.Fatalf("expected export action row to stay empty before completion, got %d button(s)", u.buttonRows[1].GetButtonCount())
	}

	result := u.scanCache[operator.Key]
	result.DNSTTChecked = 1
	result.DNSTTFinishedAt = time.Now()
	result.Resolvers[0].DNSTTTunnelOK = true
	u.scanCache[operator.Key] = result

	u.rebuildForm()

	if got := u.commands.GetItemCount(); got != 4 {
		t.Fatalf("expected DNSTT command layout to stay at 4 items after completion, got %d", got)
	}
	if !u.hasButton("Export Passed") || !u.hasButton("Copy Passed") {
		t.Fatal("expected DNSTT export actions after completion")
	}
}

func TestCopyPassedResolversCopiesOnlyDNSTTPassedIPs(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:          operator,
		FinishedAt:        time.Now(),
		DNSTTChecked:      2,
		DNSTTFinishedAt:   time.Now(),
		DNSTTE2ERequested: true,
		DNSTTE2EEnabled:   true,
		ReachableCount:    2,
		RecursiveCount:    2,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", DNSReachable: true, RecursionAvailable: true, Stable: true, DNSTTE2EOK: true},
			{IP: "198.51.100.11", DNSReachable: true, RecursionAvailable: true, Stable: true, DNSTTE2EOK: false},
		},
	}

	var copied string
	previousClipboardWriter := clipboardWriter
	clipboardWriter = func(text string) error {
		copied = text
		return nil
	}
	t.Cleanup(func() {
		clipboardWriter = previousClipboardWriter
	})

	u.copyPassedResolvers()

	if copied != "198.51.100.10" {
		t.Fatalf("unexpected clipboard contents: %q", copied)
	}
	if !strings.Contains(u.lastStatusLine, "Copied 1 passed resolvers") {
		t.Fatalf("unexpected status after copy: %q", u.lastStatusLine)
	}
}

func TestSaveResolversOnDNSTTScreenWritesPassedAndFailureFiles(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	tempDir := t.TempDir()
	successPath := filepath.Join(tempDir, "passed.txt")

	u.mode = screenDNSTT
	u.scanFormat = export.FormatTXT.String()
	u.scanPath = successPath
	u.scanSuggestedPath = filepath.Join(tempDir, "suggested.txt")
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:          operator,
		ScoreThreshold:    2,
		DNSTTChecked:      2,
		DNSTTFinishedAt:   time.Date(2026, time.March, 23, 11, 7, 49, 0, time.UTC),
		DNSTTE2ERequested: true,
		DNSTTE2EEnabled:   true,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24", TunnelScore: 6, DNSTTChecked: true, DNSTTE2EOK: true, DNSTTTunnelOK: true},
			{IP: "198.51.100.11", Prefix: "198.51.100.0/24", TunnelScore: 6, DNSTTChecked: true, DNSTTE2EOK: false, DNSTTTunnelOK: true, DNSTTError: "timeout"},
		},
	}

	u.saveResolvers()

	successData, err := os.ReadFile(successPath)
	if err != nil {
		t.Fatalf("expected passed export file: %v", err)
	}
	if got := string(successData); got != "198.51.100.10\n" {
		t.Fatalf("unexpected passed export contents: %q", got)
	}

	failureMatches, err := filepath.Glob(filepath.Join(tempDir, "dnstt-scan-failures-"+operator.Key+"_*.txt"))
	if err != nil {
		t.Fatalf("failure export glob failed: %v", err)
	}
	if len(failureMatches) != 1 {
		t.Fatalf("expected exactly one failure export file, got %v", failureMatches)
	}

	failureData, err := os.ReadFile(failureMatches[0])
	if err != nil {
		t.Fatalf("expected failure export file: %v", err)
	}
	if got := string(failureData); got != "198.51.100.11\n" {
		t.Fatalf("unexpected failure export contents: %q", got)
	}
	if !strings.Contains(u.lastStatusLine, "failures to") {
		t.Fatalf("expected status to mention failure export, got %q", u.lastStatusLine)
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
	if !strings.Contains(text, "Scan Guide") {
		t.Fatalf("expected pre-scan guide in details pane, got: %s", text)
	}
	if !strings.Contains(text, "DNSTT Domain: Tunnel domain used") {
		t.Fatalf("expected DNSTT domain guide in details pane, got: %s", text)
	}
	if !strings.Contains(text, "Score Threshold: Minimum SlipNet") {
		t.Fatalf("expected score threshold guide in details pane, got: %s", text)
	}
	if strings.Index(text, "Step Progress") > strings.Index(text, "Scan Guide") {
		t.Fatalf("expected scan guide below step progress, got: %s", text)
	}
}

func TestScannerDetailsShowGuideAfterCachedScan(t *testing.T) {
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
	if !strings.Contains(text, "Scan Guide") {
		t.Fatalf("expected scan guide to stay visible after a cached scan, got: %s", text)
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
		Scanned:    25,
		Total:      100,
		Working:    6,
		Compatible: 4,
		Qualified:  3,
	}
	u.liveResolvers = []model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
		{IP: "198.51.100.11", TunnelScore: 1},
	}

	u.renderStatus()

	text := u.status.GetText(true)
	if !strings.Contains(text, "Scanning MCI... (dns mode)") {
		t.Fatalf("expected status headline, got: %s", text)
	}
	if !strings.Contains(text, "scanned 25/100") {
		t.Fatalf("expected live scan counters in status, got: %s", text)
	}
	if !strings.Contains(text, "working 6") || !strings.Contains(text, "compatible 4") || !strings.Contains(text, "qualified 1") {
		t.Fatalf("expected live metrics in status, got: %s", text)
	}
}

func TestRenderActivityShowsSeparatorsAndLatestFirst(t *testing.T) {
	u := newUI()
	u.activityLines = []string{
		"[10:00:00] Ready",
		"[10:00:01] Load started for MCI",
		"[10:00:02] Loaded 3 targets for MCI",
	}

	u.renderActivity()

	text := u.activity.GetText(true)
	if !strings.Contains(text, "Latest first") {
		t.Fatalf("expected activity header, got: %s", text)
	}
	if !strings.Contains(text, "────────────────────────") {
		t.Fatalf("expected separators in activity log, got: %s", text)
	}

	first := strings.Index(text, "[10:00:02] Loaded 3 targets for MCI")
	second := strings.Index(text, "[10:00:01] Load started for MCI")
	third := strings.Index(text, "[10:00:00] Ready")
	if first == -1 || second == -1 || third == -1 {
		t.Fatalf("expected activity entries in log, got: %s", text)
	}
	if !(first < second && second < third) {
		t.Fatalf("expected latest activity first, got: %s", text)
	}
}

func TestRenderActivityShowsOlderEventCountWhenTruncated(t *testing.T) {
	u := newUI()
	u.activityLines = []string{
		"[10:00:00] event 1",
		"[10:00:01] event 2",
		"[10:00:02] event 3",
		"[10:00:03] event 4",
		"[10:00:04] event 5",
		"[10:00:05] event 6",
		"[10:00:06] event 7",
	}

	u.renderActivity()

	text := u.activity.GetText(true)
	if strings.Contains(text, "[10:00:00] event 1") {
		t.Fatalf("expected oldest event to be truncated from visible log, got: %s", text)
	}
	if !strings.Contains(text, "... 1 older event(s)") {
		t.Fatalf("expected older event count in activity log, got: %s", text)
	}
}

func TestScannerDetailsShowWorkflowStages(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator:    operator,
		SourceLabel: string(targetSourcePaste),
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256, ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:       operator,
		FinishedAt:     time.Now(),
		ScannedTargets: 254,
		TotalTargets:   254,
		ReachableCount: 12,
		RecursiveCount: 5,
		Protocol:       string(scanner.ProtocolUDP),
		Port:           53,
		Workers:        256,
		TimeoutMillis:  1200,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24", DNSReachable: true, RecursionAvailable: true, Stable: true},
		},
	}
	u.mode = screenScanner
	u.ensureScanRangeSelection(operator.Key)

	u.renderDetails()

	text := u.details.GetText(true)
	if !strings.Contains(text, "Step Progress") {
		t.Fatalf("expected step progress section, got: %s", text)
	}
	if !strings.Contains(text, "1. Load Targets") || !strings.Contains(text, "2. DNS Scan") || !strings.Contains(text, "3. DNSTT E2E") {
		t.Fatalf("expected workflow stages, got: %s", text)
	}
	if !strings.Contains(text, "DNS Scan\n") || !strings.Contains(text, "Export\n") {
		t.Fatalf("expected scanner detail sections, got: %s", text)
	}
	if !strings.Contains(text, "[################] 100.0%") {
		t.Fatalf("expected completed workflow progress bar, got: %s", text)
	}
}

func TestDNSTTDetailsShowDedicatedSections(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator:    operator,
		SourceLabel: string(targetSourcePaste),
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.0/24", TotalAddresses: 256, ScanHosts: 254},
		},
	}
	u.scanCache[operator.Key] = model.ScanResult{
		Operator:        operator,
		FinishedAt:      time.Now(),
		ScannedTargets:  254,
		TotalTargets:    254,
		ReachableCount:  12,
		RecursiveCount:  5,
		DNSTTChecked:    3,
		DNSTTTunnel:     2,
		DNSTTE2E:        1,
		DNSTTFinishedAt: time.Now(),
		Protocol:        string(scanner.ProtocolUDP),
		Port:            53,
		Workers:         256,
		TimeoutMillis:   1200,
		Resolvers: []model.Resolver{
			{IP: "198.51.100.10", Prefix: "198.51.100.0/24", DNSReachable: true, RecursionAvailable: true, Stable: true, DNSTTTunnelOK: true},
		},
	}
	u.mode = screenDNSTT
	u.ensureScanRangeSelection(operator.Key)

	u.renderDetails()

	text := u.details.GetText(true)
	if !strings.Contains(text, "Step Progress") || !strings.Contains(text, "3. DNSTT E2E") {
		t.Fatalf("expected staged DNSTT workflow in details, got: %s", text)
	}
	if !strings.Contains(text, "DNSTT Guide") {
		t.Fatalf("expected DNSTT guide in details, got: %s", text)
	}
	if !strings.Contains(text, "DNSTT Domain: Domain used for the tunnel") {
		t.Fatalf("expected DNSTT guide entries in details, got: %s", text)
	}
	if strings.Index(text, "Step Progress") > strings.Index(text, "DNSTT Guide") {
		t.Fatalf("expected DNSTT guide below step progress, got: %s", text)
	}
	if !strings.Contains(text, "DNSTT Setup\n") || !strings.Contains(text, "DNSTT Results\n") || !strings.Contains(text, "Export\n") {
		t.Fatalf("expected dedicated DNSTT detail sections, got: %s", text)
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
	if !strings.Contains(text, "2. DNS Scan") || !strings.Contains(text, "running: working 0, compatible 0, qualified 0") {
		t.Fatalf("expected workflow scan progress in details, got: %s", text)
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

	if got := scanRangeLabel(entry, false, false); got != "         256 IPs  198.51.100.0/24" {
		t.Fatalf("unexpected plain label: %q", got)
	}
	if got := scanRangeLabel(entry, false, true); got != "[black:lightskyblue]         256 IPs  198.51.100.0/24[-:-:-]" {
		t.Fatalf("unexpected highlighted label: %q", got)
	}
}

func TestOperatorFormShowsImportControlsForTXTSource(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.setSelectedTargetSource(operator.Key, targetSourceImportTXT)
	u.rebuildForm()

	sourceField, ok := u.form.GetFormItem(0).(*tview.DropDown)
	if !ok || sourceField == nil {
		t.Fatalf("expected source dropdown at form item 0, got %T", u.form.GetFormItem(0))
	}
	pathField, ok := u.form.GetFormItem(1).(*tview.InputField)
	if !ok {
		t.Fatalf("expected import file field at form item 1, got %T", u.form.GetFormItem(1))
	}
	if !strings.Contains(pathField.GetLabel(), "Import File") {
		t.Fatalf("expected Import File label, got %q", pathField.GetLabel())
	}
	if !u.hasButton("Import TXT") {
		t.Fatal("expected Import TXT button for TXT source")
	}
	if u.hasButton("Save Targets") {
		t.Fatal("expected Save Targets to stay hidden before any targets are loaded")
	}
}

func TestOperatorFormShowsPasteControlsForPasteSource(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.setSelectedTargetSource(operator.Key, targetSourcePaste)
	u.setPasteBuffer(operator.Key, "198.51.100.10\n198.51.100.0/24\n")
	u.rebuildForm()

	statusField, ok := u.form.GetFormItem(1).(*tview.InputField)
	if !ok {
		t.Fatalf("expected paste status field at form item 1, got %T", u.form.GetFormItem(1))
	}
	if got := statusField.GetText(); got != "2 lines ready" {
		t.Fatalf("unexpected paste status text: %q", got)
	}
	if !u.hasButton("Paste Targets") {
		t.Fatal("expected Paste Targets button for paste source")
	}
	if u.hasButton("Save Targets") {
		t.Fatal("expected Save Targets to stay hidden before any pasted targets are applied")
	}
}

func TestSelectedScanSummaryUsesRawSingleIPForImportedTargets(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator:    operator,
		SourceLabel: string(targetSourceImportTXT),
		SourcePath:  "/tmp/targets.txt",
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.10/32", TotalAddresses: 1, ScanHosts: 1},
		},
	}

	u.ensureScanRangeSelection(operator.Key)

	if got := u.selectedScanSummary(operator.Key); got != "198.51.100.10" {
		t.Fatalf("unexpected imported single-IP summary: %q", got)
	}
}

func TestSelectedScanSummaryUsesRawSingleIPForPastedTargets(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.lookupCache[operator.Key] = model.LookupResult{
		Operator:    operator,
		SourceLabel: string(targetSourcePaste),
		Entries: []model.PrefixEntry{
			{Prefix: "198.51.100.20/32", TotalAddresses: 1, ScanHosts: 1},
		},
	}

	u.ensureScanRangeSelection(operator.Key)

	if got := u.selectedScanSummary(operator.Key); got != "198.51.100.20" {
		t.Fatalf("unexpected pasted single-IP summary: %q", got)
	}
}

func TestLoadTargetsOpensPasteModalForPasteSource(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.setSelectedTargetSource(operator.Key, targetSourcePaste)

	u.loadTargets()

	if !u.pages.HasPage("paste-targets") {
		t.Fatal("expected loadTargets to open the paste modal for paste source")
	}
}

func TestPasteModalReopensAtTopWhenBufferExists(t *testing.T) {
	u := newUI()
	operator := u.selectedOperator()
	u.setPasteBuffer(operator.Key, "198.51.100.1\n198.51.100.2\n198.51.100.3")

	u.openPasteTargetsModal()

	name, primitive := u.pages.GetFrontPage()
	if name != "paste-targets" {
		t.Fatalf("expected paste-targets page on top, got %q", name)
	}

	textArea := findTextArea(primitive)
	if textArea == nil {
		t.Fatal("expected paste modal to contain a text area")
	}

	fromRow, fromColumn, toRow, toColumn := textArea.GetCursor()
	if fromRow != 0 || fromColumn != 0 || toRow != 0 || toColumn != 0 {
		t.Fatalf("expected paste modal cursor at top, got (%d,%d)->(%d,%d)", fromRow, fromColumn, toRow, toColumn)
	}
	rowOffset, columnOffset := textArea.GetOffset()
	if rowOffset != 0 || columnOffset != 0 {
		t.Fatalf("expected paste modal offset at top, got row=%d column=%d", rowOffset, columnOffset)
	}
}

func TestScannerDetailsShowDNSTTErrorForFailedE2E(t *testing.T) {
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
		Resolvers: []model.Resolver{
			{
				IP:                 "198.51.100.10",
				Prefix:             "198.51.100.0/24",
				DNSReachable:       true,
				RecursionAvailable: true,
				Stable:             true,
				DNSTTChecked:       true,
				DNSTTTunnelOK:      true,
				DNSTTE2EOK:         false,
				DNSTTError:         "socks5 handshake did not complete",
			},
		},
	}

	u.mode = screenScanner
	u.ensureScanRangeSelection(operator.Key)
	u.renderDetails()

	text := u.details.GetText(true)
	if !strings.Contains(text, "dnstt error: socks5 handshake did not complete") {
		t.Fatalf("expected DNSTT error in report section, got: %s", text)
	}
}

func hasFormItemLabel(u *ui, label string) bool {
	want := label + ": "
	for i := 0; i < u.form.GetFormItemCount(); i++ {
		switch item := u.form.GetFormItem(i).(type) {
		case *tview.InputField:
			if item.GetLabel() == want {
				return true
			}
		case *tview.DropDown:
			if item.GetLabel() == want {
				return true
			}
		}
	}
	return false
}

func findFormItemIndexByLabel(u *ui, label string) int {
	want := label + ": "
	for i := 0; i < u.form.GetFormItemCount(); i++ {
		switch item := u.form.GetFormItem(i).(type) {
		case *tview.InputField:
			if item.GetLabel() == want {
				return i
			}
		case *tview.DropDown:
			if item.GetLabel() == want {
				return i
			}
		}
	}
	return -1
}

func findTextArea(primitive tview.Primitive) *tview.TextArea {
	switch p := primitive.(type) {
	case nil:
		return nil
	case *tview.TextArea:
		return p
	case *tview.Frame:
		return findTextArea(p.GetPrimitive())
	case *tview.Flex:
		for i := 0; i < p.GetItemCount(); i++ {
			if found := findTextArea(p.GetItem(i)); found != nil {
				return found
			}
		}
	case *tview.Pages:
		_, front := p.GetFrontPage()
		return findTextArea(front)
	}
	return nil
}

type recordingScreen struct {
	tcell.Screen
	mouseEnabled bool
	pasteEnabled bool
}

func (s *recordingScreen) EnableMouse(flags ...tcell.MouseFlags) {
	s.mouseEnabled = true
	s.Screen.EnableMouse(flags...)
}

func (s *recordingScreen) EnablePaste() {
	s.pasteEnabled = true
	s.Screen.EnablePaste()
}
