package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppConfigSupportsFlexibleValues(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)
	configJSON := `{
  "importConfig": {
    "importFilePaths": "targets/shared.txt"
  },
  "scanConfig": {
    "workers": 512,
    "timeoutMS": 1500,
    "port": 5353,
    "protocol": "tcp",
    "recursionHost": "one.one.one.one",
    "probeHost1": "github.com",
    "probeHost2": "example.com"
  },
  "stormdnsConfig": {
    "domain": "t.example.com",
    "key": "deadbeef",
    "timeoutMS": 4000,
    "querySize": "",
    "scoreThreshold": 3,
    "mtuRetries": "2",
    "testNearbyIPs": "Yes"
  }
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg, loaded, err := loadAppConfig(configPath)
	if err != nil {
		t.Fatalf("loadAppConfig returned error: %v", err)
	}
	if !loaded {
		t.Fatal("expected config file to be reported as loaded")
	}

	if got := cfg.ImportConfig.ImportFilePaths[defaultImportConfigKey]; got != "targets/shared.txt" {
		t.Fatalf("unexpected default import path: %q", got)
	}
	if !cfg.ScanConfig.Workers.Set || cfg.ScanConfig.Workers.Value != "512" {
		t.Fatalf("unexpected workers config: %+v", cfg.ScanConfig.Workers)
	}
	if !cfg.ScanConfig.Port.Set || cfg.ScanConfig.Port.Value != "5353" {
		t.Fatalf("unexpected port config: %+v", cfg.ScanConfig.Port)
	}
	if !cfg.ScanConfig.Protocol.Set || cfg.ScanConfig.Protocol.Value != "tcp" {
		t.Fatalf("unexpected protocol config: %+v", cfg.ScanConfig.Protocol)
	}
	if !cfg.StormDNSConfig.TimeoutMS.Set || cfg.StormDNSConfig.TimeoutMS.Value != "4000" {
		t.Fatalf("unexpected StormDNS timeout config: %+v", cfg.StormDNSConfig.TimeoutMS)
	}
	if !cfg.StormDNSConfig.ScoreThreshold.Set || cfg.StormDNSConfig.ScoreThreshold.Value != "3" {
		t.Fatalf("unexpected StormDNS score threshold config: %+v", cfg.StormDNSConfig.ScoreThreshold)
	}
	if !cfg.StormDNSConfig.TestNearbyIPs.Set || cfg.StormDNSConfig.TestNearbyIPs.Value != "Yes" {
		t.Fatalf("unexpected StormDNS nearby setting: %+v", cfg.StormDNSConfig.TestNearbyIPs)
	}
	if !cfg.StormDNSConfig.MTURetries.Set || cfg.StormDNSConfig.MTURetries.Value != "2" {
		t.Fatalf("unexpected StormDNS mtu retries config: %+v", cfg.StormDNSConfig.MTURetries)
	}
}

func TestApplyAppConfigSetsUIState(t *testing.T) {
	u := newUI()
	configDir := t.TempDir()

	u.applyAppConfig(appConfig{
		ImportConfig: importStageConfig{
			ImportFilePaths: importFilePathConfig{
				defaultImportConfigKey: "targets/shared.txt",
				"mci":                  "targets/mci.txt",
			},
		},
		ScanConfig: scanStageConfig{
			Workers:       configured("1024"),
			TimeoutMS:     configured("2500"),
			Port:          configured("5353"),
			Protocol:      configured("both"),
			RecursionHost: configured("cloudflare.com"),
			ProbeHost1:    configured("github.com"),
			ProbeHost2:    configured("example.com"),
		},
		StormDNSConfig: stormdnsStageConfig{
			Domain:         configured("t.example.com"),
			Key:            configured("deadbeef"),
			TimeoutMS:      configured("4500"),
			QuerySize:      configured("1400"),
			ScoreThreshold: configured("4"),
			MTURetries:     configured("3"),
			TestNearbyIPs:  configured("Yes"),
		},
	}, configDir)

	if got := u.importPath(customOperatorKey); got != filepath.Join(configDir, "targets/shared.txt") {
		t.Fatalf("unexpected default import path: %q", got)
	}
	if got := u.importPath("mci"); got != filepath.Join(configDir, "targets/mci.txt") {
		t.Fatalf("unexpected operator import path: %q", got)
	}
	if got := u.importPath("unknown-operator"); got != filepath.Join(configDir, "targets/shared.txt") {
		t.Fatalf("expected default import path fallback, got %q", got)
	}

	if u.scanWorkers != "1024" || u.scanTimeoutMS != "2500" || u.scanPort != "5353" {
		t.Fatalf("unexpected scan numeric config: workers=%q timeout=%q port=%q", u.scanWorkers, u.scanTimeoutMS, u.scanPort)
	}
	if u.scanProtocol != "BOTH" || u.scanRecursionURL != "cloudflare.com" || u.scanProbeURL1 != "github.com" || u.scanProbeURL2 != "example.com" {
		t.Fatalf("unexpected scan host config: protocol=%q recursion=%q probe1=%q probe2=%q", u.scanProtocol, u.scanRecursionURL, u.scanProbeURL1, u.scanProbeURL2)
	}
	if u.stormdnsDomain != "t.example.com" || u.stormdnsKey != "deadbeef" || u.stormdnsTimeoutMS != "4500" || u.stormdnsQuerySize != "1400" || u.stormdnsScoreThreshold != "4" || u.stormdnsMTURetries != "3" || u.stormdnsNearbyIPs != yesOption {
		t.Fatalf("unexpected StormDNS config: domain=%q key=%q timeout=%q querySize=%q threshold=%q mtuRetries=%q nearby=%q",
			u.stormdnsDomain, u.stormdnsKey, u.stormdnsTimeoutMS, u.stormdnsQuerySize, u.stormdnsScoreThreshold, u.stormdnsMTURetries, u.stormdnsNearbyIPs)
	}
}

func TestSaveAppConfigRoundTripsCurrentUIState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, configFileName)

	u := newUI()
	u.configPath = configPath
	u.setImportPath(defaultImportConfigKey, filepath.Join(dir, "targets", "default.txt"))
	u.setImportPath("mtn", filepath.Join(dir, "targets", "mtn.txt"))
	u.scanWorkers = "768"
	u.scanTimeoutMS = "1800"
	u.scanPort = "5353"
	u.scanProtocol = "tcp"
	u.scanRecursionURL = "cloudflare.com"
	u.scanProbeURL1 = "github.com"
	u.scanProbeURL2 = "example.com"
	u.stormdnsDomain = "t.example.com"
	u.stormdnsKey = "deadbeef"
	u.stormdnsTimeoutMS = "4200"
	u.stormdnsQuerySize = "1400"
	u.stormdnsScoreThreshold = "5"
	u.stormdnsMTURetries = "2"
	u.stormdnsNearbyIPs = yesOption

	if err := saveAppConfig(configPath, u.currentAppConfig()); err != nil {
		t.Fatalf("saveAppConfig returned error: %v", err)
	}

	cfg, loaded, err := loadAppConfig(configPath)
	if err != nil {
		t.Fatalf("loadAppConfig returned error: %v", err)
	}
	if !loaded {
		t.Fatal("expected saved config file to be loaded")
	}

	if got := cfg.ImportConfig.ImportFilePaths[defaultImportConfigKey]; got != "targets/default.txt" {
		t.Fatalf("unexpected saved default import path: %q", got)
	}
	if got := cfg.ImportConfig.ImportFilePaths["mtn"]; got != "targets/mtn.txt" {
		t.Fatalf("unexpected saved operator import path: %q", got)
	}
	if got := cfg.ScanConfig.Workers.Value; got != "768" {
		t.Fatalf("unexpected saved workers value: %q", got)
	}
	if got := cfg.ScanConfig.Protocol.Value; got != "TCP" {
		t.Fatalf("unexpected saved protocol value: %q", got)
	}
	if cfg.ScanConfig.RecursionHost.Set || cfg.ScanConfig.ProbeHost1.Set || cfg.ScanConfig.ProbeHost2.Set {
		t.Fatalf("expected legacy scan host keys to be omitted from saved config: recursion=%+v probe1=%+v probe2=%+v", cfg.ScanConfig.RecursionHost, cfg.ScanConfig.ProbeHost1, cfg.ScanConfig.ProbeHost2)
	}
	if got := cfg.StormDNSConfig.Domain.Value; got != "t.example.com" {
		t.Fatalf("unexpected saved domain value: %q", got)
	}
	if got := cfg.StormDNSConfig.Key.Value; got != "deadbeef" {
		t.Fatalf("unexpected saved key value: %q", got)
	}
	if got := cfg.StormDNSConfig.ScoreThreshold.Value; got != "5" {
		t.Fatalf("unexpected saved score threshold value: %q", got)
	}
	if got := cfg.StormDNSConfig.TestNearbyIPs.Value; got != yesOption {
		t.Fatalf("unexpected saved nearby setting: %q", got)
	}
	if got := cfg.StormDNSConfig.MTURetries.Value; got != "2" {
		t.Fatalf("unexpected saved mtu retries value: %q", got)
	}
}

func TestLoadConfigMigratesLegacyDNSTTBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
		"stormdnsConfig": {},
		"dnsttConfig": {
			"domain": "legacy.example.com",
			"pubkey": "ignored",
			"e2eURL": "ignored",
			"socksUsername": "ignored"
		}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, loaded, err := loadAppConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded {
		t.Fatal("expected config to be loaded")
	}
	if cfg.StormDNSConfig.Domain.Value != "legacy.example.com" {
		t.Fatalf("domain not migrated, got %q", cfg.StormDNSConfig.Domain.Value)
	}
}

func TestResolveStartupConfigPathPrefersWorkingDirectory(t *testing.T) {
	workingDir := t.TempDir()
	executableDir := t.TempDir()
	workingConfigPath := filepath.Join(workingDir, configFileName)
	executableConfigPath := filepath.Join(executableDir, configFileName)

	if err := os.WriteFile(workingConfigPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(executableConfigPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	previousWorkingDirReader := workingDirReader
	previousExecutablePathReader := executablePathReader
	workingDirReader = func() (string, error) { return workingDir, nil }
	executablePathReader = func() (string, error) { return filepath.Join(executableDir, "range-scout"), nil }
	defer func() {
		workingDirReader = previousWorkingDirReader
		executablePathReader = previousExecutablePathReader
	}()

	if got := resolveStartupConfigPath(); got != workingConfigPath {
		t.Fatalf("expected working directory config path, got %q", got)
	}
}

func TestResolveStartupConfigPathFallsBackToExecutableDirectory(t *testing.T) {
	workingDir := t.TempDir()
	executableDir := t.TempDir()
	executableConfigPath := filepath.Join(executableDir, configFileName)

	if err := os.WriteFile(executableConfigPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	previousWorkingDirReader := workingDirReader
	previousExecutablePathReader := executablePathReader
	workingDirReader = func() (string, error) { return workingDir, nil }
	executablePathReader = func() (string, error) { return filepath.Join(executableDir, "range-scout"), nil }
	defer func() {
		workingDirReader = previousWorkingDirReader
		executablePathReader = previousExecutablePathReader
	}()

	if got := resolveStartupConfigPath(); got != executableConfigPath {
		t.Fatalf("expected executable directory config path, got %q", got)
	}
}

func TestEncodeConfigPathKeepsOutsidePathsAbsolute(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "project")
	outsidePath := filepath.Join(t.TempDir(), "shared", "targets.txt")

	if got := encodeConfigPath(configDir, outsidePath); got != filepath.Clean(outsidePath) {
		t.Fatalf("expected outside path to remain absolute, got %q", got)
	}
}

func configured(value string) configValue {
	return configValue{Value: value, Set: true}
}
