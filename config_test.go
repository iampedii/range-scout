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
  "dnsttConfig": {
    "domain": "t.example.com",
    "pubkey": "deadbeef",
    "timeoutMS": 4000,
    "e2eTimeoutS": 30,
    "querySize": "",
    "e2ePort": 53
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
	if !cfg.DNSTTConfig.TimeoutMS.Set || cfg.DNSTTConfig.TimeoutMS.Value != "4000" {
		t.Fatalf("unexpected DNSTT timeout config: %+v", cfg.DNSTTConfig.TimeoutMS)
	}
	if !cfg.DNSTTConfig.E2EPort.Set || cfg.DNSTTConfig.E2EPort.Value != "53" {
		t.Fatalf("unexpected DNSTT e2e port config: %+v", cfg.DNSTTConfig.E2EPort)
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
		DNSTTConfig: dnsttStageConfig{
			Domain:      configured("t.example.com"),
			Pubkey:      configured("deadbeef"),
			TimeoutMS:   configured("4500"),
			E2ETimeoutS: configured("25"),
			QuerySize:   configured("1400"),
			E2EPort:     configured("443"),
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
	if u.scanProtocol != "both" || u.scanRecursionURL != "cloudflare.com" || u.scanProbeURL1 != "github.com" || u.scanProbeURL2 != "example.com" {
		t.Fatalf("unexpected scan host config: protocol=%q recursion=%q probe1=%q probe2=%q", u.scanProtocol, u.scanRecursionURL, u.scanProbeURL1, u.scanProbeURL2)
	}
	if u.dnsttDomain != "t.example.com" || u.dnsttPubkey != "deadbeef" || u.dnsttTimeoutMS != "4500" || u.dnsttE2ETimeoutS != "25" || u.dnsttQuerySize != "1400" || u.dnsttE2EPort != "443" {
		t.Fatalf("unexpected DNSTT config: domain=%q pubkey=%q timeout=%q e2eTimeout=%q querySize=%q e2ePort=%q", u.dnsttDomain, u.dnsttPubkey, u.dnsttTimeoutMS, u.dnsttE2ETimeoutS, u.dnsttQuerySize, u.dnsttE2EPort)
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
	u.dnsttDomain = "t.example.com"
	u.dnsttPubkey = "deadbeef"
	u.dnsttTimeoutMS = "4200"
	u.dnsttE2ETimeoutS = "22"
	u.dnsttQuerySize = "1400"
	u.dnsttE2EPort = "443"

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
	if got := cfg.ScanConfig.Protocol.Value; got != "tcp" {
		t.Fatalf("unexpected saved protocol value: %q", got)
	}
	if got := cfg.DNSTTConfig.E2EPort.Value; got != "443" {
		t.Fatalf("unexpected saved e2e port value: %q", got)
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
