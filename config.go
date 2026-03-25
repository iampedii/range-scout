package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	configFileName         = "config.json"
	defaultImportConfigKey = "default"
)

var workingDirReader = os.Getwd
var executablePathReader = os.Executable

type appConfig struct {
	ImportConfig importStageConfig `json:"importConfig"`
	ScanConfig   scanStageConfig   `json:"scanConfig"`
	DNSTTConfig  dnsttStageConfig  `json:"dnsttConfig"`
}

type importStageConfig struct {
	ImportFilePaths importFilePathConfig `json:"importFilePaths"`
}

type scanStageConfig struct {
	Workers       configValue `json:"workers"`
	TimeoutMS     configValue `json:"timeoutMS"`
	Port          configValue `json:"port"`
	Protocol      configValue `json:"protocol"`
	RecursionHost configValue `json:"recursionHost"`
	ProbeHost1    configValue `json:"probeHost1"`
	ProbeHost2    configValue `json:"probeHost2"`
}

type dnsttStageConfig struct {
	Domain         configValue `json:"domain"`
	Pubkey         configValue `json:"pubkey"`
	TimeoutMS      configValue `json:"timeoutMS"`
	E2ETimeoutS    configValue `json:"e2eTimeoutS"`
	QuerySize      configValue `json:"querySize"`
	ScoreThreshold configValue `json:"scoreThreshold"`
	E2EURL         configValue `json:"e2eURL"`
	TestNearbyIPs  configValue `json:"testNearbyIPs"`
	SOCKSUsername  configValue `json:"socksUsername"`
	SOCKSPassword  configValue `json:"socksPassword"`
	E2EPort        configValue `json:"e2ePort"`
}

type configValue struct {
	Value string
	Set   bool
}

func (v configValue) MarshalJSON() ([]byte, error) {
	if !v.Set {
		return []byte("null"), nil
	}
	return json.Marshal(v.Value)
}

func (v *configValue) UnmarshalJSON(data []byte) error {
	v.Set = true

	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		v.Value = ""
		return nil
	}

	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		v.Value = text
		return nil
	}

	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err == nil {
		v.Value = number.String()
		return nil
	}

	return fmt.Errorf("expected string or number, got %s", strings.TrimSpace(string(data)))
}

type importFilePathConfig map[string]string

func (c *importFilePathConfig) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*c = nil
		return nil
	}

	var single string
	if err := json.Unmarshal(trimmed, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			*c = nil
			return nil
		}
		*c = importFilePathConfig{defaultImportConfigKey: single}
		return nil
	}

	var many map[string]string
	if err := json.Unmarshal(trimmed, &many); err == nil {
		*c = importFilePathConfig(many)
		return nil
	}

	return fmt.Errorf("expected string or object for importFilePaths")
}

func loadAppConfig(path string) (appConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return appConfig{}, false, nil
		}
		return appConfig{}, false, err
	}

	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return appConfig{}, true, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	return cfg, true, nil
}

func (u *ui) currentAppConfig() appConfig {
	configDir := filepath.Dir(u.currentConfigPath())
	importPaths := make(importFilePathConfig)
	for key, path := range u.importPaths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		importPaths[key] = encodeConfigPath(configDir, trimmed)
	}

	return appConfig{
		ImportConfig: importStageConfig{
			ImportFilePaths: importPaths,
		},
		ScanConfig: scanStageConfig{
			Workers:       configValue{Value: u.scanWorkers, Set: true},
			TimeoutMS:     configValue{Value: u.scanTimeoutMS, Set: true},
			Port:          configValue{Value: u.scanPort, Set: true},
			Protocol:      configValue{Value: u.scanProtocol, Set: true},
			RecursionHost: configValue{Value: u.scanRecursionURL, Set: true},
			ProbeHost1:    configValue{Value: u.scanProbeURL1, Set: true},
			ProbeHost2:    configValue{Value: u.scanProbeURL2, Set: true},
		},
		DNSTTConfig: dnsttStageConfig{
			Domain:         configValue{Value: u.dnsttDomain, Set: true},
			Pubkey:         configValue{Value: u.dnsttPubkey, Set: true},
			TimeoutMS:      configValue{Value: u.dnsttTimeoutMS, Set: true},
			E2ETimeoutS:    configValue{Value: u.dnsttE2ETimeoutS, Set: true},
			QuerySize:      configValue{Value: u.dnsttQuerySize, Set: true},
			ScoreThreshold: configValue{Value: u.dnsttScoreThreshold, Set: true},
			E2EURL:         configValue{Value: u.dnsttE2EURL, Set: true},
			TestNearbyIPs:  configValue{Value: normalizeYesNoValue(u.dnsttNearbyIPs), Set: true},
			SOCKSUsername:  configValue{Value: u.dnsttSOCKSUsername, Set: true},
			SOCKSPassword:  configValue{Value: u.dnsttSOCKSPassword, Set: true},
		},
	}
}

func saveAppConfig(path string, cfg appConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func (u *ui) loadStartupConfig() string {
	configPath := resolveStartupConfigPath()
	u.configPath = configPath

	cfg, loaded, err := loadAppConfig(configPath)
	if err != nil {
		return fmt.Sprintf("Config load failed: %v", err)
	}
	if !loaded {
		return ""
	}

	u.applyAppConfig(cfg, filepath.Dir(configPath))
	return fmt.Sprintf("Loaded config from %s", configPath)
}

func (u *ui) saveConfig() {
	configPath := u.currentConfigPath()
	if err := saveAppConfig(configPath, u.currentAppConfig()); err != nil {
		u.setStatus(fmt.Sprintf("Config save failed: %v", err))
		u.addActivity("Config save failed")
		return
	}
	u.configPath = configPath
	u.setStatus(fmt.Sprintf("Saved config to %s", configPath))
	u.addActivity(fmt.Sprintf("Saved config to %s", configPath))
}

func (u *ui) applyAppConfig(cfg appConfig, configDir string) {
	for key, path := range cfg.ImportConfig.ImportFilePaths {
		targetKey := strings.TrimSpace(key)
		if targetKey == "" {
			targetKey = defaultImportConfigKey
		}
		u.setImportPath(targetKey, resolveConfigPath(configDir, path))
	}

	if cfg.ScanConfig.Workers.Set {
		u.scanWorkers = cfg.ScanConfig.Workers.Value
	}
	if cfg.ScanConfig.TimeoutMS.Set {
		u.scanTimeoutMS = cfg.ScanConfig.TimeoutMS.Value
	}
	if cfg.ScanConfig.Port.Set {
		u.scanPort = cfg.ScanConfig.Port.Value
	}
	if cfg.ScanConfig.Protocol.Set {
		u.scanProtocol = cfg.ScanConfig.Protocol.Value
	}
	if cfg.ScanConfig.RecursionHost.Set {
		u.scanRecursionURL = cfg.ScanConfig.RecursionHost.Value
	}
	if cfg.ScanConfig.ProbeHost1.Set {
		u.scanProbeURL1 = cfg.ScanConfig.ProbeHost1.Value
	}
	if cfg.ScanConfig.ProbeHost2.Set {
		u.scanProbeURL2 = cfg.ScanConfig.ProbeHost2.Value
	}

	if cfg.DNSTTConfig.Domain.Set {
		u.dnsttDomain = cfg.DNSTTConfig.Domain.Value
	}
	if cfg.DNSTTConfig.Pubkey.Set {
		u.dnsttPubkey = cfg.DNSTTConfig.Pubkey.Value
	}
	if cfg.DNSTTConfig.TimeoutMS.Set {
		u.dnsttTimeoutMS = cfg.DNSTTConfig.TimeoutMS.Value
	}
	if cfg.DNSTTConfig.E2ETimeoutS.Set {
		u.dnsttE2ETimeoutS = cfg.DNSTTConfig.E2ETimeoutS.Value
	}
	if cfg.DNSTTConfig.QuerySize.Set {
		u.dnsttQuerySize = cfg.DNSTTConfig.QuerySize.Value
	}
	if cfg.DNSTTConfig.ScoreThreshold.Set {
		u.dnsttScoreThreshold = cfg.DNSTTConfig.ScoreThreshold.Value
	}
	if cfg.DNSTTConfig.E2EURL.Set {
		u.dnsttE2EURL = cfg.DNSTTConfig.E2EURL.Value
	}
	if cfg.DNSTTConfig.TestNearbyIPs.Set {
		u.dnsttNearbyIPs = normalizeYesNoValue(cfg.DNSTTConfig.TestNearbyIPs.Value)
	}
	if cfg.DNSTTConfig.SOCKSUsername.Set {
		u.dnsttSOCKSUsername = cfg.DNSTTConfig.SOCKSUsername.Value
	}
	if cfg.DNSTTConfig.SOCKSPassword.Set {
		u.dnsttSOCKSPassword = cfg.DNSTTConfig.SOCKSPassword.Value
	}
}

func resolveConfigPath(configDir, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	if strings.TrimSpace(configDir) == "" || configDir == "." {
		return filepath.Clean(trimmed)
	}
	return filepath.Clean(filepath.Join(configDir, trimmed))
}

func (u *ui) currentConfigPath() string {
	if trimmed := strings.TrimSpace(u.configPath); trimmed != "" {
		return filepath.Clean(trimmed)
	}
	return resolveStartupConfigPath()
}

func resolveStartupConfigPath() string {
	for _, path := range startupConfigCandidates() {
		if configFileExists(path) {
			return path
		}
	}

	candidates := startupConfigCandidates()
	if len(candidates) > 0 {
		return candidates[0]
	}
	return configFileName
}

func startupConfigCandidates() []string {
	candidates := make([]string, 0, 2)

	if workingDir, err := workingDirReader(); err == nil && strings.TrimSpace(workingDir) != "" {
		candidates = appendUniquePath(candidates, filepath.Join(workingDir, configFileName))
	}

	if executablePath, err := executablePathReader(); err == nil && strings.TrimSpace(executablePath) != "" {
		candidates = appendUniquePath(candidates, filepath.Join(filepath.Dir(executablePath), configFileName))
	}

	return candidates
}

func appendUniquePath(paths []string, path string) []string {
	cleaned := filepath.Clean(path)
	for _, existing := range paths {
		if existing == cleaned {
			return paths
		}
	}
	return append(paths, cleaned)
}

func configFileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func encodeConfigPath(configDir, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	if !filepath.IsAbs(trimmed) {
		return filepath.ToSlash(filepath.Clean(trimmed))
	}

	if strings.TrimSpace(configDir) != "" {
		relative, err := filepath.Rel(configDir, trimmed)
		if err == nil && !pathEscapesBase(relative) {
			return filepath.ToSlash(filepath.Clean(relative))
		}
	}

	return filepath.Clean(trimmed)
}

func pathEscapesBase(path string) bool {
	cleaned := filepath.Clean(path)
	if cleaned == ".." {
		return true
	}
	return strings.HasPrefix(filepath.ToSlash(cleaned), "../")
}
