package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
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
	ImportConfig    importStageConfig   `json:"importConfig"`
	ScanConfig      scanStageConfig     `json:"scanConfig"`
	StormDNSConfig  stormdnsStageConfig `json:"stormdnsConfig"`
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

func (c scanStageConfig) MarshalJSON() ([]byte, error) {
	type savedScanStageConfig struct {
		Workers   configValue `json:"workers"`
		TimeoutMS configValue `json:"timeoutMS"`
		Port      configValue `json:"port"`
		Protocol  configValue `json:"protocol"`
	}

	return json.Marshal(savedScanStageConfig{
		Workers:   c.Workers,
		TimeoutMS: c.TimeoutMS,
		Port:      c.Port,
		Protocol:  c.Protocol,
	})
}

type stormdnsStageConfig struct {
	Domain         configValue `json:"domain"`
	Key            configValue `json:"key"`
	Transport      configValue `json:"transport"`
	ResolverURL    configValue `json:"resolverURL"`
	TimeoutMS      configValue `json:"timeoutMS"`
	QuerySize      configValue `json:"querySize"`
	ScoreThreshold configValue `json:"scoreThreshold"`
	MTURetries     configValue `json:"mtuRetries"`
	TestNearbyIPs  configValue `json:"testNearbyIPs"`
}

func (c stormdnsStageConfig) MarshalJSON() ([]byte, error) {
	type savedStormDNSStageConfig struct {
		Domain         configValue `json:"domain"`
		Key            configValue `json:"key"`
		Transport      configValue `json:"transport"`
		ResolverURL    configValue `json:"resolverURL"`
		TimeoutMS      configValue `json:"timeoutMS"`
		QuerySize      configValue `json:"querySize"`
		ScoreThreshold configValue `json:"scoreThreshold"`
		MTURetries     configValue `json:"mtuRetries"`
		TestNearbyIPs  configValue `json:"testNearbyIPs"`
	}

	return json.Marshal(savedStormDNSStageConfig{
		Domain:         c.Domain,
		Key:            c.Key,
		Transport:      c.Transport,
		ResolverURL:    c.ResolverURL,
		TimeoutMS:      c.TimeoutMS,
		QuerySize:      c.QuerySize,
		ScoreThreshold: c.ScoreThreshold,
		MTURetries:     c.MTURetries,
		TestNearbyIPs:  c.TestNearbyIPs,
	})
}

// legacyDNSTTBlock is used only for migration: reading old "dnsttConfig" JSON blocks.
type legacyDNSTTBlock struct {
	Domain configValue `json:"domain"`
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

// rawConfigForMigration is used internally to detect legacy dnsttConfig blocks
// alongside the new stormdnsConfig block.
type rawConfigForMigration struct {
	StormDNSConfig    stormdnsStageConfig `json:"stormdnsConfig"`
	LegacyDNSTTConfig *legacyDNSTTBlock   `json:"dnsttConfig"`
}

func loadAppConfig(path string) (appConfig, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return appConfig{}, false, nil
		}
		return appConfig{}, false, err
	}

	// First, decode into migration-aware shape to detect legacy dnsttConfig blocks.
	var raw rawConfigForMigration
	if err := json.Unmarshal(data, &raw); err != nil {
		return appConfig{}, true, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	if raw.LegacyDNSTTConfig != nil && raw.LegacyDNSTTConfig.Domain.Set && raw.LegacyDNSTTConfig.Domain.Value != "" && !raw.StormDNSConfig.Domain.Set {
		raw.StormDNSConfig.Domain = raw.LegacyDNSTTConfig.Domain
		log.Println(`WARN: legacy dnsttConfig block detected; "domain" migrated to stormdnsConfig.domain; other DNSTT-only fields ignored`)
	}

	var cfg appConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return appConfig{}, true, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}

	// Apply migrated stormdnsConfig domain if needed.
	if raw.StormDNSConfig.Domain.Set && !cfg.StormDNSConfig.Domain.Set {
		cfg.StormDNSConfig.Domain = raw.StormDNSConfig.Domain
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
			Workers:   configValue{Value: u.scanWorkers, Set: true},
			TimeoutMS: configValue{Value: u.scanTimeoutMS, Set: true},
			Port:      configValue{Value: u.scanPort, Set: true},
			Protocol:  configValue{Value: mustProtocol(u.scanProtocol, "UDP"), Set: true},
		},
		StormDNSConfig: stormdnsStageConfig{
			Domain:         configValue{Value: u.stormdnsDomain, Set: true},
			Key:            configValue{Value: u.stormdnsKey, Set: true},
			Transport:      configValue{Value: u.stormdnsTransport, Set: true},
			ResolverURL:    configValue{Value: u.stormdnsResolverURL, Set: true},
			TimeoutMS:      configValue{Value: u.stormdnsTimeoutMS, Set: true},
			QuerySize:      configValue{Value: u.stormdnsQuerySize, Set: true},
			ScoreThreshold: configValue{Value: u.stormdnsScoreThreshold, Set: true},
			MTURetries:     configValue{Value: u.stormdnsMTURetries, Set: true},
			TestNearbyIPs:  configValue{Value: normalizeYesNoValue(u.stormdnsNearbyIPs), Set: true},
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
		u.scanProtocol = mustProtocol(cfg.ScanConfig.Protocol.Value, "UDP")
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

	if cfg.StormDNSConfig.Domain.Set {
		u.stormdnsDomain = cfg.StormDNSConfig.Domain.Value
	}
	if cfg.StormDNSConfig.Key.Set {
		u.stormdnsKey = cfg.StormDNSConfig.Key.Value
	}
	if cfg.StormDNSConfig.Transport.Set {
		u.stormdnsTransport = cfg.StormDNSConfig.Transport.Value
	}
	if cfg.StormDNSConfig.ResolverURL.Set {
		u.stormdnsResolverURL = cfg.StormDNSConfig.ResolverURL.Value
	}
	if cfg.StormDNSConfig.TimeoutMS.Set {
		u.stormdnsTimeoutMS = cfg.StormDNSConfig.TimeoutMS.Value
	}
	if cfg.StormDNSConfig.QuerySize.Set {
		u.stormdnsQuerySize = cfg.StormDNSConfig.QuerySize.Value
	}
	if cfg.StormDNSConfig.ScoreThreshold.Set {
		u.stormdnsScoreThreshold = cfg.StormDNSConfig.ScoreThreshold.Value
	}
	if cfg.StormDNSConfig.MTURetries.Set {
		u.stormdnsMTURetries = cfg.StormDNSConfig.MTURetries.Value
	}
	if cfg.StormDNSConfig.TestNearbyIPs.Set {
		u.stormdnsNearbyIPs = normalizeYesNoValue(cfg.StormDNSConfig.TestNearbyIPs.Value)
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
