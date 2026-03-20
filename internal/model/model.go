package model

import "time"

type Operator struct {
	Key  string   `json:"key"`
	Name string   `json:"name"`
	ASNs []string `json:"asns"`
}

type PrefixEntry struct {
	Prefix         string   `json:"prefix"`
	SourceASNs     []string `json:"source_asns"`
	TotalAddresses uint64   `json:"total_addresses"`
	ScanHosts      uint64   `json:"scan_hosts"`
}

type LookupResult struct {
	Operator       Operator      `json:"operator"`
	Entries        []PrefixEntry `json:"entries"`
	TotalAddresses uint64        `json:"total_addresses"`
	TotalScanHosts uint64        `json:"total_scan_hosts"`
	FetchedAt      time.Time     `json:"fetched_at"`
	Warnings       []string      `json:"warnings,omitempty"`
	SourceLabel    string        `json:"source_label"`
	SourceURL      string        `json:"source_url"`
	SourcePath     string        `json:"source_path,omitempty"`
}

type Resolver struct {
	IP                  string `json:"ip"`
	Transport           string `json:"transport,omitempty"`
	Prefix              string `json:"prefix"`
	DNSReachable        bool   `json:"dns_reachable"`
	RecursionAvailable  bool   `json:"recursion_available"`
	RecursionAdvertised bool   `json:"recursion_advertised"`
	Stable              bool   `json:"stable"`
	ResponseCode        string `json:"response_code"`
	LatencyMillis       int64  `json:"latency_ms"`
	DNSTTChecked        bool   `json:"dnstt_checked,omitempty"`
	DNSTTTunnelOK       bool   `json:"dnstt_tunnel_ok,omitempty"`
	DNSTTE2EOK          bool   `json:"dnstt_e2e_ok,omitempty"`
	DNSTTTunnelMillis   int64  `json:"dnstt_tunnel_ms,omitempty"`
	DNSTTE2EMillis      int64  `json:"dnstt_e2e_ms,omitempty"`
	DNSTTError          string `json:"dnstt_error,omitempty"`
}

type ScanResult struct {
	Operator        Operator      `json:"operator"`
	Prefixes        []PrefixEntry `json:"prefixes,omitempty"`
	Resolvers       []Resolver    `json:"resolvers"`
	TotalTargets    uint64        `json:"total_targets"`
	ScannedTargets  uint64        `json:"scanned_targets"`
	ReachableCount  uint64        `json:"reachable_count"`
	RecursiveCount  uint64        `json:"recursive_count"`
	Workers         int           `json:"workers"`
	TimeoutMillis   int           `json:"timeout_ms"`
	HostLimit       uint64        `json:"host_limit"`
	Port            int           `json:"port"`
	Protocol        string        `json:"protocol,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	DNSTTDomain     string        `json:"dnstt_domain,omitempty"`
	DNSTTChecked    uint64        `json:"dnstt_checked_count,omitempty"`
	DNSTTTunnel     uint64        `json:"dnstt_tunnel_count,omitempty"`
	DNSTTE2E        uint64        `json:"dnstt_e2e_count,omitempty"`
	DNSTTTimeoutMS  int           `json:"dnstt_timeout_ms,omitempty"`
	DNSTTE2ETimeS   int           `json:"dnstt_e2e_timeout_s,omitempty"`
	DNSTTQuerySize  int           `json:"dnstt_query_size,omitempty"`
	DNSTTE2EPort    int           `json:"dnstt_e2e_port,omitempty"`
	DNSTTE2EEnabled bool          `json:"dnstt_e2e_enabled,omitempty"`
	DNSTTStartedAt  time.Time     `json:"dnstt_started_at,omitempty"`
	DNSTTFinishedAt time.Time     `json:"dnstt_finished_at,omitempty"`
	Warnings        []string      `json:"warnings,omitempty"`
}
