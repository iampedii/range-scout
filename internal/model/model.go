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
	IP                   string `json:"ip"`
	Transport            string `json:"transport,omitempty"`
	Prefix               string `json:"prefix"`
	DNSTTNearby          bool   `json:"dnstt_nearby,omitempty"`
	DNSReachable         bool   `json:"dns_reachable"`
	ScanStatus           string `json:"scan_status,omitempty"`
	ScanError            string `json:"scan_error,omitempty"`
	RecursionAvailable   bool   `json:"recursion_available"`
	RecursionAdvertised  bool   `json:"recursion_advertised"`
	Stable               bool   `json:"stable"`
	ResponseCode         string `json:"response_code"`
	LatencyMillis        int64  `json:"latency_ms"`
	TunnelScore          int    `json:"tunnel_score,omitempty"`
	TunnelNSSupport      bool   `json:"tunnel_ns_support,omitempty"`
	TunnelTXTSupport     bool   `json:"tunnel_txt_support,omitempty"`
	TunnelRandomSub      bool   `json:"tunnel_random_sub,omitempty"`
	TunnelRealism        bool   `json:"tunnel_realism,omitempty"`
	TunnelEDNS0Support   bool   `json:"tunnel_edns0_support,omitempty"`
	TunnelEDNSMaxPayload int    `json:"tunnel_edns_max_payload,omitempty"`
	TunnelNXDOMAIN       bool   `json:"tunnel_nxdomain,omitempty"`
	DNSTTChecked         bool   `json:"dnstt_checked,omitempty"`
	DNSTTTunnelOK        bool   `json:"dnstt_tunnel_ok,omitempty"`
	DNSTTE2EOK           bool   `json:"dnstt_e2e_ok,omitempty"`
	DNSTTTunnelMillis    int64  `json:"dnstt_tunnel_ms,omitempty"`
	DNSTTE2EMillis       int64  `json:"dnstt_e2e_ms,omitempty"`
	DNSTTError           string `json:"dnstt_error,omitempty"`
}

type ScanResult struct {
	Operator                 Operator      `json:"operator"`
	Prefixes                 []PrefixEntry `json:"prefixes,omitempty"`
	Resolvers                []Resolver    `json:"resolvers"`
	TotalTargets             uint64        `json:"total_targets"`
	ScannedTargets           uint64        `json:"scanned_targets"`
	ReachableCount           uint64        `json:"reachable_count"`
	RecursiveCount           uint64        `json:"recursive_count"`
	WorkingCount             uint64        `json:"working_count,omitempty"`
	CompatibleCount          uint64        `json:"compatible_count,omitempty"`
	QualifiedCount           uint64        `json:"qualified_count,omitempty"`
	Workers                  int           `json:"workers"`
	TimeoutMillis            int           `json:"timeout_ms"`
	HostLimit                uint64        `json:"host_limit"`
	Port                     int           `json:"port"`
	Protocol                 string        `json:"protocol,omitempty"`
	TunnelDomain             string        `json:"tunnel_domain,omitempty"`
	QuerySize                int           `json:"query_size,omitempty"`
	ScoreThreshold           int           `json:"score_threshold,omitempty"`
	TransparentProxyDetected bool          `json:"transparent_proxy_detected,omitempty"`
	StartedAt                time.Time     `json:"started_at"`
	FinishedAt               time.Time     `json:"finished_at"`
	DNSTTDomain              string        `json:"dnstt_domain,omitempty"`
	DNSTTCandidates          uint64        `json:"dnstt_candidate_count,omitempty"`
	DNSTTChecked             uint64        `json:"dnstt_checked_count,omitempty"`
	DNSTTTunnel              uint64        `json:"dnstt_tunnel_count,omitempty"`
	DNSTTE2E                 uint64        `json:"dnstt_e2e_count,omitempty"`
	DNSTTTimeoutMS           int           `json:"dnstt_timeout_ms,omitempty"`
	DNSTTE2ETimeS            int           `json:"dnstt_e2e_timeout_s,omitempty"`
	DNSTTQuerySize           int           `json:"dnstt_query_size,omitempty"`
	DNSTTE2EPort             int           `json:"dnstt_e2e_port,omitempty"`
	DNSTTE2EURL              string        `json:"dnstt_e2e_url,omitempty"`
	DNSTTE2EEnabled          bool          `json:"dnstt_e2e_enabled,omitempty"`
	DNSTTE2ERequested        bool          `json:"dnstt_e2e_requested,omitempty"`
	DNSTTTestNearbyIPs       bool          `json:"dnstt_test_nearby_ips,omitempty"`
	DNSTTStartedAt           time.Time     `json:"dnstt_started_at,omitempty"`
	DNSTTFinishedAt          time.Time     `json:"dnstt_finished_at,omitempty"`
	Warnings                 []string      `json:"warnings,omitempty"`
}
