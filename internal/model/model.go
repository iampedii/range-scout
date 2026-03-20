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
}

type ScanResult struct {
	Operator       Operator      `json:"operator"`
	Prefixes       []PrefixEntry `json:"prefixes,omitempty"`
	Resolvers      []Resolver    `json:"resolvers"`
	TotalTargets   uint64        `json:"total_targets"`
	ScannedTargets uint64        `json:"scanned_targets"`
	ReachableCount uint64        `json:"reachable_count"`
	RecursiveCount uint64        `json:"recursive_count"`
	Workers        int           `json:"workers"`
	TimeoutMillis  int           `json:"timeout_ms"`
	HostLimit      uint64        `json:"host_limit"`
	Port           int           `json:"port"`
	Protocol       string        `json:"protocol,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	FinishedAt     time.Time     `json:"finished_at"`
	Warnings       []string      `json:"warnings,omitempty"`
}
