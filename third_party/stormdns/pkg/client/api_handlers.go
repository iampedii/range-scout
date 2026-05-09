// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the StormDNS client.
// This file (api_handlers.go) implements the HTTP API endpoint handlers.
// ==============================================================================

package client

import (
	"net/http"
	"sort"
	"time"

	"range-scout/third_party/stormdns/internal/compression"
	"range-scout/third_party/stormdns/internal/security"
	"range-scout/third_party/stormdns/internal/version"
)

// ---------------------------------------------------------------------------
// GET /api/v1/status
// ---------------------------------------------------------------------------

type apiStatusResponse struct {
	Session  apiSessionInfo  `json:"session"`
	Version  string          `json:"version"`
	Protocol string          `json:"protocol"`
	Encryption apiEncryptionInfo `json:"encryption"`
	Compression apiCompressionInfo `json:"compression"`
	BaseEncoding bool        `json:"base_encoding"`
	MTU      apiMTUInfo      `json:"mtu"`
}

type apiSessionInfo struct {
	Ready         bool    `json:"ready"`
	ID            uint8   `json:"id"`
	UptimeSeconds float64 `json:"uptime_seconds"`
}

type apiEncryptionInfo struct {
	MethodID   int    `json:"method_id"`
	MethodName string `json:"method_name"`
}

type apiCompressionInfo struct {
	Upload   string `json:"upload"`
	Download string `json:"download"`
}

type apiMTUInfo struct {
	UploadBytes   int `json:"upload_bytes"`
	DownloadBytes int `json:"download_bytes"`
}

func (c *Client) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ready := c.sessionReady
	sessionID := c.sessionID

	var uptime float64
	if !c.startedAt.IsZero() {
		uptime = time.Since(c.startedAt).Seconds()
	}

	resp := apiStatusResponse{
		Session: apiSessionInfo{
			Ready:         ready,
			ID:            sessionID,
			UptimeSeconds: uptime,
		},
		Version:  version.GetVersion(),
		Protocol: c.cfg.ProtocolType,
		Encryption: apiEncryptionInfo{
			MethodID:   c.cfg.DataEncryptionMethod,
			MethodName: security.EncryptionMethodName(c.cfg.DataEncryptionMethod),
		},
		Compression: apiCompressionInfo{
			Upload:   compressionName(c.cfg.UploadCompressionType),
			Download: compressionName(c.cfg.DownloadCompressionType),
		},
		BaseEncoding: c.cfg.BaseEncodeData,
		MTU: apiMTUInfo{
			UploadBytes:   c.syncedUploadMTU,
			DownloadBytes: c.syncedDownloadMTU,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// GET /api/v1/traffic
// ---------------------------------------------------------------------------

type apiTrafficResponse struct {
	TXBytes           uint64  `json:"tx_bytes"`
	RXBytes           uint64  `json:"rx_bytes"`
	TXSpeedBytesPerSec float64  `json:"tx_speed_bytes_per_sec"`
	RXSpeedBytesPerSec float64  `json:"rx_speed_bytes_per_sec"`
	TXTotal           string  `json:"tx_total"`
	RXTotal           string  `json:"rx_total"`
	TXSpeed           string  `json:"tx_speed"`
	RXSpeed           string  `json:"rx_speed"`
}

func (c *Client) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentTX := c.txTotalBytes.Load()
	currentRX := c.rxTotalBytes.Load()
	now := time.Now()

	lastTX := c.apiLastTXBytes.Swap(currentTX)
	lastRX := c.apiLastRXBytes.Swap(currentRX)
	lastTime := c.apiLastSpeedTime.Swap(now.UnixNano())

	var upSpeed, downSpeed float64
	if lastTime > 0 {
		elapsed := time.Duration(now.UnixNano() - lastTime).Seconds()
		if elapsed > 0 {
			upSpeed = float64(currentTX-uint64(lastTX)) / elapsed
			downSpeed = float64(currentRX-uint64(lastRX)) / elapsed
		}
	}

	resp := apiTrafficResponse{
		TXBytes:           currentTX,
		RXBytes:           currentRX,
		TXSpeedBytesPerSec: upSpeed,
		RXSpeedBytesPerSec: downSpeed,
		TXTotal:           formatBytes(currentTX),
		RXTotal:           formatBytes(currentRX),
		TXSpeed:           formatSpeed(upSpeed),
		RXSpeed:           formatSpeed(downSpeed),
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// GET /api/v1/resolvers
// ---------------------------------------------------------------------------

type apiResolverEntry struct {
	Label           string  `json:"label"`
	Domain          string  `json:"domain"`
	IP              string  `json:"ip"`
	Port            int     `json:"port"`
	Valid           bool    `json:"valid"`
	Disabled        bool    `json:"disabled"`
	DisabledCause   string  `json:"disabled_cause,omitempty"`
	DisabledAt      string  `json:"disabled_at,omitempty"`
	NextRetryAt     string  `json:"next_retry_at,omitempty"`
	RTTMicros       int64   `json:"rtt_micros,omitempty"`
	PacketsSent     uint64  `json:"packets_sent"`
	PacketsAcked    uint64  `json:"packets_acked"`
	LossRate        float64 `json:"loss_rate"`
	UploadMTU       int     `json:"upload_mtu_bytes"`
	DownloadMTU     int     `json:"download_mtu_bytes"`
	LastSuccessAt   string  `json:"last_success_at,omitempty"`
	TimeoutCount    int     `json:"timeout_count"`
	TimeoutOnlySince string  `json:"timeout_only_since,omitempty"`
}

type apiResolversResponse struct {
	Total    int                `json:"total"`
	Valid    int                `json:"valid"`
	Disabled int                `json:"disabled"`
	Resolvers []apiResolverEntry `json:"resolvers"`
}

func (c *Client) handleResolvers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.resolverHealthMu.RLock()
	entries := make([]apiResolverEntry, 0, len(c.connections))
	validCount := 0
	disabledCount := 0

	for _, conn := range c.connections {
		key := conn.Key
		entry := apiResolverEntry{
			Label:       conn.ResolverLabel,
			Domain:      conn.Domain,
			IP:          conn.Resolver,
			Port:        conn.ResolverPort,
			Valid:       conn.IsValid,
			UploadMTU:   conn.UploadMTUBytes,
			DownloadMTU: conn.DownloadMTUBytes,
		}

		if conn.IsValid {
			validCount++
		}

		if health, ok := c.resolverHealth[key]; ok {
			entry.TimeoutCount = len(health.Events)
			if !health.LastSuccessAt.IsZero() {
				entry.LastSuccessAt = health.LastSuccessAt.Format(time.RFC3339)
			}
			if !health.TimeoutOnlySince.IsZero() {
				entry.TimeoutOnlySince = health.TimeoutOnlySince.Format(time.RFC3339)
			}
		}

		if disabled, ok := c.runtimeDisabled[key]; ok {
			entry.Disabled = true
			entry.DisabledCause = disabled.Cause
			entry.DisabledAt = disabled.DisabledAt.Format(time.RFC3339)
			entry.NextRetryAt = disabled.NextRetryAt.Format(time.RFC3339)
			disabledCount++
		}

		rtt, hasRTT := c.balancer.AverageRTT(key)
		if hasRTT {
			entry.RTTMicros = rtt.Microseconds()
		}

		if stats := c.balancer.StatsForKey(key); stats != nil {
			entry.PacketsSent = stats.Sent()
			entry.PacketsAcked = stats.Acked()
			if entry.PacketsSent > 0 {
				entry.LossRate = float64(entry.PacketsSent-entry.PacketsAcked) / float64(entry.PacketsSent)
			}
		}

		entries = append(entries, entry)
	}
	c.resolverHealthMu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Domain != entries[j].Domain {
			return entries[i].Domain < entries[j].Domain
		}
		return entries[i].Label < entries[j].Label
	})

	writeJSON(w, http.StatusOK, apiResolversResponse{
		Total:     len(entries),
		Valid:     validCount,
		Disabled:  disabledCount,
		Resolvers: entries,
	})
}

// ---------------------------------------------------------------------------
// GET /api/v1/streams
// ---------------------------------------------------------------------------

type apiStreamEntry struct {
	ID                   uint16 `json:"id"`
	Status               string `json:"status"`
	CreatedAt            string `json:"created_at,omitempty"`
	LastActivity         string `json:"last_activity,omitempty"`
	PreferredResolver    string `json:"preferred_resolver,omitempty"`
	ResendStreak         int    `json:"resend_streak"`
}

type apiStreamsResponse struct {
	Count   int              `json:"count"`
	Streams []apiStreamEntry `json:"streams"`
}

func (c *Client) handleStreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.streamsMu.RLock()
	entries := make([]apiStreamEntry, 0, len(c.active_streams))
	for _, s := range c.active_streams {
		if s == nil {
			continue
		}
		entry := apiStreamEntry{
			ID:                s.StreamID,
			Status:            s.StatusValue(),
			PreferredResolver: s.PreferredServerKey,
			ResendStreak:      s.ResolverResendStreak,
		}
		if !s.CreateTime.IsZero() {
			entry.CreatedAt = s.CreateTime.Format(time.RFC3339)
		}
		if !s.LastActivityTime.IsZero() {
			entry.LastActivity = s.LastActivityTime.Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}
	c.streamsMu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	writeJSON(w, http.StatusOK, apiStreamsResponse{
		Count:   len(entries),
		Streams: entries,
	})
}

// ---------------------------------------------------------------------------
// GET /api/v1/balancer
// ---------------------------------------------------------------------------

type apiBalancerResponse struct {
	Strategy        string `json:"strategy"`
	ValidConnections int   `json:"valid_connections"`
	BestConnection  string `json:"best_connection,omitempty"`
}

func (c *Client) handleBalancer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if c.balancer == nil {
		writeJSON(w, http.StatusOK, apiBalancerResponse{})
		return
	}

	resp := apiBalancerResponse{
		Strategy:        balancerStrategyName(c.cfg.ResolverBalancingStrategy),
		ValidConnections: c.balancer.ValidCount(),
	}

	if best, ok := c.balancer.GetBestConnection(); ok {
		resp.BestConnection = best.Key
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// GET /api/v1/mtu
// ---------------------------------------------------------------------------

type apiMTUDetailResponse struct {
	UploadBytes   int `json:"upload_bytes"`
	DownloadBytes int `json:"download_bytes"`
	UploadChars   int `json:"upload_chars"`
	MaxPackedBlocks int `json:"max_packed_blocks"`
	MinUpload     int `json:"min_upload"`
	MaxUpload     int `json:"max_upload"`
	MinDownload   int `json:"min_download"`
	MaxDownload   int `json:"max_download"`
	CryptoOverhead int `json:"crypto_overhead"`
}

func (c *Client) handleMTU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := apiMTUDetailResponse{
		UploadBytes:    c.syncedUploadMTU,
		DownloadBytes:  c.syncedDownloadMTU,
		UploadChars:    c.syncedUploadChars,
		MaxPackedBlocks: c.maxPackedBlocks,
		MinUpload:      c.cfg.MinUploadMTU,
		MaxUpload:      c.cfg.MaxUploadMTU,
		MinDownload:    c.cfg.MinDownloadMTU,
		MaxDownload:    c.cfg.MaxDownloadMTU,
		CryptoOverhead: c.mtuCryptoOverhead,
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// GET /api/v1/ping
// ---------------------------------------------------------------------------

type apiPingResponse struct {
	LastPingSentAt          string `json:"last_ping_sent_at,omitempty"`
	LastPongReceivedAt      string `json:"last_pong_received_at,omitempty"`
	LastNonPingSentAt       string `json:"last_non_ping_sent_at,omitempty"`
	LastNonPongReceivedAt   string `json:"last_non_pong_received_at,omitempty"`
	PingIntervalMode        string `json:"ping_interval_mode"`
}

func (c *Client) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if c.pingManager == nil {
		writeJSON(w, http.StatusOK, apiPingResponse{PingIntervalMode: "disabled"})
		return
	}

	pm := c.pingManager
	now := time.Now().UnixNano()

	lastPingSent := pm.lastPingSentAt.Load()
	lastPongRecv := pm.lastPongReceivedAt.Load()
	lastNonPingSent := pm.lastNonPingSentAt.Load()
	lastNonPongRecv := pm.lastNonPongReceivedAt.Load()

	mode := pingIntervalMode(
		now,
		lastPingSent, lastPongRecv,
		lastNonPingSent, lastNonPongRecv,
		c.cfg.PingWarmThreshold(),
		c.cfg.PingCoolThreshold(),
		c.cfg.PingColdThreshold(),
	)

	resp := apiPingResponse{
		PingIntervalMode: mode,
	}
	if lastPingSent > 0 {
		resp.LastPingSentAt = time.Unix(0, lastPingSent).Format(time.RFC3339)
	}
	if lastPongRecv > 0 {
		resp.LastPongReceivedAt = time.Unix(0, lastPongRecv).Format(time.RFC3339)
	}
	if lastNonPingSent > 0 {
		resp.LastNonPingSentAt = time.Unix(0, lastNonPingSent).Format(time.RFC3339)
	}
	if lastNonPongRecv > 0 {
		resp.LastNonPongReceivedAt = time.Unix(0, lastNonPongRecv).Format(time.RFC3339)
	}

	writeJSON(w, http.StatusOK, resp)
}

func pingIntervalMode(now int64, lastPingSent, lastPongRecv, lastNonPingSent, lastNonPongRecv int64, warmThreshold, coolThreshold, coldThreshold time.Duration) string {
	lastActivity := lastNonPingSent
	if lastNonPongRecv > lastActivity {
		lastActivity = lastNonPongRecv
	}
	timeSinceActivity := now - lastActivity
	_ = lastPingSent
	_ = lastPongRecv

	if timeSinceActivity < int64(warmThreshold) {
		return "aggressive"
	}
	if timeSinceActivity < int64(coolThreshold) {
		return "lazy"
	}
	return "cold"
}

// ---------------------------------------------------------------------------
// GET /api/v1/socks
// ---------------------------------------------------------------------------

type apiSocksResponse struct {
	ActiveConnections int `json:"active_connections"`
	BlockedIPs        int `json:"blocked_ips"`
}

func (c *Client) handleSocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	c.streamsMu.RLock()
	activeCount := 0
	for _, s := range c.active_streams {
		if s != nil && s.StatusValue() == streamStatusActive {
			activeCount++
		}
	}
	c.streamsMu.RUnlock()

	blockedCount := 0
	if c.socksRateLimit != nil {
		blockedCount = c.socksRateLimit.BlockedCount()
	}

	writeJSON(w, http.StatusOK, apiSocksResponse{
		ActiveConnections: activeCount,
		BlockedIPs:        blockedCount,
	})
}

// ---------------------------------------------------------------------------
// GET /api/v1/version
// ---------------------------------------------------------------------------

type apiVersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time,omitempty"`
}

func (c *Client) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, apiVersionResponse{
		Version: version.GetVersion(),
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/stop
// ---------------------------------------------------------------------------

func (c *Client) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	select {
	case c.apiWriteCh <- apiCmdStop:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "message": "shutting down"})
	default:
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/restart-session
// ---------------------------------------------------------------------------

func (c *Client) handleRestartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	select {
	case c.apiWriteCh <- apiCmdRestartSession:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "message": "restarting session"})
	default:
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/restart
// ---------------------------------------------------------------------------

func (c *Client) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	select {
	case c.apiWriteCh <- apiCmdRestartProcess:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted", "message": "restarting process"})
	default:
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func compressionName(t int) string {
	switch t {
	case compression.TypeZSTD:
		return "ZSTD"
	case compression.TypeLZ4:
		return "LZ4"
	case compression.TypeZLIB:
		return "ZLIB"
	default:
		return "OFF"
	}
}

func balancerStrategyName(s int) string {
	switch s {
	case BalancingRoundRobinDefault, BalancingRoundRobin:
		return "round_robin"
	case BalancingRandom:
		return "random"
	case BalancingLeastLoss:
		return "least_loss"
	case BalancingLowestLatency:
		return "lowest_latency"
	default:
		return "unknown"
	}
}
