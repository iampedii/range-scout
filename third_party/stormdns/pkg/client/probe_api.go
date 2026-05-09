// ==============================================================================
// probe_api.go — range-scout-specific addition to the vendored StormDNS client.
//
// This file is NOT part of upstream StormDNS.  It MUST be re-applied verbatim
// on every re-sync (see third_party/stormdns/SYNC.md, patch #6).
//
// Design choice: ProbeOnlyClient lives in the same package as Client so it can
// call the unexported probeConnectionMTU directly, without modifying upstream
// types.  An exported pass-through method (Client.RunProbeOnce) is added for
// the same reason — it delegates to the unexported method.
// ==============================================================================

package client

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"range-scout/third_party/stormdns/internal/config"
	"range-scout/third_party/stormdns/internal/logger"
	"range-scout/third_party/stormdns/internal/security"
)

// ProbeOnlyClient wraps a minimal StormDNS Client configured for a single
// one-shot MTU probe.  No balancer goroutines, no SOCKS5 listener, no health
// loop, and no session are ever started.
type ProbeOnlyClient struct {
	c       *Client
	conn    Connection
	mu      sync.Mutex
	lastErr error
}

// NewProbeOnlyClient constructs a ProbeOnlyClient for the given resolver and
// domain.  querySize and retries correspond to the upload payload ceiling and
// the number of probe attempts per binary-search step.  Pass 0 for querySize
// to use the upstream default cap (200 bytes).
func NewProbeOnlyClient(
	resolverIP string,
	resolverPort int,
	domain string,
	key string,
	encryptionMethod int,
	querySize int,
	retries int,
) (*ProbeOnlyClient, error) {
	if resolverIP == "" {
		return nil, fmt.Errorf("probe_api: resolver IP must not be empty")
	}
	if domain == "" {
		return nil, fmt.Errorf("probe_api: domain must not be empty")
	}
	if key == "" {
		return nil, fmt.Errorf("probe_api: encryption key must not be empty")
	}

	if querySize <= 0 {
		querySize = 200
	}
	if retries <= 0 {
		retries = 3
	}

	// Build a minimal ClientConfig — all listeners and goroutine-heavy features
	// are left at their zero/false values so Run() is never needed.
	cfg := config.ClientConfig{
		Domains:               []string{domain},
		EncryptionKey:         key,
		DataEncryptionMethod:  encryptionMethod,
		MaxUploadMTU:          querySize,
		MinUploadMTU:          10,
		MaxDownloadMTU:        4000,
		MinDownloadMTU:        100,
		MTUTestRetries:        retries,
		MTUTestTimeout:        2.0,
		MTUTestParallelism:    1,
		ResolverBalancingStrategy: 0,
		RecheckBatchSize:      1,
		LocalDNSCacheMaxRecords:   100,
		LocalDNSCacheTTLSeconds:   3600,
		LocalDNSPendingTimeoutSec: 60,
		LocalDNSCacheFlushSec:     60,
		TXChannelSize:         64,
		RXChannelSize:         64,
		ResolverUDPConnectionPoolSize: 1,
		StreamQueueInitialCapacity:    8,
		OrphanQueueInitialCapacity:    4,
		DNSResponseFragmentStoreCap:   16,
		DNSResponseFragmentTimeoutSeconds: 10,
		RX_TX_Workers:         1,
		TunnelProcessWorkers:  1,
		TunnelPacketTimeoutSec: 8,
		LogLevel:              "ERROR",
		Resolvers: []config.ResolverAddress{
			{IP: resolverIP, Port: resolverPort},
		},
		ResolverMap: map[string]int{resolverIP: resolverPort},
	}
	// Set active MTU trio directly (normally done by ApplyStartupModeMTU).
	cfg.MTUTestRetries = retries
	cfg.MTUTestTimeout = 2.0
	cfg.MTUTestParallelism = 1

	log := logger.New("StormDNS-Probe", "ERROR")

	codec, err := security.NewCodec(encryptionMethod, key)
	if err != nil {
		return nil, fmt.Errorf("probe_api: codec setup: %w", err)
	}

	c := New(cfg, log, codec)

	// Manually build connection map without touching the filesystem or goroutines.
	if err := c.BuildConnectionMap(); err != nil {
		return nil, fmt.Errorf("probe_api: build connection map: %w", err)
	}
	if len(c.connections) == 0 {
		return nil, fmt.Errorf("probe_api: no connections built")
	}

	return &ProbeOnlyClient{
		c:    c,
		conn: c.connections[0],
	}, nil
}

// ProbeOnce runs a single upload+download MTU probe against the configured
// resolver/domain pair.  Returns true when both directions pass.
// On success the connection's UploadMTUBytes / DownloadMTUBytes are populated.
func (p *ProbeOnlyClient) ProbeOnce(ctx context.Context) bool {
	if p == nil || p.c == nil {
		p.setLastErr(errors.New("probe failed: nil client"))
		return false
	}
	// Determine max upload payload cap for this domain.
	maxUpload := p.c.maxUploadMTUPayload(p.conn.Domain)
	if maxUpload <= 0 {
		maxUpload = p.c.cfg.MaxUploadMTU
	}
	conn := p.conn
	result, reason := p.c.probeConnectionMTU(ctx, &conn, maxUpload)
	if reason != mtuRejectNone {
		// Capture the failure reason in lastErr
		var err error
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		} else {
			err = fmt.Errorf("probe failed: rejection reason %d", reason)
		}
		p.setLastErr(err)
		return false
	}
	// Store results back so NegotiatedMTU can read them.
	p.conn.IsValid = true
	p.conn.UploadMTUBytes = result.UploadBytes
	p.conn.UploadMTUChars = result.UploadChars
	p.conn.DownloadMTUBytes = result.DownloadBytes
	p.conn.MTUResolveTime = result.ResolveTime
	p.setLastErr(nil)
	return true
}

// setLastErr stores the error under the mutex lock.
func (p *ProbeOnlyClient) setLastErr(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastErr = err
}

// NegotiatedMTU returns the upload and download MTU values discovered by the
// most recent successful ProbeOnce call.  Both values are 0 until a probe
// succeeds.
func (p *ProbeOnlyClient) NegotiatedMTU() (up, down int) {
	if p == nil {
		return 0, 0
	}
	return p.conn.UploadMTUBytes, p.conn.DownloadMTUBytes
}

// LastProbeError returns the last error from ProbeOnce, or nil if the most
// recent probe succeeded.
func (p *ProbeOnlyClient) LastProbeError() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}

// Close is a no-op for ProbeOnlyClient (no goroutines or connections are held
// open between probes) but satisfies the io.Closer interface for callers that
// want uniform resource cleanup.
func (p *ProbeOnlyClient) Close() error {
	return nil
}

// RunProbeOnce is an exported pass-through on *Client that calls the unexported
// probeConnectionMTU.  It exists so external packages that hold a *Client and
// want to drive a fresh probe do not need to go through ProbeOnlyClient.
// ProbeOnlyClient itself calls probeConnectionMTU directly.
func (c *Client) RunProbeOnce(ctx context.Context, conn *Connection, maxUploadPayload int) (upMTU, downMTU int, ok bool) {
	if c == nil || conn == nil {
		return 0, 0, false
	}
	result, reason := c.probeConnectionMTU(ctx, conn, maxUploadPayload)
	if reason != mtuRejectNone {
		return 0, 0, false
	}
	return result.UploadBytes, result.DownloadBytes, true
}
