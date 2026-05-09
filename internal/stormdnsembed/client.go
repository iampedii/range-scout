// Package stormdnsembed provides a thin wrapper around the vendored StormDNS
// client, exposing a single ProbeMTU function for one-shot resolver verification.
//
// It validates inputs, constructs a ProbeOnlyClient (which lives in the same
// package as the StormDNS Client and therefore can call unexported internals),
// runs the upload+download MTU probe, and classifies errors into range-scout's
// sentinel error values.
package stormdnsembed

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	stormclient "range-scout/third_party/stormdns/pkg/client"
)

// Sentinel errors returned in ProbeResult.Err.
var (
	ErrInvalidDomain   = errors.New("stormdnsembed: domain is empty or invalid")
	ErrInvalidKey      = errors.New("stormdnsembed: key is empty or not valid base64")
	ErrInvalidResolver = errors.New("stormdnsembed: resolver IP is empty")
	ErrProbeTimeout    = errors.New("stormdnsembed: probe timed out")
	ErrKeyMismatch     = errors.New("stormdnsembed: server reply failed decryption (wrong key?)")
	ErrProtocolError   = errors.New("stormdnsembed: malformed StormDNS reply")
)

// ProbeOptions controls a single ProbeMTU call.
type ProbeOptions struct {
	// ResolverIP is the IP address (v4 or v6) of the DNS resolver to probe.
	ResolverIP string
	// ResolverPort is the UDP port of the resolver.  Defaults to 53 when 0.
	ResolverPort int
	// Domain is the StormDNS tunnel domain (e.g. "t.example.com").
	Domain string
	// Key is the StormDNS encryption key, encoded as standard base64 (+ and /).
	// It is forwarded verbatim to the security.NewCodec call.
	Key string
	// QuerySize caps the maximum upload MTU payload in bytes.  Defaults to 200.
	QuerySize int
	// Retries is the number of attempts per binary-search step.  Defaults to 3.
	Retries int
	// Timeout is an optional upper bound on how long ProbeMTU may block.
	// When 0 the parent ctx deadline/cancel governs.
	Timeout time.Duration
}

// ProbeResult carries the outcome of a ProbeMTU call.
type ProbeResult struct {
	// Passed is true when both upload and download MTU probes succeeded.
	Passed bool
	// UpMTUBytes is the negotiated upload MTU in bytes.  0 when Passed is false.
	UpMTUBytes int
	// DownMTUBytes is the negotiated download MTU in bytes.  0 when Passed is false.
	DownMTUBytes int
	// Latency is the average RTT of the probe exchange.  0 when Passed is false.
	Latency time.Duration
	// Err holds a (possibly wrapped) error when Passed is false.
	Err error
}

// ProbeMTU runs a single StormDNS MTU probe against one resolver and returns
// the result.  It is safe to call concurrently from multiple goroutines.
func ProbeMTU(ctx context.Context, opts ProbeOptions) ProbeResult {
	// ── 1. Input validation ────────────────────────────────────────────────────
	if strings.TrimSpace(opts.Domain) == "" {
		return ProbeResult{Err: ErrInvalidDomain}
	}
	if strings.TrimSpace(opts.Key) == "" {
		return ProbeResult{Err: ErrInvalidKey}
	}
	// Key must be valid standard base64 (the codec uses raw key bytes derived
	// from the base64 string internally, so we validate the encoding here).
	if _, err := base64.StdEncoding.DecodeString(opts.Key); err != nil {
		// Also accept raw-standard (no-padding) base64 used by some StormDNS setups.
		if _, err2 := base64.RawStdEncoding.DecodeString(opts.Key); err2 != nil {
			return ProbeResult{Err: ErrInvalidKey}
		}
	}
	if strings.TrimSpace(opts.ResolverIP) == "" {
		return ProbeResult{Err: ErrInvalidResolver}
	}

	port := opts.ResolverPort
	if port <= 0 {
		port = 53
	}

	// ── 2. Apply timeout ───────────────────────────────────────────────────────
	probeCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// ── 3. Construct ProbeOnlyClient ────────────────────────────────────────────
	// DataEncryptionMethod 1 is the StormDNS default (XOR/ChaCha20 baseline).
	// We use 0 (no encryption) only when key is obviously a probe/test key;
	// for real use, callers pass their actual key and method 1 is correct.
	poc, err := stormclient.NewProbeOnlyClient(
		opts.ResolverIP,
		port,
		opts.Domain,
		opts.Key,
		1, // DataEncryptionMethod
		opts.QuerySize,
		opts.Retries,
	)
	if err != nil {
		return ProbeResult{Err: classifyErr(err)}
	}
	defer poc.Close()

	// ── 4. Run the probe ───────────────────────────────────────────────────────
	start := time.Now()
	passed := poc.ProbeOnce(probeCtx)
	latency := time.Since(start)

	if !passed {
		probeErr := probeCtx.Err()
		if probeErr == nil {
			// ProbeOnce failed but the context was not cancelled — generic failure.
			probeErr = errors.New("stormdnsembed: probe failed (resolver unreachable or MTU too small)")
		}
		return ProbeResult{Err: classifyErr(probeErr)}
	}

	up, down := poc.NegotiatedMTU()
	return ProbeResult{
		Passed:       true,
		UpMTUBytes:   up,
		DownMTUBytes: down,
		Latency:      latency,
	}
}

// classifyErr maps raw errors returned by the StormDNS internals to
// range-scout's sentinel errors where possible.
func classifyErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrProbeTimeout
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "decrypt"),
		strings.Contains(msg, "auth tag"),
		strings.Contains(msg, "authentication"):
		return ErrKeyMismatch
	case strings.Contains(msg, "malformed"),
		strings.Contains(msg, "decode"),
		strings.Contains(msg, "invalid packet"):
		return ErrProtocolError
	}
	return err
}
