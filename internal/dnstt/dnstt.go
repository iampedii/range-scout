package dnstt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"range-scout/internal/model"
)

const (
	defaultEDNSBufSize = 1232
	localSocksBasePort = 10800
)

type Config struct {
	Workers    int
	Timeout    time.Duration
	E2ETimeout time.Duration
	Port       int
	Domain     string
	Pubkey     string
	QuerySize  int
	E2EPort    int
	BinaryPath string
}

type Summary struct {
	Candidates uint64
	Checked    uint64
	TunnelOK   uint64
	E2EOK      uint64
	StartedAt  time.Time
	FinishedAt time.Time
}

type EventType string

const (
	EventProgress EventType = "progress"
	EventResolver EventType = "resolver"
)

type Event struct {
	Type    EventType
	Tested  uint64
	Total   uint64
	Tunnel  uint64
	E2E     uint64
	Item    *model.Resolver
	Summary Summary
}

func Test(
	ctx context.Context,
	resolvers []model.Resolver,
	cfg Config,
	emit func(Event),
) ([]model.Resolver, Summary, error) {
	cfg, binaryPath, candidates, err := prepareConfig(resolvers, cfg)
	if err != nil {
		return nil, Summary{}, err
	}

	updated := append([]model.Resolver(nil), resolvers...)
	summary := Summary{
		Candidates: uint64(len(candidates)),
		StartedAt:  time.Now(),
	}

	jobs := make(chan int, len(candidates))
	var tested atomic.Uint64
	var tunnelOK atomic.Uint64
	var e2eOK atomic.Uint64

	portPool := make(chan int, cfg.Workers)
	if strings.TrimSpace(cfg.Pubkey) != "" {
		for index := 0; index < cfg.Workers; index++ {
			portPool <- localSocksBasePort + index
		}
	}

	for _, index := range candidates {
		jobs <- index
	}
	close(jobs)

	var workerWG sync.WaitGroup
	for workerID := 0; workerID < cfg.Workers; workerID++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}

				resolver := runResolverCheck(ctx, updated[index], cfg, binaryPath, portPool)
				updated[index] = resolver

				currentTested := tested.Add(1)
				if resolver.DNSTTTunnelOK {
					tunnelOK.Add(1)
				}
				if resolver.DNSTTE2EOK {
					e2eOK.Add(1)
				}

				currentSummary := Summary{
					Candidates: summary.Candidates,
					Checked:    currentTested,
					TunnelOK:   tunnelOK.Load(),
					E2EOK:      e2eOK.Load(),
					StartedAt:  summary.StartedAt,
				}

				if emit != nil {
					copyResolver := resolver
					emit(Event{
						Type:    EventResolver,
						Tested:  currentTested,
						Total:   summary.Candidates,
						Tunnel:  currentSummary.TunnelOK,
						E2E:     currentSummary.E2EOK,
						Item:    &copyResolver,
						Summary: currentSummary,
					})
					emit(Event{
						Type:    EventProgress,
						Tested:  currentTested,
						Total:   summary.Candidates,
						Tunnel:  currentSummary.TunnelOK,
						E2E:     currentSummary.E2EOK,
						Summary: currentSummary,
					})
				}
			}
		}()
	}

	workerWG.Wait()

	summary.Checked = tested.Load()
	summary.TunnelOK = tunnelOK.Load()
	summary.E2EOK = e2eOK.Load()
	summary.FinishedAt = time.Now()

	if errorsIsCanceled(ctx) {
		return updated, summary, ctx.Err()
	}
	return updated, summary, nil
}

func EligibleResolvers(resolvers []model.Resolver) []int {
	indexes := make([]int, 0, len(resolvers))
	for index, resolver := range resolvers {
		if resolver.RecursionAvailable && resolver.Stable {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func FindClientBinary() (string, error) {
	return findBinary("dnstt-client")
}

func prepareConfig(resolvers []model.Resolver, cfg Config) (Config, string, []int, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Timeout <= 0 {
		return Config{}, "", nil, fmt.Errorf("dnstt timeout must be greater than zero")
	}
	if cfg.Port <= 0 {
		cfg.Port = 53
	}
	cfg.Domain = dns.Fqdn(strings.TrimSpace(cfg.Domain))
	if cfg.Domain == "." {
		return Config{}, "", nil, fmt.Errorf("dnstt domain is required")
	}
	if cfg.QuerySize < 0 {
		return Config{}, "", nil, fmt.Errorf("dnstt query size must be zero or greater")
	}

	candidates := EligibleResolvers(resolvers)
	if len(candidates) == 0 {
		return Config{}, "", nil, fmt.Errorf("no healthy recursive resolvers are available for DNSTT testing")
	}

	binaryPath := strings.TrimSpace(cfg.BinaryPath)
	if strings.TrimSpace(cfg.Pubkey) != "" {
		if cfg.E2ETimeout <= 0 {
			return Config{}, "", nil, fmt.Errorf("dnstt e2e timeout must be greater than zero")
		}
		if cfg.E2EPort <= 0 {
			cfg.E2EPort = 53
		}
		if cfg.E2EPort > 65535 {
			return Config{}, "", nil, fmt.Errorf("dnstt e2e port must be between 1 and 65535")
		}
		if binaryPath == "" {
			var err error
			binaryPath, err = findBinary("dnstt-client")
			if err != nil {
				return Config{}, "", nil, err
			}
		}
	}

	return cfg, binaryPath, candidates, nil
}

func runResolverCheck(ctx context.Context, resolver model.Resolver, cfg Config, binaryPath string, ports chan int) model.Resolver {
	resolver.DNSTTChecked = true
	resolver.DNSTTTunnelOK = false
	resolver.DNSTTE2EOK = false
	resolver.DNSTTTunnelMillis = 0
	resolver.DNSTTE2EMillis = 0
	resolver.DNSTTError = ""

	tunnelOK, tunnelMS, tunnelErr := tunnelCheck(ctx, resolver.IP, cfg.Port, cfg.Domain, cfg.Timeout)
	if tunnelMS > 0 {
		resolver.DNSTTTunnelMillis = tunnelMS
	}
	if tunnelErr != nil {
		resolver.DNSTTError = tunnelErr.Error()
		return resolver
	}
	if !tunnelOK {
		resolver.DNSTTError = "dnstt tunnel precheck failed"
		return resolver
	}
	resolver.DNSTTTunnelOK = true

	if strings.TrimSpace(cfg.Pubkey) == "" {
		return resolver
	}

	e2eOK, e2eMS, e2eErr := dnsttCheck(ctx, binaryPath, resolver.IP, cfg.Port, cfg.Domain, cfg.Pubkey, cfg.E2ETimeout, cfg.QuerySize, cfg.E2EPort, ports)
	if e2eMS > 0 {
		resolver.DNSTTE2EMillis = e2eMS
	}
	if e2eErr != nil {
		resolver.DNSTTError = e2eErr.Error()
		return resolver
	}
	if !e2eOK {
		resolver.DNSTTError = "dnstt e2e check failed"
		return resolver
	}

	resolver.DNSTTE2EOK = true
	resolver.DNSTTError = ""
	return resolver
}

func tunnelCheck(ctx context.Context, resolverIP string, port int, domain string, timeout time.Duration) (bool, int64, error) {
	qname := fmt.Sprintf("tun-%s.%s", randLabel(8), strings.TrimSuffix(domain, "."))
	start := time.Now()
	response, ok := queryRaw(ctx, resolverIP, port, qname, dns.TypeTXT, timeout)
	latencyMS := roundMillis(time.Since(start))
	if !ok || response == nil {
		return false, latencyMS, fmt.Errorf("dnstt tunnel query timed out")
	}
	switch response.Rcode {
	case dns.RcodeServerFailure, dns.RcodeRefused:
		return false, latencyMS, fmt.Errorf("resolver returned %s for tunnel query", dns.RcodeToString[response.Rcode])
	default:
		return true, latencyMS, nil
	}
}

func dnsttCheck(ctx context.Context, binaryPath, resolverIP string, resolverPort int, domain, pubkey string, timeout time.Duration, querySize int, e2ePort int, ports chan int) (bool, int64, error) {
	if binaryPath == "" {
		return false, 0, fmt.Errorf("dnstt-client binary is required for e2e testing")
	}

	var port int
	select {
	case port = <-ports:
	case <-ctx.Done():
		return false, 0, ctx.Err()
	}
	defer func() {
		ports <- port
	}()

	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var stderr bytes.Buffer

	args := []string{
		"-udp", net.JoinHostPort(resolverIP, fmt.Sprintf("%d", resolverPort)),
		"-pubkey", pubkey,
	}
	if querySize > 0 {
		args = append(args, "-mtu", fmt.Sprintf("%d", querySize))
	}
	args = append(args, domain, fmt.Sprintf("127.0.0.1:%d", port))

	cmd := exec.CommandContext(checkCtx, binaryPath, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return false, 0, fmt.Errorf("start dnstt-client: %w", err)
	}

	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}()

	if err := waitAndTestSOCKS5Connect(checkCtx, port, resolverIP, e2ePort, exited); err != nil {
		select {
		case err := <-exited:
			if err != nil {
				stderrText := strings.TrimSpace(stderr.String())
				if stderrText != "" {
					return false, roundMillis(time.Since(start)), fmt.Errorf("dnstt-client failed: %s", truncate(stderrText, 220))
				}
				return false, roundMillis(time.Since(start)), fmt.Errorf("dnstt-client exited early: %v", err)
			}
		default:
		}
		if checkCtx.Err() != nil {
			return false, roundMillis(time.Since(start)), fmt.Errorf("dnstt e2e timed out")
		}
		return false, roundMillis(time.Since(start)), err
	}

	return true, roundMillis(time.Since(start)), nil
}

func waitAndTestSOCKS5Connect(ctx context.Context, port int, targetHost string, targetPort int, exited <-chan error) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}

		select {
		case <-exited:
			return fmt.Errorf("dnstt-client exited before socks5 handshake")
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			continue
		}

		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}

		if _, err := performSOCKS5Greeting(conn); err != nil {
			_ = conn.Close()
			return err
		}

		connectReq, err := buildSOCKS5ConnectRequest(targetHost, targetPort)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if _, err := conn.Write(connectReq); err != nil {
			_ = conn.Close()
			return fmt.Errorf("socks5 connect write failed: %w", err)
		}

		connectResp := make([]byte, 4)
		if _, err := io.ReadFull(conn, connectResp); err != nil {
			_ = conn.Close()
			return formatSOCKS5ConnectReplyError(err)
		}
		_ = conn.Close()
		if connectResp[0] != 0x05 {
			return fmt.Errorf("socks5 connect reply had invalid version 0x%02x", connectResp[0])
		}
		return nil
	}
}

func formatSOCKS5ConnectReplyError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("no CONNECT reply from tunnel")
	}
	return fmt.Errorf("socks5 connect reply failed: %w", err)
}

func performSOCKS5Greeting(conn net.Conn) (byte, error) {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return 0, fmt.Errorf("socks5 greeting failed: %w", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return 0, fmt.Errorf("socks5 greeting reply failed: %w", err)
	}
	if response[0] != 0x05 {
		return 0, fmt.Errorf("socks5 greeting reply had invalid version 0x%02x", response[0])
	}
	return response[1], nil
}

func buildSOCKS5ConnectRequest(host string, port int) ([]byte, error) {
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("dnstt e2e target host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("dnstt e2e port must be between 1 and 65535")
	}

	request := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		request = append(request, 0x01)
		request = append(request, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		request = append(request, 0x04)
		request = append(request, ip.To16()...)
	default:
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("dnstt e2e target host must be between 1 and 255 bytes")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}

	request = append(request, byte(port>>8), byte(port))
	return request, nil
}

func queryRaw(ctx context.Context, resolver string, port int, domain string, qtype uint16, timeout time.Duration) (*dns.Msg, bool) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), qtype)
	message.RecursionDesired = true
	message.SetEdns0(defaultEDNSBufSize, false)

	addr := net.JoinHostPort(resolver, fmt.Sprintf("%d", port))
	client := &dns.Client{Net: "udp", Timeout: timeout}
	deadline := time.Now().Add(timeout * 2)

	remaining := func() time.Duration {
		left := time.Until(deadline)
		if left < 500*time.Millisecond {
			return 500 * time.Millisecond
		}
		return left
	}

	exchange := func(client *dns.Client, message *dns.Msg) (*dns.Msg, error) {
		queryCtx, cancel := context.WithTimeout(ctx, remaining())
		defer cancel()
		response, _, err := client.ExchangeContext(queryCtx, message, addr)
		return response, err
	}

	response, err := exchange(client, message)
	ednsRetry := func() bool {
		savedExtra := message.Extra
		message.Extra = nil
		retryResponse, retryErr := exchange(client, message)
		if retryErr == nil && retryResponse != nil {
			response = retryResponse
			err = nil
			return true
		}
		message.Extra = savedExtra
		return false
	}

	if err == nil && response != nil && response.Rcode != dns.RcodeSuccess {
		ednsRetry()
	}

	if err != nil || response == nil {
		client.Net = "tcp"
		response, err = exchange(client, message)
		if err != nil || response == nil {
			message.Extra = nil
			response, err = exchange(client, message)
			if err != nil || response == nil {
				return nil, false
			}
		}
		if response != nil && response.Rcode != dns.RcodeSuccess && len(message.Extra) > 0 {
			ednsRetry()
		}
	}

	if response.Truncated {
		client.Net = "tcp"
		response, err = exchange(client, message)
		if err != nil || response == nil {
			return nil, false
		}
	}

	return response, true
}

func platformVariants(name string) []string {
	variants := []string{name}
	switch runtime.GOOS {
	case "windows":
		if filepath.Ext(name) == "" {
			variants = []string{name + ".exe", name}
		}
	case "linux":
		variants = append(variants, name+"-linux")
	case "darwin":
		variants = append(variants, name+"-darwin")
	}
	return variants
}

func findBinary(name string) (string, error) {
	variants := platformVariants(name)

	for _, variant := range variants {
		if path, err := exec.LookPath(variant); err == nil {
			return path, nil
		}
	}

	for _, variant := range variants {
		if abs, err := filepath.Abs(variant); err == nil {
			if info, err := os.Stat(abs); err == nil && isExecutable(info) {
				return abs, nil
			}
		}
	}

	if executable, err := os.Executable(); err == nil {
		for _, variant := range variants {
			candidate := filepath.Join(filepath.Dir(executable), variant)
			if info, err := os.Stat(candidate); err == nil && isExecutable(info) {
				return candidate, nil
			}
		}
	}

	pathHelp := fmt.Sprintf("  2. Move it to a folder in PATH:  sudo mv %s /usr/local/bin/\n  3. Or add current directory to PATH:  export PATH=$PATH:$(pwd)", name)
	if runtime.GOOS == "windows" {
		pathHelp = "  2. Or add the folder to PATH:  set PATH=%PATH%;%cd%"
	}

	return "", fmt.Errorf(
		"%s not found in PATH, current directory, or next to the range-scout binary.\n\nInstall with Go:\n  go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest\n\nIf already downloaded, either:\n  1. Place it next to the range-scout executable\n%s",
		name,
		pathHelp,
	)
}

func isExecutable(info os.FileInfo) bool {
	if info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

func randLabel(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	value := make([]byte, n)
	for i := range value {
		value[i] = chars[rand.Intn(len(chars))]
	}
	return string(value)
}

func roundMillis(duration time.Duration) int64 {
	return duration.Milliseconds()
}

func truncate(text string, max int) string {
	if max <= 0 || len(text) <= max {
		return text
	}
	return text[:max] + "..."
}

func errorsIsCanceled(ctx context.Context) bool {
	return ctx.Err() != nil && ctx.Err() == context.Canceled
}
