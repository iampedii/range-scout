package dnstt

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"

	embed "range-scout/internal/dnsttembed"
	"range-scout/internal/model"
)

const (
	defaultEDNSBufSize = 1232
	localSocksBasePort = 10800
	DefaultE2ETestURL  = "http://www.gstatic.com/generate_204"
)

type Config struct {
	Workers        int
	Timeout        time.Duration
	E2ETimeout     time.Duration
	Port           int
	Domain         string
	Pubkey         string
	QuerySize      int
	E2EURL         string
	ScoreThreshold int
	TestNearbyIPs  bool
	BasePrefixes   []string
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

type embeddedClient interface {
	SetAuthoritativeMode(bool)
	SetMaxPayload(int)
	Start() error
	Stop()
	IsRunning() bool
}

var newEmbeddedClient = func(dnsAddr, tunnelDomain, publicKey, listenAddr string) (embeddedClient, error) {
	return embed.NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr)
}

var runTunnelCheck = tunnelCheck

func Test(
	ctx context.Context,
	resolvers []model.Resolver,
	cfg Config,
	emit func(Event),
) ([]model.Resolver, Summary, error) {
	cfg, candidates, err := prepareConfig(resolvers, cfg)
	if err != nil {
		return nil, Summary{}, err
	}

	updated := append([]model.Resolver(nil), resolvers...)
	for index, resolver := range updated {
		updated[index] = resetResolverState(resolver)
	}
	summary := Summary{
		Candidates: uint64(len(candidates)),
		StartedAt:  time.Now(),
	}
	basePrefixes := parseBasePrefixes(cfg.BasePrefixes, updated)

	var tested atomic.Uint64
	var tunnelOK atomic.Uint64
	var e2eOK atomic.Uint64

	portPool := make(chan int, cfg.Workers)
	if strings.TrimSpace(cfg.Pubkey) != "" {
		for index := 0; index < cfg.Workers; index++ {
			portPool <- localSocksBasePort + index
		}
	}

	runCandidateBatch(ctx, updated, candidates, cfg, portPool, summary.Candidates, &tested, &tunnelOK, &e2eOK, summary.StartedAt, emit)

	if ctx.Err() == nil && cfg.TestNearbyIPs {
		nearbyResolvers := collectNearbyResolvers(updated, candidates, strings.TrimSpace(cfg.Pubkey) != "", basePrefixes)
		if len(nearbyResolvers) > 0 {
			startIndex := len(updated)
			updated = append(updated, nearbyResolvers...)

			nearbyIndexes := make([]int, 0, len(nearbyResolvers))
			for index := range nearbyResolvers {
				nearbyIndexes = append(nearbyIndexes, startIndex+index)
			}
			summary.Candidates += uint64(len(nearbyIndexes))
			emitProgress(emit, summary.Candidates, tested.Load(), tunnelOK.Load(), e2eOK.Load(), summary.StartedAt)
			runCandidateBatch(ctx, updated, nearbyIndexes, cfg, portPool, summary.Candidates, &tested, &tunnelOK, &e2eOK, summary.StartedAt, emit)
		}
	}

	summary.Checked = tested.Load()
	summary.TunnelOK = tunnelOK.Load()
	summary.E2EOK = e2eOK.Load()
	summary.FinishedAt = time.Now()

	if errorsIsCanceled(ctx) {
		return updated, summary, ctx.Err()
	}
	return updated, summary, nil
}

func EligibleResolvers(resolvers []model.Resolver, scoreThreshold int) []int {
	indexes := make([]int, 0, len(resolvers))
	scoreThreshold = normalizeScoreThreshold(scoreThreshold)
	for index, resolver := range resolvers {
		if resolver.TunnelScore >= scoreThreshold {
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func prepareConfig(resolvers []model.Resolver, cfg Config) (Config, []int, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Timeout <= 0 {
		return Config{}, nil, fmt.Errorf("dnstt timeout must be greater than zero")
	}
	if cfg.Port <= 0 {
		cfg.Port = 53
	}
	cfg.Domain = dns.Fqdn(strings.TrimSpace(cfg.Domain))
	if cfg.Domain == "." {
		return Config{}, nil, fmt.Errorf("dnstt domain is required")
	}
	if cfg.QuerySize < 0 {
		return Config{}, nil, fmt.Errorf("dnstt query size must be zero or greater")
	}
	cfg.ScoreThreshold = normalizeScoreThreshold(cfg.ScoreThreshold)

	candidates := EligibleResolvers(resolvers, cfg.ScoreThreshold)
	if len(candidates) == 0 {
		return Config{}, nil, fmt.Errorf("no compatible resolvers are available for DNSTT testing")
	}

	if strings.TrimSpace(cfg.Pubkey) != "" {
		if cfg.E2ETimeout <= 0 {
			return Config{}, nil, fmt.Errorf("dnstt e2e timeout must be greater than zero")
		}
		cfg.E2EURL = strings.TrimSpace(cfg.E2EURL)
		if cfg.E2EURL == "" {
			cfg.E2EURL = DefaultE2ETestURL
		}
		request, err := http.NewRequest(http.MethodGet, cfg.E2EURL, nil)
		if err != nil || request.URL == nil || request.URL.Host == "" {
			return Config{}, nil, fmt.Errorf("dnstt e2e url must be a valid http or https URL")
		}
		if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
			return Config{}, nil, fmt.Errorf("dnstt e2e url must use http or https")
		}
	}

	return cfg, candidates, nil
}

func runResolverCheck(ctx context.Context, resolver model.Resolver, cfg Config, ports chan int) model.Resolver {
	resolver = resetResolverState(resolver)
	resolver.DNSTTChecked = true

	if strings.TrimSpace(cfg.Pubkey) == "" {
		tunnelOK, tunnelMS, tunnelErr := runTunnelCheck(ctx, resolver.IP, cfg.Port, cfg.Domain, cfg.Timeout)
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
		return resolver
	}

	e2eOK, tunnelMS, e2eMS, e2eErr := dnsttCheck(ctx, resolver.IP, cfg.Port, cfg.Domain, cfg.Pubkey, cfg.E2ETimeout, cfg.QuerySize, cfg.E2EURL, ports)
	if tunnelMS > 0 {
		resolver.DNSTTTunnelMillis = tunnelMS
		resolver.DNSTTTunnelOK = true
	}
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

func runCandidateBatch(
	ctx context.Context,
	updated []model.Resolver,
	indexes []int,
	cfg Config,
	portPool chan int,
	total uint64,
	tested *atomic.Uint64,
	tunnelOK *atomic.Uint64,
	e2eOK *atomic.Uint64,
	startedAt time.Time,
	emit func(Event),
) {
	jobs := make(chan int, len(indexes))
	for _, index := range indexes {
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

				resolver := runResolverCheck(ctx, updated[index], cfg, portPool)
				updated[index] = resolver

				currentTested := tested.Add(1)
				if resolver.DNSTTTunnelOK {
					tunnelOK.Add(1)
				}
				if resolver.DNSTTE2EOK {
					e2eOK.Add(1)
				}

				currentSummary := Summary{
					Candidates: total,
					Checked:    currentTested,
					TunnelOK:   tunnelOK.Load(),
					E2EOK:      e2eOK.Load(),
					StartedAt:  startedAt,
				}

				if emit != nil {
					copyResolver := resolver
					emit(Event{
						Type:    EventResolver,
						Tested:  currentTested,
						Total:   total,
						Tunnel:  currentSummary.TunnelOK,
						E2E:     currentSummary.E2EOK,
						Item:    &copyResolver,
						Summary: currentSummary,
					})
					emit(Event{
						Type:    EventProgress,
						Tested:  currentTested,
						Total:   total,
						Tunnel:  currentSummary.TunnelOK,
						E2E:     currentSummary.E2EOK,
						Summary: currentSummary,
					})
				}
			}
		}()
	}

	workerWG.Wait()
}

func emitProgress(emit func(Event), total, tested, tunnel, e2e uint64, startedAt time.Time) {
	if emit == nil {
		return
	}
	summary := Summary{
		Candidates: total,
		Checked:    tested,
		TunnelOK:   tunnel,
		E2EOK:      e2e,
		StartedAt:  startedAt,
	}
	emit(Event{
		Type:    EventProgress,
		Tested:  tested,
		Total:   total,
		Tunnel:  tunnel,
		E2E:     e2e,
		Summary: summary,
	})
}

func collectNearbyResolvers(resolvers []model.Resolver, seedIndexes []int, e2eRequested bool, basePrefixes []netip.Prefix) []model.Resolver {
	seenIPs := make(map[string]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		seenIPs[resolver.IP] = struct{}{}
	}

	expandedSubnets := make(map[string]struct{})
	nearby := make([]model.Resolver, 0)
	for _, index := range seedIndexes {
		if index < 0 || index >= len(resolvers) {
			continue
		}
		resolver := resolvers[index]
		if resolver.DNSTTNearby {
			continue
		}
		if !resolverPassed(resolver, e2eRequested) {
			continue
		}

		ip, ok := parseIPv4Addr(resolver.IP)
		if !ok {
			continue
		}
		if prefixCoverageCount(netip.AddrFrom4(ip), basePrefixes) > 1 {
			continue
		}

		subnetKey, subnetPrefix := subnetForIPv4(ip)
		if _, ok := expandedSubnets[subnetKey]; ok {
			continue
		}
		expandedSubnets[subnetKey] = struct{}{}

		for lastOctet := 0; lastOctet < 256; lastOctet++ {
			candidateAddr := netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], byte(lastOctet)})
			candidateIP := candidateAddr.String()
			if _, ok := seenIPs[candidateIP]; ok {
				continue
			}
			if ipCoveredByAnyPrefix(candidateAddr, basePrefixes) {
				continue
			}
			seenIPs[candidateIP] = struct{}{}
			nearby = append(nearby, model.Resolver{
				IP:          candidateIP,
				Prefix:      subnetPrefix,
				DNSTTNearby: true,
			})
		}
	}
	return nearby
}

func parseBasePrefixes(configured []string, resolvers []model.Resolver) []netip.Prefix {
	rawValues := configured
	if len(rawValues) == 0 {
		rawValues = make([]string, 0, len(resolvers))
		for _, resolver := range resolvers {
			if resolver.DNSTTNearby {
				continue
			}
			rawValues = append(rawValues, resolver.Prefix)
		}
	}

	seen := make(map[string]struct{}, len(rawValues))
	prefixes := make([]netip.Prefix, 0, len(rawValues))
	for _, raw := range rawValues {
		prefix, ok := parseBasePrefix(raw)
		if !ok {
			continue
		}
		key := prefix.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func parseBasePrefix(raw string) (netip.Prefix, bool) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(text); err == nil {
		if addr.Is4() {
			return netip.PrefixFrom(addr, 32), true
		}
		return netip.PrefixFrom(addr, 128), true
	}
	return netip.Prefix{}, false
}

func parseIPv4Addr(raw string) ([4]byte, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return [4]byte{}, false
	}
	return addr.As4(), true
}

func subnetForIPv4(ip [4]byte) (string, string) {
	subnet := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
	return subnet, fmt.Sprintf("%s.0/24", subnet)
}

func prefixCoverageCount(addr netip.Addr, prefixes []netip.Prefix) int {
	count := 0
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			count++
		}
	}
	return count
}

func ipCoveredByAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	return prefixCoverageCount(addr, prefixes) > 0
}

func resolverPassed(resolver model.Resolver, e2eRequested bool) bool {
	if e2eRequested {
		return resolver.DNSTTE2EOK
	}
	return resolver.DNSTTTunnelOK
}

func resetResolverState(resolver model.Resolver) model.Resolver {
	resolver.DNSTTChecked = false
	resolver.DNSTTTunnelOK = false
	resolver.DNSTTE2EOK = false
	resolver.DNSTTTunnelMillis = 0
	resolver.DNSTTE2EMillis = 0
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

func dnsttCheck(ctx context.Context, resolverIP string, resolverPort int, domain, pubkey string, timeout time.Duration, querySize int, e2eURL string, ports chan int) (bool, int64, int64, error) {
	var port int
	select {
	case port = <-ports:
	case <-ctx.Done():
		return false, 0, 0, ctx.Err()
	}
	defer func() {
		ports <- port
	}()

	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	client, err := newEmbeddedClient(
		net.JoinHostPort(resolverIP, fmt.Sprintf("%d", resolverPort)),
		domain,
		pubkey,
		addr,
	)
	if err != nil {
		return false, 0, 0, fmt.Errorf("create embedded dnstt client: %w", err)
	}
	client.SetAuthoritativeMode(false)
	if querySize > 0 {
		client.SetMaxPayload(querySize)
	}

	startCh := make(chan error, 1)
	go func() {
		startCh <- client.Start()
	}()

	select {
	case err := <-startCh:
		if err != nil {
			return false, 0, roundMillis(time.Since(start)), fmt.Errorf("start embedded dnstt client: %w", err)
		}
	case <-checkCtx.Done():
		return false, 0, roundMillis(time.Since(start)), fmt.Errorf("dnstt e2e timed out")
	}
	defer client.Stop()

	if err := waitForEmbeddedSOCKS5Port(checkCtx, addr, client); err != nil {
		if checkCtx.Err() != nil {
			return false, 0, roundMillis(time.Since(start)), fmt.Errorf("dnstt e2e timed out")
		}
		return false, 0, roundMillis(time.Since(start)), err
	}

	tunnelMS := roundMillis(time.Since(start))
	if err := verifyHTTPThroughSOCKS5(checkCtx, addr, e2eURL); err != nil {
		if checkCtx.Err() != nil {
			return false, tunnelMS, roundMillis(time.Since(start)), fmt.Errorf("dnstt e2e timed out")
		}
		return false, tunnelMS, roundMillis(time.Since(start)), err
	}

	return true, tunnelMS, roundMillis(time.Since(start)), nil
}

func waitForEmbeddedSOCKS5Port(ctx context.Context, addr string, client embeddedClient) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}

		if client != nil && !client.IsRunning() {
			return fmt.Errorf("embedded dnstt client stopped before socks5 proxy was ready")
		}

		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return nil
	}
}

func normalizeScoreThreshold(value int) int {
	switch {
	case value <= 0:
		return 2
	case value > 6:
		return 6
	default:
		return value
	}
}

func verifyHTTPThroughSOCKS5(ctx context.Context, addr string, testURL string) error {
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("create socks5 dialer: %w", err)
	}

	tlsTimeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < tlsTimeout {
			tlsTimeout = remaining
		}
	}

	transport := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: tlsTimeout,
	}
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		transport.DialContext = contextDialer.DialContext
	} else {
		transport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return fmt.Errorf("create http verification request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("http verification failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("http verification returned status %d", response.StatusCode)
	}

	return nil
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
