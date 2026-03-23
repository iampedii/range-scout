package scanner

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"range-scout/internal/model"
	"range-scout/internal/prefixes"
)

const (
	StatusWorking = "WORKING"
	StatusTimeout = "TIMEOUT"
	StatusError   = "ERROR"

	defaultTunnelScoreThreshold = 2
)

var (
	verifyBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	testNetIPs   = []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
)

type Config struct {
	Workers        int
	Timeout        time.Duration
	HostLimit      uint64
	Port           int
	Protocol       Protocol
	Domain         string
	QuerySize      int
	ScoreThreshold int
}

type Protocol string

const (
	ProtocolUDP  Protocol = "UDP"
	ProtocolTCP  Protocol = "TCP"
	ProtocolBoth Protocol = "BOTH"
)

type EventType string

const (
	EventProgress EventType = "progress"
	EventResolver EventType = "resolver"
)

type Event struct {
	Type       EventType
	Scanned    uint64
	Total      uint64
	Working    uint64
	Compatible uint64
	Qualified  uint64
	Item       *model.Resolver
}

type scanTarget struct {
	IP     netip.Addr
	Prefix string
}

type tunnelTestResult struct {
	NSSupport       bool
	TXTSupport      bool
	RandomSub       bool
	TunnelRealism   bool
	EDNS0Support    bool
	EDNSMaxPayload  int
	NXDOMAINCorrect bool
}

func (t tunnelTestResult) Score() int {
	score := 0
	for _, ok := range []bool{
		t.NSSupport,
		t.TXTSupport,
		t.RandomSub,
		t.TunnelRealism,
		t.EDNS0Support,
		t.NXDOMAINCorrect,
	} {
		if ok {
			score++
		}
	}
	return score
}

func Scan(
	ctx context.Context,
	operator model.Operator,
	entries []model.PrefixEntry,
	cfg Config,
	emit func(Event),
) (model.ScanResult, error) {
	if cfg.Workers <= 0 {
		return model.ScanResult{}, fmt.Errorf("workers must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return model.ScanResult{}, fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.QuerySize < 0 {
		return model.ScanResult{}, fmt.Errorf("query size must be zero or greater")
	}

	domain := configuredTunnelDomain(cfg.Domain)
	if domain == "." {
		return model.ScanResult{}, fmt.Errorf("dnstt domain is required")
	}
	threshold := normalizeScoreThreshold(cfg.ScoreThreshold)
	port := cfg.Port
	if port <= 0 {
		port = 53
	}

	totalTargets := prefixes.EstimateScanTargets(entries, cfg.HostLimit)
	result := model.ScanResult{
		Operator:       operator,
		Prefixes:       append([]model.PrefixEntry(nil), entries...),
		TotalTargets:   totalTargets,
		Workers:        cfg.Workers,
		TimeoutMillis:  int(cfg.Timeout.Milliseconds()),
		HostLimit:      cfg.HostLimit,
		Port:           port,
		Protocol:       string(ProtocolUDP),
		TunnelDomain:   strings.TrimSuffix(domain, "."),
		QuerySize:      cfg.QuerySize,
		ScoreThreshold: threshold,
		StartedAt:      time.Now(),
	}

	if DetectTransparentProxy(ctx, domain, 2*time.Second) {
		result.TransparentProxyDetected = true
		result.Warnings = append(result.Warnings, "transparent DNS proxy detected; results may be inaccurate")
	}

	jobs := make(chan scanTarget, cfg.Workers*4)
	var scanned atomic.Uint64
	var working atomic.Uint64
	var compatible atomic.Uint64
	var qualified atomic.Uint64
	var resolversMu sync.Mutex
	resolvers := make([]model.Resolver, 0)

	progressDone := make(chan struct{})
	var progressWG sync.WaitGroup
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		tickerCh := ticker.C
		ctxDone := ctx.Done()
		emitProgress := func() {
			if emit != nil {
				emit(Event{
					Type:       EventProgress,
					Scanned:    scanned.Load(),
					Total:      totalTargets,
					Working:    working.Load(),
					Compatible: compatible.Load(),
					Qualified:  qualified.Load(),
				})
			}
		}
		for {
			select {
			case <-progressDone:
				emitProgress()
				return
			case <-tickerCh:
				emitProgress()
			case <-ctxDone:
				tickerCh = nil
				ctxDone = nil
			}
		}
	}()

	var workerWG sync.WaitGroup
	for workerID := 0; workerID < cfg.Workers; workerID++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for target := range jobs {
				resolver, ok := probeResolver(ctx, target, cfg.Timeout, port, domain, cfg.QuerySize, threshold)
				scanned.Add(1)
				if ok {
					currentWorking := working.Add(1)
					if resolver.TunnelScore > 0 {
						compatible.Add(1)
					}
					if resolver.TunnelScore >= threshold {
						qualified.Add(1)
					}
					resolversMu.Lock()
					resolvers = append(resolvers, resolver)
					resolversMu.Unlock()
					if emit != nil {
						copyResolver := resolver
						emit(Event{
							Type:       EventResolver,
							Scanned:    scanned.Load(),
							Total:      totalTargets,
							Working:    currentWorking,
							Compatible: compatible.Load(),
							Qualified:  qualified.Load(),
							Item:       &copyResolver,
						})
					}
				}
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}

	walkErrCh := make(chan error, 1)
	go func() {
		defer close(jobs)
		_, err := prefixes.WalkHosts(entries, cfg.HostLimit, func(addr netip.Addr, prefix string) bool {
			select {
			case <-ctx.Done():
				return false
			case jobs <- scanTarget{IP: addr, Prefix: prefix}:
				return true
			}
		})
		walkErrCh <- err
	}()

	workerWG.Wait()
	close(progressDone)
	progressWG.Wait()

	walkErr := <-walkErrCh
	resolversMu.Lock()
	sort.Slice(resolvers, func(i, j int) bool {
		if resolvers[i].TunnelScore != resolvers[j].TunnelScore {
			return resolvers[i].TunnelScore > resolvers[j].TunnelScore
		}
		if resolvers[i].LatencyMillis != resolvers[j].LatencyMillis {
			return resolvers[i].LatencyMillis < resolvers[j].LatencyMillis
		}
		return resolvers[i].IP < resolvers[j].IP
	})
	result.Resolvers = append(result.Resolvers, resolvers...)
	resolversMu.Unlock()

	result.ScannedTargets = scanned.Load()
	result.WorkingCount = working.Load()
	result.CompatibleCount = compatible.Load()
	result.QualifiedCount = qualified.Load()
	result.ReachableCount = result.WorkingCount
	result.RecursiveCount = result.QualifiedCount
	result.FinishedAt = time.Now()

	if errors.Is(ctx.Err(), context.Canceled) {
		result.Warnings = append(result.Warnings, "scan canceled")
		return result, ctx.Err()
	}
	if walkErr != nil {
		return result, walkErr
	}

	return result, nil
}

func probeResolver(ctx context.Context, target scanTarget, timeout time.Duration, port int, domain string, querySize int, threshold int) (model.Resolver, bool) {
	probeTimeout := timeout
	if probeTimeout > 1500*time.Millisecond {
		probeTimeout = 1500 * time.Millisecond
	}

	parent := getParentDomain(domain)
	query := randomLabel(8) + "." + parent
	response, latencyMS, err := dnsQuery(ctx, target.IP, port, query, dns.TypeA, probeTimeout, 0)
	if err != nil || response == nil {
		return model.Resolver{}, false
	}

	resolver := model.Resolver{
		Transport:           string(ProtocolUDP),
		IP:                  target.IP.String(),
		Prefix:              target.Prefix,
		DNSReachable:        true,
		ScanStatus:          StatusWorking,
		ResponseCode:        dnsResponseCodeLabel(response.Rcode),
		LatencyMillis:       latencyMS,
		RecursionAdvertised: response.RecursionAvailable,
	}

	var tunnel tunnelTestResult
	var wg sync.WaitGroup
	wg.Add(6)
	go func() {
		defer wg.Done()
		tunnel.NSSupport = testNS(ctx, target.IP, port, parent, timeout)
	}()
	go func() {
		defer wg.Done()
		tunnel.TXTSupport = testTXT(ctx, target.IP, port, domain, timeout)
	}()
	go func() {
		defer wg.Done()
		tunnel.RandomSub = testRandomSubdomain(ctx, target.IP, port, domain, timeout)
	}()
	go func() {
		defer wg.Done()
		tunnel.TunnelRealism = testTunnelRealism(ctx, target.IP, port, domain, timeout, querySize)
	}()
	go func() {
		defer wg.Done()
		tunnel.EDNS0Support, tunnel.EDNSMaxPayload = testEDNS0(ctx, target.IP, port, domain, timeout)
	}()
	go func() {
		defer wg.Done()
		tunnel.NXDOMAINCorrect = testNXDOMAIN(ctx, target.IP, port, timeout)
	}()
	wg.Wait()

	resolver.TunnelNSSupport = tunnel.NSSupport
	resolver.TunnelTXTSupport = tunnel.TXTSupport
	resolver.TunnelRandomSub = tunnel.RandomSub
	resolver.TunnelRealism = tunnel.TunnelRealism
	resolver.TunnelEDNS0Support = tunnel.EDNS0Support
	resolver.TunnelEDNSMaxPayload = tunnel.EDNSMaxPayload
	resolver.TunnelNXDOMAIN = tunnel.NXDOMAINCorrect
	resolver.TunnelScore = tunnel.Score()
	resolver.RecursionAvailable = resolver.TunnelScore >= threshold
	resolver.Stable = resolver.TunnelScore == 6

	return resolver, true
}

func DetectTransparentProxy(ctx context.Context, domain string, timeout time.Duration) bool {
	var detected atomic.Bool
	var wg sync.WaitGroup
	for _, ip := range testNetIPs {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			response, _, err := dnsQuery(ctx, netip.MustParseAddr(host), 53, randomLabel(8)+"."+domain, dns.TypeA, timeout, 0)
			if err == nil && response != nil {
				detected.Store(true)
			}
		}(ip)
	}
	wg.Wait()
	return detected.Load()
}

func testNS(ctx context.Context, ip netip.Addr, port int, parentDomain string, timeout time.Duration) bool {
	response, _, err := dnsQuery(ctx, ip, port, parentDomain, dns.TypeNS, timeout, 0)
	if err != nil || response == nil {
		return false
	}
	var nsHost string
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.NS); ok {
			nsHost = record.Ns
			break
		}
	}
	if nsHost == "" {
		return false
	}
	response, _, err = dnsQuery(ctx, ip, port, nsHost, dns.TypeA, timeout, 0)
	return err == nil && response != nil
}

func testTXT(ctx context.Context, ip netip.Addr, port int, domain string, timeout time.Duration) bool {
	query := randomLabel(8) + "." + getParentDomain(domain)
	response, _, err := dnsQuery(ctx, ip, port, query, dns.TypeTXT, timeout, 0)
	return err == nil && response != nil
}

func testRandomSubdomain(ctx context.Context, ip netip.Addr, port int, domain string, timeout time.Duration) bool {
	for range 2 {
		query := randomLabel(8) + "." + randomLabel(8) + "." + strings.TrimSuffix(domain, ".")
		response, _, err := dnsQuery(ctx, ip, port, query, dns.TypeA, timeout, 0)
		if err == nil && response != nil {
			return true
		}
	}
	return false
}

func testTunnelRealism(ctx context.Context, ip netip.Addr, port int, domain string, timeout time.Duration, querySize int) bool {
	randomBytes := make([]byte, tunnelRealismPayload(querySize, domain))
	for index := range randomBytes {
		randomBytes[index] = byte(rand.IntN(256))
	}
	encoded := verifyBase32.EncodeToString(randomBytes)
	labels := splitLabels(encoded, 57)
	query := strings.Join(labels, ".") + "." + strings.TrimSuffix(domain, ".")
	response, _, err := dnsQuery(ctx, ip, port, query, dns.TypeTXT, timeout, 0)
	return err == nil && response != nil
}

func testEDNS0(ctx context.Context, ip netip.Addr, port int, domain string, timeout time.Duration) (bool, int) {
	maxPayload := 0
	anyOK := false
	for _, payload := range []int{512, 900, 1232} {
		query := randomLabel(8) + "." + getParentDomain(domain)
		response, _, err := dnsQuery(ctx, ip, port, query, dns.TypeA, timeout, payload)
		if err != nil || response == nil {
			break
		}
		if response.Rcode == dns.RcodeFormatError {
			break
		}
		if response.IsEdns0() != nil {
			anyOK = true
			maxPayload = payload
			continue
		}
		break
	}
	return anyOK, maxPayload
}

func testNXDOMAIN(ctx context.Context, ip netip.Addr, port int, timeout time.Duration) bool {
	good := 0
	for range 3 {
		response, _, err := dnsQuery(ctx, ip, port, randomLabel(12)+".invalid", dns.TypeA, timeout, 0)
		if err != nil || response == nil {
			continue
		}
		if response.Rcode == dns.RcodeNameError {
			good++
		}
	}
	return good >= 2
}

func dnsQuery(ctx context.Context, ip netip.Addr, port int, name string, qtype uint16, timeout time.Duration, ednsPayload int) (*dns.Msg, int64, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	message.RecursionDesired = true
	if ednsPayload > 0 {
		message.SetEdns0(uint16(ednsPayload), false)
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	response, _, err := (&dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}).ExchangeContext(queryCtx, message, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	latency := max(time.Since(start).Milliseconds(), int64(1))
	if err != nil {
		return nil, latency, err
	}
	return response, latency, nil
}

func ParseProtocol(value string) (Protocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", string(ProtocolUDP):
		return ProtocolUDP, nil
	case string(ProtocolTCP):
		return ProtocolTCP, nil
	case string(ProtocolBoth):
		return ProtocolBoth, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", value)
	}
}

func NormalizeProbeDomain(input string) (string, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", fmt.Errorf("enter a probe URL or hostname")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid probe URL %q", input)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("invalid probe URL %q", input)
	}
	return dns.Fqdn(host), nil
}

func configuredTunnelDomain(domain string) string {
	return dns.Fqdn(strings.TrimSpace(domain))
}

func normalizeScoreThreshold(value int) int {
	if value <= 0 {
		return defaultTunnelScoreThreshold
	}
	if value > 6 {
		return 6
	}
	return value
}

func getParentDomain(domain string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	parts := strings.SplitN(trimmed, ".", 2)
	if len(parts) >= 2 && strings.Contains(parts[1], ".") {
		return parts[1]
	}
	return trimmed
}

func randomLabel(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, length)
	for index := range bytes {
		bytes[index] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(bytes)
}

func splitLabels(value string, maxLen int) []string {
	if maxLen <= 0 {
		return []string{value}
	}
	labels := make([]string, 0, (len(value)/maxLen)+1)
	for len(value) > maxLen {
		labels = append(labels, value[:maxLen])
		value = value[maxLen:]
	}
	if value != "" {
		labels = append(labels, value)
	}
	return labels
}

func tunnelRealismPayload(querySize int, domain string) int {
	if querySize < 50 {
		return 100
	}
	suffixLen := len(strings.TrimSuffix(domain, ".")) + 2
	overhead := 12 + 4 + suffixLen
	available := querySize - overhead
	if available < 10 {
		available = 10
	}
	raw := available * 5 / 9
	switch {
	case raw < 5:
		return 5
	case raw > 100:
		return 100
	default:
		return raw
	}
}

func dnsResponseCodeLabel(code int) string {
	if label, ok := dns.RcodeToString[code]; ok {
		return label
	}
	return strconv.Itoa(code)
}
