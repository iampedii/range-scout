package scanner

import (
	"context"
	"errors"
	"fmt"
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

var defaultStabilityDomains = []string{"github.com."}

type Config struct {
	Workers          int
	Timeout          time.Duration
	HostLimit        uint64
	Port             int
	StabilityDomains []string
}

type EventType string

const (
	EventProgress EventType = "progress"
	EventResolver EventType = "resolver"
)

type Event struct {
	Type      EventType
	Scanned   uint64
	Total     uint64
	Reachable uint64
	Recursive uint64
	Item      *model.Resolver
}

type scanTarget struct {
	IP     netip.Addr
	Prefix string
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

	totalTargets := prefixes.EstimateScanTargets(entries, cfg.HostLimit)
	result := model.ScanResult{
		Operator:      operator,
		TotalTargets:  totalTargets,
		Workers:       cfg.Workers,
		TimeoutMillis: int(cfg.Timeout.Milliseconds()),
		HostLimit:     cfg.HostLimit,
		StartedAt:     time.Now(),
	}

	jobs := make(chan scanTarget, cfg.Workers*4)
	var scanned atomic.Uint64
	var reachable atomic.Uint64
	var recursive atomic.Uint64
	var resolversMu sync.Mutex
	resolvers := make([]model.Resolver, 0)
	targetPort := cfg.Port
	if targetPort <= 0 {
		targetPort = 53
	}
	stabilityDomains := configuredStabilityDomains(cfg.StabilityDomains)

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
					Type:      EventProgress,
					Scanned:   scanned.Load(),
					Total:     totalTargets,
					Reachable: reachable.Load(),
					Recursive: recursive.Load(),
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
				resolver, ok := probeResolver(ctx, target, cfg.Timeout, targetPort, stabilityDomains)
				scanned.Add(1)
				if ok {
					reachable.Add(1)
					if resolver.RecursionAvailable {
						recursive.Add(1)
					}
					resolversMu.Lock()
					resolvers = append(resolvers, resolver)
					resolversMu.Unlock()
					if emit != nil {
						copyResolver := resolver
						emit(Event{
							Type:      EventResolver,
							Scanned:   scanned.Load(),
							Total:     totalTargets,
							Reachable: reachable.Load(),
							Recursive: recursive.Load(),
							Item:      &copyResolver,
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
		if resolvers[i].Stable != resolvers[j].Stable {
			return resolvers[i].Stable
		}
		if resolvers[i].RecursionAvailable != resolvers[j].RecursionAvailable {
			return resolvers[i].RecursionAvailable
		}
		if resolvers[i].RecursionAdvertised != resolvers[j].RecursionAdvertised {
			return resolvers[i].RecursionAdvertised
		}
		if resolvers[i].LatencyMillis != resolvers[j].LatencyMillis {
			return resolvers[i].LatencyMillis < resolvers[j].LatencyMillis
		}
		return resolvers[i].IP < resolvers[j].IP
	})
	result.Resolvers = append(result.Resolvers, resolvers...)
	resolversMu.Unlock()
	result.ScannedTargets = scanned.Load()
	result.ReachableCount = reachable.Load()
	result.RecursiveCount = recursive.Load()
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

func probeResolver(ctx context.Context, target scanTarget, timeout time.Duration, port int, stabilityDomains []string) (model.Resolver, bool) {
	reachabilityResponse, reachabilityLatency, ok := probeDNSReachable(ctx, target.IP, timeout, port)
	if !ok {
		return model.Resolver{}, false
	}

	resolver := model.Resolver{
		IP:                  target.IP.String(),
		Prefix:              target.Prefix,
		DNSReachable:        true,
		ResponseCode:        dnsResponseCodeLabel(reachabilityResponse.Rcode),
		LatencyMillis:       reachabilityLatency,
		RecursionAvailable:  false,
		RecursionAdvertised: reachabilityResponse.RecursionAvailable,
		Stable:              false,
	}

	recursionResponse, recursionLatency, recursionOK := probeLookup(ctx, target.IP, timeout, port, "google.com.", true)
	if recursionResponse != nil {
		resolver.RecursionAdvertised = recursionResponse.RecursionAvailable
		resolver.ResponseCode = dnsResponseCodeLabel(recursionResponse.Rcode)
		resolver.LatencyMillis = recursionLatency
	}
	if recursionOK {
		resolver.RecursionAvailable = true
		resolver.Stable = probeStability(ctx, target.IP, timeout, port, stabilityDomains)
	}

	return resolver, true
}

func probeDNSReachable(ctx context.Context, addr netip.Addr, timeout time.Duration, port int) (*dns.Msg, int64, bool) {
	response, rtt, err := exchangeLookup(ctx, addr, timeout, port, "example.com.", false)
	if err != nil || response == nil || !response.Response {
		return nil, 0, false
	}
	return response, max(rtt.Milliseconds(), int64(1)), true
}

func probeLookup(ctx context.Context, addr netip.Addr, timeout time.Duration, port int, domain string, recursive bool) (*dns.Msg, int64, bool) {
	response, rtt, err := exchangeLookup(ctx, addr, timeout, port, domain, recursive)
	if err != nil || response == nil || !response.Response {
		return nil, 0, false
	}
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
		return response, max(rtt.Milliseconds(), int64(1)), false
	}
	return response, max(rtt.Milliseconds(), int64(1)), true
}

func probeStability(ctx context.Context, addr netip.Addr, timeout time.Duration, port int, stabilityDomains []string) bool {
	for _, domain := range stabilityDomains {
		if ctx.Err() != nil {
			return false
		}
		_, _, ok := probeLookup(ctx, addr, timeout, port, domain, true)
		if !ok {
			return false
		}
	}
	return true
}

func exchangeLookup(ctx context.Context, addr netip.Addr, timeout time.Duration, port int, domain string, recursive bool) (*dns.Msg, time.Duration, error) {
	message := new(dns.Msg)
	message.SetQuestion(domain, dns.TypeA)
	message.RecursionDesired = recursive

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	return client.ExchangeContext(ctx, message, net.JoinHostPort(addr.String(), strconv.Itoa(port)))
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

func configuredStabilityDomains(domains []string) []string {
	if len(domains) == 0 {
		return append([]string(nil), defaultStabilityDomains...)
	}
	return append([]string(nil), domains...)
}

func dnsResponseCodeLabel(code int) string {
	if label, ok := dns.RcodeToString[code]; ok {
		return label
	}
	return strconv.Itoa(code)
}
