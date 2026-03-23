package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"range-scout/internal/model"
)

func TestProbeResolverScoresFullyCompatibleResolvers(t *testing.T) {
	const domain = "tun.example.com."

	port, shutdown := startTestDNSServer(t, fullyCompatibleHandler(domain))
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, domain, 0, 2)
	if !ok {
		t.Fatal("expected resolver to be reachable")
	}
	if !resolver.DNSReachable {
		t.Fatal("expected DNSReachable to be true")
	}
	if resolver.TunnelScore != 6 {
		t.Fatalf("expected tunnel score 6, got %d", resolver.TunnelScore)
	}
	if !resolver.TunnelNSSupport || !resolver.TunnelTXTSupport || !resolver.TunnelRandomSub || !resolver.TunnelRealism || !resolver.TunnelEDNS0Support || !resolver.TunnelNXDOMAIN {
		t.Fatalf("expected all tunnel checks to pass: %#v", resolver)
	}
	if resolver.TunnelEDNSMaxPayload != 1232 {
		t.Fatalf("expected max EDNS payload 1232, got %d", resolver.TunnelEDNSMaxPayload)
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected resolver to qualify for DNSTT")
	}
	if !resolver.Stable {
		t.Fatal("expected fully compatible resolver to be marked stable")
	}
	if resolver.Transport != string(ProtocolUDP) {
		t.Fatalf("expected transport %q, got %q", ProtocolUDP, resolver.Transport)
	}
}

func TestScanTracksWorkingCompatibleAndQualifiedCounts(t *testing.T) {
	const domain = "tun.example.com."

	port, shutdown := startTestDNSServer(t, fullyCompatibleHandler(domain))
	defer shutdown()

	result, err := Scan(context.Background(), model.Operator{Name: "Test"}, []model.PrefixEntry{
		{Prefix: "127.0.0.1/32", ScanHosts: 1},
	}, Config{
		Workers:        1,
		Timeout:        500 * time.Millisecond,
		Port:           port,
		Domain:         domain,
		ScoreThreshold: 2,
	}, nil)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.ScannedTargets != 1 {
		t.Fatalf("expected 1 scanned target, got %d", result.ScannedTargets)
	}
	if result.WorkingCount != 1 || result.CompatibleCount != 1 || result.QualifiedCount != 1 {
		t.Fatalf("unexpected counts: working=%d compatible=%d qualified=%d", result.WorkingCount, result.CompatibleCount, result.QualifiedCount)
	}
	if result.ReachableCount != 1 || result.RecursiveCount != 1 {
		t.Fatalf("unexpected compatibility aliases: reachable=%d recursive=%d", result.ReachableCount, result.RecursiveCount)
	}
	if result.Protocol != string(ProtocolUDP) {
		t.Fatalf("expected protocol %q, got %q", ProtocolUDP, result.Protocol)
	}
	if result.TunnelDomain != "tun.example.com" {
		t.Fatalf("unexpected tunnel domain %q", result.TunnelDomain)
	}
	if len(result.Resolvers) != 1 || result.Resolvers[0].TunnelScore != 6 {
		t.Fatalf("unexpected scan results: %#v", result.Resolvers)
	}
}

func TestScanWaitsForProgressEmitterBeforeReturning(t *testing.T) {
	progressStarted := make(chan struct{})
	releaseProgress := make(chan struct{})
	returned := make(chan struct{})

	go func() {
		_, _ = Scan(context.Background(), model.Operator{Name: "Test"}, nil, Config{
			Workers: 1,
			Timeout: 50 * time.Millisecond,
			Domain:  "tun.example.com.",
		}, func(event Event) {
			if event.Type != EventProgress {
				return
			}
			select {
			case <-progressStarted:
			default:
				close(progressStarted)
			}
			<-releaseProgress
		})
		close(returned)
	}()

	select {
	case <-progressStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for progress event")
	}

	select {
	case <-returned:
		t.Fatal("Scan returned before the progress emitter completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseProgress)

	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Scan to return")
	}
}

func TestNormalizeProbeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "https://github.com/login", want: "github.com."},
		{input: "example.com/docs", want: "example.com."},
		{input: "sub.domain.test", want: "sub.domain.test."},
	}

	for _, test := range tests {
		got, err := NormalizeProbeDomain(test.input)
		if err != nil {
			t.Fatalf("NormalizeProbeDomain(%q) returned error: %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("NormalizeProbeDomain(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestTunnelRealismPayloadHonorsQueryBudget(t *testing.T) {
	if got := tunnelRealismPayload(0, "tun.example.com."); got != 100 {
		t.Fatalf("expected default tunnel realism payload 100, got %d", got)
	}
	if got := tunnelRealismPayload(80, "tun.example.com."); got <= 0 || got > 100 {
		t.Fatalf("unexpected bounded tunnel realism payload %d", got)
	}
}

func fullyCompatibleHandler(domain string) dns.HandlerFunc {
	trimmedDomain := strings.TrimSuffix(domain, ".")
	parent := getParentDomain(domain) + "."
	nsHost := "ns." + parent

	return func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)

		name := r.Question[0].Name
		switch {
		case strings.HasSuffix(name, ".invalid."):
			reply.Rcode = dns.RcodeNameError
		case r.Question[0].Qtype == dns.TypeNS && name == parent:
			reply.Answer = []dns.RR{
				&dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: nsHost},
			}
		case r.Question[0].Qtype == dns.TypeA && name == nsHost:
			reply.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("203.0.113.7").To4()},
			}
		case r.Question[0].Qtype == dns.TypeTXT:
			reply.Answer = []dns.RR{
				&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"ok"}},
			}
		default:
			reply.Answer = []dns.RR{
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("93.184.216.34").To4()},
			}
		}

		if strings.HasSuffix(name, "."+trimmedDomain+".") || strings.HasSuffix(name, "."+parent) || name == parent {
			reply.RecursionAvailable = true
		}
		if opt := r.IsEdns0(); opt != nil {
			reply.Extra = append(reply.Extra, &dns.OPT{
				Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
			})
			_ = opt
		}

		_ = w.WriteMsg(reply)
	}
}

func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) (int, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}

	server := &dns.Server{
		PacketConn: conn,
		Handler:    handler,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ActivateAndServe()
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	shutdown := func() {
		_ = server.Shutdown()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed network connection") {
				t.Fatalf("dns server returned error: %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for dns server shutdown")
		}
	}

	return port, shutdown
}
