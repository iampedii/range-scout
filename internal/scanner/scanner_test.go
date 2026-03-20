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

func TestProbeResolverReachableWithoutRecursion(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Rcode = dns.RcodeRefused
		reply.RecursionAvailable = false
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolUDP, configuredRecursionDomain(""), configuredStabilityDomains(nil))
	if !ok {
		t.Fatal("expected dns host to be reachable")
	}
	if !resolver.DNSReachable {
		t.Fatal("expected DNSReachable to be true")
	}
	if resolver.RecursionAvailable {
		t.Fatal("expected RecursionAvailable to be false")
	}
	if resolver.RecursionAdvertised {
		t.Fatal("expected RecursionAdvertised to be false")
	}
	if resolver.Stable {
		t.Fatal("expected Stable to be false")
	}
	if resolver.ResponseCode != "REFUSED" {
		t.Fatalf("expected response code REFUSED, got %q", resolver.ResponseCode)
	}
}

func TestProbeResolverMarksStableRecursiveResolvers(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			reply.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34").To4(),
				},
			}
		} else {
			reply.Rcode = dns.RcodeRefused
			reply.RecursionAvailable = false
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolUDP, configuredRecursionDomain(""), configuredStabilityDomains(nil))
	if !ok {
		t.Fatal("expected dns host to be reachable")
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected RecursionAvailable to be true")
	}
	if !resolver.RecursionAdvertised {
		t.Fatal("expected RecursionAdvertised to be true")
	}
	if !resolver.Stable {
		t.Fatal("expected Stable to be true")
	}
	if resolver.ResponseCode != "NOERROR" {
		t.Fatalf("expected response code NOERROR, got %q", resolver.ResponseCode)
	}
}

func TestProbeResolverMarksUnstableRecursiveResolvers(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			switch r.Question[0].Name {
			case "google.com.":
				reply.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "google.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP("8.8.8.8").To4(),
					},
				}
			default:
				reply.Rcode = dns.RcodeNameError
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolUDP, configuredRecursionDomain(""), []string{"github.com.", "example.com."})
	if !ok {
		t.Fatal("expected dns host to be reachable")
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected RecursionAvailable to be true")
	}
	if resolver.Stable {
		t.Fatal("expected Stable to be false")
	}
}

func TestProbeResolverUsesProvidedStabilityDomainsWithoutFallback(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			if r.Question[0].Name == "google.com." {
				reply.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "google.com.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP("8.8.8.8").To4(),
					},
				}
			} else {
				reply.Rcode = dns.RcodeNameError
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolUDP, configuredRecursionDomain(""), []string{})
	if !ok {
		t.Fatal("expected dns host to be reachable")
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected RecursionAvailable to be true")
	}
	if !resolver.Stable {
		t.Fatal("expected Stable to be true when no stability domains are provided")
	}
}

func TestScanTracksReachableAndRecursiveCounts(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			reply.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34").To4(),
				},
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	result, err := Scan(context.Background(), model.Operator{Name: "Test"}, []model.PrefixEntry{
		{Prefix: "127.0.0.1/32", ScanHosts: 1},
	}, Config{
		Workers:         1,
		Timeout:         500 * time.Millisecond,
		HostLimit:       0,
		Port:            port,
		RecursionDomain: "google.com.",
	}, nil)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.ScannedTargets != 1 {
		t.Fatalf("expected 1 scanned target, got %d", result.ScannedTargets)
	}
	if result.ReachableCount != 1 {
		t.Fatalf("expected 1 reachable host, got %d", result.ReachableCount)
	}
	if result.RecursiveCount != 1 {
		t.Fatalf("expected 1 recursive host, got %d", result.RecursiveCount)
	}
	if len(result.Resolvers) != 1 {
		t.Fatalf("expected 1 result row, got %d", len(result.Resolvers))
	}
	if !result.Resolvers[0].Stable {
		t.Fatal("expected scan result to be marked stable")
	}
	if result.Resolvers[0].Transport != string(ProtocolUDP) {
		t.Fatalf("expected resolver transport %q, got %q", ProtocolUDP, result.Resolvers[0].Transport)
	}
	if result.Port != port {
		t.Fatalf("expected scan port %d, got %d", port, result.Port)
	}
	if result.Protocol != string(ProtocolUDP) {
		t.Fatalf("expected scan protocol %q, got %q", ProtocolUDP, result.Protocol)
	}
}

func TestProbeResolverSupportsTCP(t *testing.T) {
	port, shutdown := startTestDNSServerTCP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			reply.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34").To4(),
				},
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolTCP, configuredRecursionDomain(""), configuredStabilityDomains(nil))
	if !ok {
		t.Fatal("expected dns host to be reachable over TCP")
	}
	if resolver.Transport != string(ProtocolTCP) {
		t.Fatalf("expected transport %q, got %q", ProtocolTCP, resolver.Transport)
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected recursive lookup to succeed over TCP")
	}
}

func TestProbeResolverBothFallsBackToTCP(t *testing.T) {
	port, shutdown := startTestDNSServerTCP(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			reply.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: net.ParseIP("93.184.216.34").To4(),
				},
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolBoth, configuredRecursionDomain(""), configuredStabilityDomains(nil))
	if !ok {
		t.Fatal("expected dns host to be reachable when BOTH is selected")
	}
	if resolver.Transport != string(ProtocolTCP) {
		t.Fatalf("expected BOTH mode to fall back to TCP, got %q", resolver.Transport)
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

func TestProbeResolverUsesConfiguredRecursionDomain(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if r.RecursionDesired {
			reply.RecursionAvailable = true
			if r.Question[0].Name == "resolver-test.example." {
				reply.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "resolver-test.example.",
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						A: net.ParseIP("93.184.216.34").To4(),
					},
				}
			} else {
				reply.Rcode = dns.RcodeNameError
			}
		} else {
			reply.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolver, ok := probeResolver(context.Background(), scanTarget{
		IP:     netip.MustParseAddr("127.0.0.1"),
		Prefix: "127.0.0.1/32",
	}, 500*time.Millisecond, port, ProtocolUDP, "resolver-test.example.", []string{})
	if !ok {
		t.Fatal("expected dns host to be reachable")
	}
	if !resolver.RecursionAvailable {
		t.Fatal("expected RecursionAvailable to be true for configured recursion domain")
	}
}

func TestConfiguredRecursionDomainFallsBackToDefault(t *testing.T) {
	if got := configuredRecursionDomain(""); got != defaultRecursionDomain {
		t.Fatalf("configuredRecursionDomain(\"\") = %q, want %q", got, defaultRecursionDomain)
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

func startTestDNSServerTCP(t *testing.T, handler dns.HandlerFunc) (int, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}

	server := &dns.Server{
		Listener: listener,
		Handler:  handler,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ActivateAndServe()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
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
