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
	}, 500*time.Millisecond, port, nil)
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
	}, 500*time.Millisecond, port, nil)
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
	}, 500*time.Millisecond, port, []string{"github.com.", "example.com."})
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
		Workers:   1,
		Timeout:   500 * time.Millisecond,
		HostLimit: 0,
		Port:      port,
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
