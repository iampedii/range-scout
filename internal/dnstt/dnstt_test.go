package dnstt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"range-scout/internal/model"
)

func TestEligibleResolversFiltersQualifiedCandidates(t *testing.T) {
	indexes := EligibleResolvers([]model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
		{IP: "198.51.100.11", TunnelScore: 1},
		{IP: "198.51.100.12", TunnelScore: 0},
	}, 2)

	if len(indexes) != 1 || indexes[0] != 0 {
		t.Fatalf("unexpected eligible indexes: %#v", indexes)
	}
}

func TestTestMarksHealthyResolversWithTunnelResults(t *testing.T) {
	port, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.RecursionAvailable = true
		reply.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{"ok"},
			},
		}
		_ = w.WriteMsg(reply)
	})
	defer shutdown()

	resolvers := []model.Resolver{
		{IP: "127.0.0.1", Prefix: "127.0.0.1/32", TunnelScore: 6},
		{IP: "127.0.0.2", Prefix: "127.0.0.0/24", TunnelScore: 1},
	}

	updated, summary, err := Test(nilContext(), resolvers, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Port:    port,
		Domain:  "t.example.com",
	}, nil)
	if err != nil {
		t.Fatalf("Test returned error: %v", err)
	}

	if summary.Candidates != 1 || summary.Checked != 1 || summary.TunnelOK != 1 || summary.E2EOK != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if !updated[0].DNSTTChecked || !updated[0].DNSTTTunnelOK {
		t.Fatalf("expected first resolver to pass tunnel check: %#v", updated[0])
	}
	if updated[1].DNSTTChecked {
		t.Fatalf("expected ineligible resolver to be skipped: %#v", updated[1])
	}
}

func TestTestExpandsNearbyIPsAfterSuccess(t *testing.T) {
	previousTunnelCheck := runTunnelCheck
	runTunnelCheck = func(ctx context.Context, resolverIP string, port int, domain string, timeout time.Duration) (bool, int64, error) {
		if strings.HasPrefix(resolverIP, "198.51.100.") {
			return true, 7, nil
		}
		return false, 7, fmt.Errorf("unexpected resolver %s", resolverIP)
	}
	t.Cleanup(func() {
		runTunnelCheck = previousTunnelCheck
	})

	resolvers := []model.Resolver{
		{IP: "198.51.100.10", Prefix: "198.51.100.10/32", TunnelScore: 6},
		{IP: "203.0.113.5", Prefix: "203.0.113.5/32", TunnelScore: 1},
	}

	updated, summary, err := Test(nilContext(), resolvers, Config{
		Workers:       8,
		Timeout:       500 * time.Millisecond,
		Port:          53,
		Domain:        "t.example.com",
		TestNearbyIPs: true,
	}, nil)
	if err != nil {
		t.Fatalf("Test returned error: %v", err)
	}

	if summary.Candidates != 256 || summary.Checked != 256 || summary.TunnelOK != 256 || summary.E2EOK != 0 {
		t.Fatalf("unexpected summary after nearby expansion: %#v", summary)
	}
	if len(updated) != 257 {
		t.Fatalf("expected nearby expansion to append 255 resolvers, got %d", len(updated))
	}

	var nearby model.Resolver
	foundNearby := false
	for _, resolver := range updated {
		if resolver.IP != "198.51.100.11" {
			continue
		}
		nearby = resolver
		foundNearby = true
		break
	}
	if !foundNearby {
		t.Fatal("expected nearby resolver to be appended")
	}
	if !nearby.DNSTTNearby || !nearby.DNSTTChecked || !nearby.DNSTTTunnelOK {
		t.Fatalf("expected appended nearby resolver to be checked successfully: %#v", nearby)
	}
	if updated[1].DNSTTChecked {
		t.Fatalf("expected ineligible resolver to remain unchecked: %#v", updated[1])
	}
}

func TestTestSkipsNearbyExpansionForSeedsCoveredByAnotherBaseRange(t *testing.T) {
	previousTunnelCheck := runTunnelCheck
	runTunnelCheck = func(ctx context.Context, resolverIP string, port int, domain string, timeout time.Duration) (bool, int64, error) {
		return true, 7, nil
	}
	t.Cleanup(func() {
		runTunnelCheck = previousTunnelCheck
	})

	resolvers := []model.Resolver{
		{IP: "198.51.100.10", Prefix: "198.51.100.10/32", TunnelScore: 6},
	}

	updated, summary, err := Test(nilContext(), resolvers, Config{
		Workers:       4,
		Timeout:       500 * time.Millisecond,
		Port:          53,
		Domain:        "t.example.com",
		TestNearbyIPs: true,
		BasePrefixes:  []string{"198.51.100.10/32", "198.51.100.0/24"},
	}, nil)
	if err != nil {
		t.Fatalf("Test returned error: %v", err)
	}

	if summary.Candidates != 1 || summary.Checked != 1 {
		t.Fatalf("expected no nearby expansion for overlapping seed ranges, got summary %#v", summary)
	}
	if len(updated) != 1 {
		t.Fatalf("expected no nearby resolvers to be appended, got %d", len(updated))
	}
}

func TestTestSkipsNearbyIPsAlreadyCoveredByAnotherBaseRange(t *testing.T) {
	previousTunnelCheck := runTunnelCheck
	runTunnelCheck = func(ctx context.Context, resolverIP string, port int, domain string, timeout time.Duration) (bool, int64, error) {
		if strings.HasPrefix(resolverIP, "198.51.100.") {
			return true, 7, nil
		}
		return false, 7, fmt.Errorf("unexpected resolver %s", resolverIP)
	}
	t.Cleanup(func() {
		runTunnelCheck = previousTunnelCheck
	})

	resolvers := []model.Resolver{
		{IP: "198.51.100.10", Prefix: "198.51.100.10/32", TunnelScore: 6},
	}

	updated, summary, err := Test(nilContext(), resolvers, Config{
		Workers:       8,
		Timeout:       500 * time.Millisecond,
		Port:          53,
		Domain:        "t.example.com",
		TestNearbyIPs: true,
		BasePrefixes:  []string{"198.51.100.10/32", "198.51.100.128/25"},
	}, nil)
	if err != nil {
		t.Fatalf("Test returned error: %v", err)
	}

	if summary.Candidates != 128 || summary.Checked != 128 || summary.TunnelOK != 128 {
		t.Fatalf("unexpected summary after excluding overlapping base ranges: %#v", summary)
	}
	if len(updated) != 128 {
		t.Fatalf("expected only 127 nearby resolvers to be appended, got %d", len(updated))
	}
	foundAllowed := false
	for _, resolver := range updated {
		if resolver.IP == "198.51.100.200" {
			t.Fatalf("did not expect nearby resolver inside another base range: %#v", resolver)
		}
		if resolver.IP == "198.51.100.64" {
			foundAllowed = true
		}
	}
	if !foundAllowed {
		t.Fatal("expected nearby resolver outside overlapping base ranges to be appended")
	}
}

func TestTestReturnsErrorWhenNoHealthyResolversExist(t *testing.T) {
	_, _, err := Test(nilContext(), []model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 1},
	}, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Domain:  "t.example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an error when no healthy resolvers exist")
	}
}

func TestPrepareConfigDefaultsE2EURLWhenPubkeySet(t *testing.T) {
	cfg, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
	}, Config{
		Workers:    1,
		Timeout:    500 * time.Millisecond,
		E2ETimeout: 5 * time.Second,
		Domain:     "t.example.com",
		Pubkey:     "deadbeef",
	})
	if err != nil {
		t.Fatalf("prepareConfig returned error: %v", err)
	}
	if cfg.E2EURL != DefaultE2ETestURL {
		t.Fatalf("unexpected default e2e url: %q", cfg.E2EURL)
	}
}

func TestPrepareConfigAllowsBlankE2EURLInTunnelOnlyMode(t *testing.T) {
	cfg, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
	}, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Domain:  "t.example.com",
	})
	if err != nil {
		t.Fatalf("prepareConfig returned error: %v", err)
	}
	if cfg.E2EURL != "" {
		t.Fatalf("unexpected tunnel-only e2e url mutation: %q", cfg.E2EURL)
	}
}

func nilContext() context.Context {
	return context.Background()
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
