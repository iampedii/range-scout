package dnstt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
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

func TestPrepareConfigSkipsTCPOnlyResolvers(t *testing.T) {
	cfg, candidates, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", Transport: "TCP", TunnelScore: 6},
		{IP: "198.51.100.11", Transport: "UDP", TunnelScore: 6},
		{IP: "198.51.100.12", Transport: "BOTH", TunnelScore: 6},
	}, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Domain:  "t.example.com",
	})
	if err != nil {
		t.Fatalf("prepareConfig returned error: %v", err)
	}
	if cfg.Domain != "t.example.com." {
		t.Fatalf("expected fqdn domain, got %q", cfg.Domain)
	}
	if len(candidates) != 3 || candidates[0] != 0 || candidates[1] != 1 || candidates[2] != 2 {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestPrepareConfigRejectsInvalidTransport(t *testing.T) {
	_, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", Transport: "TCP", TunnelScore: 6},
	}, Config{
		Workers:   1,
		Timeout:   500 * time.Millisecond,
		Domain:    "t.example.com",
		Transport: "bogus",
	})
	if err == nil {
		t.Fatal("expected transport validation error")
	}
	if !strings.Contains(err.Error(), "transport") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareConfigRequiresResolverEndpointForDoH(t *testing.T) {
	_, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
	}, Config{
		Workers:    1,
		Timeout:    500 * time.Millisecond,
		E2ETimeout: 5 * time.Second,
		Domain:     "t.example.com",
		Pubkey:     "deadbeef",
		Transport:  TransportDoH,
	})
	if err == nil {
		t.Fatal("expected resolver endpoint validation error")
	}
	if !strings.Contains(err.Error(), "resolver endpoint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildResolverAddrUsesTransportDefaultsAndTemplates(t *testing.T) {
	addr, err := buildResolverAddr(Config{Transport: TransportUDP}, "198.51.100.10", 53)
	if err != nil || addr != "198.51.100.10:53" {
		t.Fatalf("unexpected udp resolver addr: %q err=%v", addr, err)
	}
	addr, err = buildResolverAddr(Config{Transport: TransportTCP}, "198.51.100.10", 53)
	if err != nil || addr != "tcp://198.51.100.10:53" {
		t.Fatalf("unexpected tcp resolver addr: %q err=%v", addr, err)
	}
	addr, err = buildResolverAddr(Config{Transport: TransportDoT}, "198.51.100.10", 853)
	if err != nil || addr != "tls://198.51.100.10:853" {
		t.Fatalf("unexpected dot resolver addr: %q err=%v", addr, err)
	}
	addr, err = buildResolverAddr(Config{Transport: TransportDoH, ResolverURL: "https://{ip}:{port}/dns-query"}, "198.51.100.10", 443)
	if err != nil || addr != "https://198.51.100.10:443/dns-query" {
		t.Fatalf("unexpected doh resolver addr: %q err=%v", addr, err)
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

func TestPrepareConfigRejectsSOCKSPasswordWithoutUsernameWhenE2EEnabled(t *testing.T) {
	_, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", TunnelScore: 6},
	}, Config{
		Workers:       1,
		Timeout:       500 * time.Millisecond,
		E2ETimeout:    5 * time.Second,
		Domain:        "t.example.com",
		Pubkey:        "deadbeef",
		SOCKSPassword: "scanner-pass",
	})
	if err == nil {
		t.Fatal("expected socks auth validation error")
	}
	if !strings.Contains(err.Error(), "socks username") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyHTTPThroughSOCKS5SupportsAuthenticatedProxy(t *testing.T) {
	addr, attempts, shutdown := startTestSOCKS5Server(t, "scanner-user", "scanner-pass")
	defer shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := verifyHTTPThroughSOCKS5(ctx, addr, "http://example.com/generate_204", "scanner-user", "scanner-pass"); err != nil {
		t.Fatalf("verifyHTTPThroughSOCKS5 returned error: %v", err)
	}

	attempt := <-attempts
	if attempt.Username != "scanner-user" || attempt.Password != "scanner-pass" {
		t.Fatalf("unexpected socks auth attempt: %#v", attempt)
	}
}

func TestVerifyHTTPThroughSOCKS5FailsWithoutCredentialsWhenProxyRequiresAuth(t *testing.T) {
	addr, _, shutdown := startTestSOCKS5Server(t, "scanner-user", "scanner-pass")
	defer shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := verifyHTTPThroughSOCKS5(ctx, addr, "http://example.com/generate_204", "", ""); err == nil {
		t.Fatal("expected verifyHTTPThroughSOCKS5 to fail without required socks auth")
	}
}

func TestDNSTTCheckUsesDynamicLoopbackPort(t *testing.T) {
	previousNewEmbeddedClient := newEmbeddedClient
	previousVerifySOCKS5HTTP := verifySOCKS5HTTP
	previousWaitForSOCKS5Port := waitForSOCKS5Port
	t.Cleanup(func() {
		newEmbeddedClient = previousNewEmbeddedClient
		verifySOCKS5HTTP = previousVerifySOCKS5HTTP
		waitForSOCKS5Port = previousWaitForSOCKS5Port
	})

	var requestedAddr string
	client := &stubEmbeddedClient{}
	newEmbeddedClient = func(dnsAddr, tunnelDomain, publicKey, listenAddr string) (embeddedClient, error) {
		requestedAddr = listenAddr
		client.requestedAddr = listenAddr
		return client, nil
	}

	var verifiedAddr string
	verifySOCKS5HTTP = func(ctx context.Context, addr string, testURL string, username string, password string) error {
		verifiedAddr = addr
		return nil
	}
	waitForSOCKS5Port = func(ctx context.Context, addr string, client embeddedClient) error {
		return nil
	}

	ok, tunnelMS, e2eMS, err := dnsttCheck(
		context.Background(),
		"198.51.100.10",
		Config{Port: 53},
		"t.example.com",
		"deadbeef",
		2*time.Second,
		0,
		DefaultE2ETestURL,
		"",
		"",
	)
	if err != nil {
		t.Fatalf("dnsttCheck returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected dnsttCheck to succeed")
	}
	if tunnelMS < 0 || e2eMS < 0 {
		t.Fatalf("expected non-negative timings, got tunnel=%d e2e=%d", tunnelMS, e2eMS)
	}
	if requestedAddr != "127.0.0.1:0" {
		t.Fatalf("expected dynamic loopback listen address, got %q", requestedAddr)
	}
	if verifiedAddr == "" || strings.HasSuffix(verifiedAddr, ":0") {
		t.Fatalf("expected resolved listener address, got %q", verifiedAddr)
	}
	if verifiedAddr == requestedAddr {
		t.Fatalf("expected verify step to use the bound listener address, got %q", verifiedAddr)
	}
}

func nilContext() context.Context {
	return context.Background()
}

type stubEmbeddedClient struct {
	mu            sync.Mutex
	requestedAddr string
	listenAddr    string
	running       bool
}

func (c *stubEmbeddedClient) SetAuthoritativeMode(bool) {}

func (c *stubEmbeddedClient) SetMaxPayload(int) {}

func (c *stubEmbeddedClient) Start() error {
	c.mu.Lock()
	c.listenAddr = "127.0.0.1:19001"
	c.running = true
	c.mu.Unlock()
	return nil
}

func (c *stubEmbeddedClient) Stop() {
	c.mu.Lock()
	c.listenAddr = ""
	c.running = false
	c.mu.Unlock()
}

func (c *stubEmbeddedClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *stubEmbeddedClient) ListenAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listenAddr != "" {
		return c.listenAddr
	}
	return c.requestedAddr
}

type socksAuthAttempt struct {
	Username string
	Password string
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

func startTestSOCKS5Server(t *testing.T, username string, password string) (string, <-chan socksAuthAttempt, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}

	attempts := make(chan socksAuthAttempt, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- handleTestSOCKS5Conn(conn, username, password, attempts)
	}()

	shutdown := func() {
		_ = listener.Close()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
				t.Fatalf("socks5 server returned error: %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("timed out waiting for socks5 server shutdown")
		}
	}

	return listener.Addr().String(), attempts, shutdown
}

func handleTestSOCKS5Conn(conn net.Conn, username string, password string, attempts chan<- socksAuthAttempt) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("unexpected socks version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	method := byte(0x00)
	if username != "" {
		method = 0x02
		if !containsByte(methods, method) {
			if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
				return err
			}
			return nil
		}
	}
	if _, err := conn.Write([]byte{0x05, method}); err != nil {
		return err
	}

	if method == 0x02 {
		var authHeader [2]byte
		if _, err := io.ReadFull(reader, authHeader[:]); err != nil {
			return err
		}
		if authHeader[0] != 0x01 {
			return fmt.Errorf("unexpected auth version %d", authHeader[0])
		}

		usernameBytes := make([]byte, int(authHeader[1]))
		if _, err := io.ReadFull(reader, usernameBytes); err != nil {
			return err
		}

		passwordLen, err := reader.ReadByte()
		if err != nil {
			return err
		}
		passwordBytes := make([]byte, int(passwordLen))
		if _, err := io.ReadFull(reader, passwordBytes); err != nil {
			return err
		}

		attempt := socksAuthAttempt{
			Username: string(usernameBytes),
			Password: string(passwordBytes),
		}
		attempts <- attempt

		status := byte(0x00)
		if attempt.Username != username || attempt.Password != password {
			status = 0x01
		}
		if _, err := conn.Write([]byte{0x01, status}); err != nil {
			return err
		}
		if status != 0x00 {
			return nil
		}
	}

	var requestHeader [4]byte
	if _, err := io.ReadFull(reader, requestHeader[:]); err != nil {
		return err
	}
	if requestHeader[0] != 0x05 {
		return fmt.Errorf("unexpected request version %d", requestHeader[0])
	}
	if requestHeader[1] != 0x01 {
		return fmt.Errorf("unexpected socks command %d", requestHeader[1])
	}

	switch requestHeader[3] {
	case 0x01:
		if _, err := io.CopyN(io.Discard, reader, 4); err != nil {
			return err
		}
	case 0x03:
		hostLen, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, reader, int64(hostLen)); err != nil {
			return err
		}
	case 0x04:
		if _, err := io.CopyN(io.Discard, reader, 16); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected address type %d", requestHeader[3])
	}
	if _, err := io.CopyN(io.Discard, reader, 2); err != nil {
		return err
	}

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	_ = request.Body.Close()

	_, err = io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	return err
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
