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

func nilContext() context.Context {
	return context.Background()
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
