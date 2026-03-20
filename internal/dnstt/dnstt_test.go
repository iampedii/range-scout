package dnstt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"range-scout/internal/model"
)

func TestEligibleResolversFiltersStableRecursiveCandidates(t *testing.T) {
	indexes := EligibleResolvers([]model.Resolver{
		{IP: "198.51.100.10", RecursionAvailable: true, Stable: true},
		{IP: "198.51.100.11", RecursionAvailable: true, Stable: false},
		{IP: "198.51.100.12", RecursionAvailable: false, Stable: true},
	})

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
		{IP: "127.0.0.1", Prefix: "127.0.0.1/32", RecursionAvailable: true, Stable: true},
		{IP: "127.0.0.2", Prefix: "127.0.0.0/24", RecursionAvailable: false, Stable: true},
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

func TestTestReturnsErrorWhenNoHealthyResolversExist(t *testing.T) {
	_, _, err := Test(nilContext(), []model.Resolver{
		{IP: "198.51.100.10", RecursionAvailable: true, Stable: false},
	}, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Domain:  "t.example.com",
	}, nil)
	if err == nil {
		t.Fatal("expected an error when no healthy resolvers exist")
	}
}

func TestPlatformVariantsIncludeReleaseNames(t *testing.T) {
	variants := platformVariants("dnstt-client")

	switch runtime.GOOS {
	case "windows":
		if len(variants) == 0 || variants[0] != "dnstt-client.exe" {
			t.Fatalf("expected windows variant first, got %#v", variants)
		}
	case "linux":
		if !containsString(variants, "dnstt-client-linux") {
			t.Fatalf("expected linux release variant, got %#v", variants)
		}
	case "darwin":
		if !containsString(variants, "dnstt-client-darwin") {
			t.Fatalf("expected darwin release variant, got %#v", variants)
		}
	}
}

func TestFindClientBinaryFindsPlatformVariantInCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
		_ = os.Setenv("PATH", oldPath)
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatalf("Setenv returned error: %v", err)
	}

	variant := platformVariants("dnstt-client")[0]
	if variants := platformVariants("dnstt-client"); len(variants) > 1 {
		variant = variants[1]
	}
	target := filepath.Join(dir, variant)
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	path, err := FindClientBinary()
	if err != nil {
		t.Fatalf("FindClientBinary returned error: %v", err)
	}
	if filepath.Base(path) != variant {
		t.Fatalf("unexpected binary path: got %q want base %q", path, variant)
	}
}

func TestFindClientBinaryErrorIncludesInstallHint(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
		_ = os.Setenv("PATH", oldPath)
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatalf("Setenv returned error: %v", err)
	}

	_, err = FindClientBinary()
	if err == nil {
		t.Fatal("expected FindClientBinary to return an error when nothing is installed")
	}
	if !strings.Contains(err.Error(), "go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest") {
		t.Fatalf("expected install hint in error, got: %v", err)
	}
}

func TestPrepareConfigDefaultsE2EPortTo53WhenPubkeySet(t *testing.T) {
	cfg, _, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", RecursionAvailable: true, Stable: true},
	}, Config{
		Workers:    1,
		Timeout:    500 * time.Millisecond,
		E2ETimeout: 5 * time.Second,
		Domain:     "t.example.com",
		Pubkey:     "deadbeef",
		BinaryPath: "/tmp/dnstt-client",
	})
	if err != nil {
		t.Fatalf("prepareConfig returned error: %v", err)
	}
	if cfg.E2EPort != 53 {
		t.Fatalf("unexpected default e2e port: %d", cfg.E2EPort)
	}
}

func TestPrepareConfigAllowsZeroE2EPortInTunnelOnlyMode(t *testing.T) {
	cfg, _, _, err := prepareConfig([]model.Resolver{
		{IP: "198.51.100.10", RecursionAvailable: true, Stable: true},
	}, Config{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Domain:  "t.example.com",
	})
	if err != nil {
		t.Fatalf("prepareConfig returned error: %v", err)
	}
	if cfg.E2EPort != 0 {
		t.Fatalf("unexpected tunnel-only e2e port mutation: %d", cfg.E2EPort)
	}
}

func TestBuildSOCKS5ConnectRequestForIPv4(t *testing.T) {
	request, err := buildSOCKS5ConnectRequest("8.8.8.8", 53)
	if err != nil {
		t.Fatalf("buildSOCKS5ConnectRequest returned error: %v", err)
	}
	want := []byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	if string(request) != string(want) {
		t.Fatalf("unexpected request bytes: %#v", request)
	}
}

func TestPerformSOCKS5GreetingReturnsSelectedMethodLikeFindns(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		defer server.Close()
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(server, greeting); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) {
			done <- errors.New("unexpected greeting bytes")
			return
		}
		_, err := server.Write([]byte{0x05, 0xff})
		done <- err
	}()

	method, err := performSOCKS5Greeting(client)
	if err != nil {
		t.Fatalf("performSOCKS5Greeting returned error: %v", err)
	}
	if method != 0xff {
		t.Fatalf("unexpected selected method: 0x%02x", method)
	}
	if err := <-done; err != nil {
		t.Fatalf("server goroutine returned error: %v", err)
	}
}

func TestFormatSOCKS5ConnectReplyErrorUsesTunnelMessageForEOF(t *testing.T) {
	err := formatSOCKS5ConnectReplyError(io.EOF)
	if err == nil || err.Error() != "no CONNECT reply from tunnel" {
		t.Fatalf("unexpected EOF connect reply error: %v", err)
	}
}

func TestWaitAndTestSOCKS5ConnectContinuesAfterNonNoAuthMethodLikeFindns(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	handled := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			handled <- err
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			handled <- err
			return
		}
		if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) {
			handled <- errors.New("unexpected greeting bytes")
			return
		}
		if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
			handled <- err
			return
		}

		connectReq := make([]byte, 10)
		if _, err := io.ReadFull(conn, connectReq); err != nil {
			handled <- err
			return
		}
		if !bytes.Equal(connectReq, []byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}) {
			handled <- errors.New("unexpected connect request bytes")
			return
		}
		_, err = conn.Write([]byte{0x05, 0x01, 0x00, 0x01})
		handled <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	exited := make(chan error)

	err = waitAndTestSOCKS5Connect(ctx, listener.Addr().(*net.TCPAddr).Port, "8.8.8.8", 53, exited)
	if err != nil {
		t.Fatalf("waitAndTestSOCKS5Connect returned error: %v", err)
	}
	if err := <-handled; err != nil {
		t.Fatalf("server goroutine returned error: %v", err)
	}
}

func TestWaitAndTestSOCKS5ConnectFailsWithoutConnectReplyAfterMethodSelection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	handled := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			handled <- err
			return
		}
		defer conn.Close()

		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			handled <- err
			return
		}
		if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
			handled <- err
			return
		}

		connectReq := make([]byte, 10)
		if _, err := io.ReadFull(conn, connectReq); err != nil {
			handled <- err
			return
		}
		handled <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	exited := make(chan error)

	err = waitAndTestSOCKS5Connect(ctx, listener.Addr().(*net.TCPAddr).Port, "8.8.8.8", 53, exited)
	if err == nil || err.Error() != "no CONNECT reply from tunnel" {
		t.Fatalf("unexpected waitAndTestSOCKS5Connect error: %v", err)
	}
	if err := <-handled; err != nil {
		t.Fatalf("server goroutine returned error: %v", err)
	}
}

func nilContext() context.Context {
	return context.Background()
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
