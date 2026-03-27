package dnsttembed

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	dnsttdns "www.bamsoftware.com/git/dnstt.git/dns"
	dnsttclient "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	dnsttnoise "www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const idleTimeout = 2 * time.Minute

// Client is a minimal in-process DNSTT runtime for range-scout's desktop E2E
// flow. It is intentionally limited to the UDP resolver transport the app
// currently uses.
type Client struct {
	dnsAddr      string
	tunnelDomain string
	pubkey       []byte
	listenAddr   string

	authoritativeMode bool
	maxPayload        int

	mu            sync.Mutex
	running       bool
	cancel        context.CancelFunc
	listener      net.Listener
	transportConn net.PacketConn
	dnsConn       net.PacketConn
	kcpConn       net.Conn
	session       *smux.Session
}

func NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr string) (*Client, error) {
	if strings.TrimSpace(dnsAddr) == "" {
		return nil, fmt.Errorf("resolver address is required")
	}
	if strings.TrimSpace(tunnelDomain) == "" {
		return nil, fmt.Errorf("tunnel domain is required")
	}
	if strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if strings.TrimSpace(listenAddr) == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	pubkey, err := dnsttnoise.DecodeKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	return &Client{
		dnsAddr:      dnsAddr,
		tunnelDomain: tunnelDomain,
		pubkey:       pubkey,
		listenAddr:   listenAddr,
	}, nil
}

func (c *Client) SetAuthoritativeMode(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authoritativeMode = enabled
}

func (c *Client) SetMaxPayload(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxPayload = size
}

func (c *Client) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("client is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	authoritativeMode := c.authoritativeMode
	maxPayload := c.maxPayload
	c.cancel = cancel
	c.mu.Unlock()

	domain, err := dnsttdns.ParseName(c.tunnelDomain)
	if err != nil {
		c.shutdown()
		return fmt.Errorf("invalid tunnel domain: %w", err)
	}

	localAddr, err := net.ResolveTCPAddr("tcp", c.listenAddr)
	if err != nil {
		c.shutdown()
		return fmt.Errorf("resolve listen address: %w", err)
	}

	transportConn, remoteAddr, err := openTransport(c.dnsAddr, authoritativeMode)
	if err != nil {
		c.shutdown()
		return fmt.Errorf("open dns transport: %w", err)
	}

	var dnsConn net.PacketConn = dnsttclient.NewDNSPacketConnWithConfig(transportConn, remoteAddr, domain, dnsPacketConnConfig(authoritativeMode))
	if _, ok := remoteAddr.(turbotunnel.DummyAddr); ok {
		dnsConn = &addrNormConn{PacketConn: dnsConn, fixedAddr: remoteAddr}
	}

	mtu := dnsNameCapacity(domain) - 8 - 1 - dnsttclient.NumPadding - 1
	if mtu < 80 {
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("domain %s leaves only %d bytes for payload", domain, mtu)
	}
	if cappedPayload := effectiveMaxPayload(maxPayload, mtu); cappedPayload > 0 {
		mtu = cappedPayload
	}

	kcpConn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, dnsConn)
	if err != nil {
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("open kcp connection: %w", err)
	}
	kcpConn.SetStreamMode(true)
	if authoritativeMode {
		kcpConn.SetNoDelay(1, 20, 2, 1)
		kcpConn.SetACKNoDelay(true)
		kcpConn.SetWindowSize(256, 256)
	} else {
		kcpConn.SetNoDelay(0, 0, 0, 1)
		kcpConn.SetWindowSize(64, 64)
	}
	if !kcpConn.SetMtu(mtu) {
		_ = kcpConn.Close()
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("failed to set kcp mtu to %d", mtu)
	}

	noiseConn, err := dnsttnoise.NewClient(kcpConn, c.pubkey)
	if err != nil {
		_ = kcpConn.Close()
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("open noise channel: %w", err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	if authoritativeMode {
		// Keep the flag for interface compatibility even though the desktop flow
		// currently always uses the default tuning unless explicitly requested.
		smuxConfig.MaxStreamBuffer = 4 * 1024 * 1024
		smuxConfig.MaxReceiveBuffer = 16 * 1024 * 1024
	}

	session, err := smux.Client(noiseConn, smuxConfig)
	if err != nil {
		_ = kcpConn.Close()
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("open smux session: %w", err)
	}

	listener, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		_ = session.Close()
		_ = kcpConn.Close()
		_ = dnsConn.Close()
		_ = transportConn.Close()
		c.shutdown()
		return fmt.Errorf("open local listener: %w", err)
	}

	c.mu.Lock()
	c.listener = listener
	c.transportConn = transportConn
	c.dnsConn = dnsConn
	c.kcpConn = kcpConn
	c.session = session
	c.running = true
	c.mu.Unlock()

	go c.serve(ctx, listener, session, kcpConn.GetConv())
	return nil
}

func (c *Client) Stop() {
	c.shutdown()
}

func (c *Client) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *Client) ListenAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return c.listenAddr
}

func (c *Client) serve(ctx context.Context, listener net.Listener, session *smux.Session, conv uint32) {
	defer c.shutdown()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		localConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				continue
			}
			log.Printf("embedded dnstt accept: %v", err)
			return
		}

		tcpConn, ok := localConn.(*net.TCPConn)
		if !ok {
			_ = localConn.Close()
			continue
		}

		go func() {
			defer tcpConn.Close()
			if err := proxyTCPConn(tcpConn, session, conv); err != nil && !session.IsClosed() {
				log.Printf("embedded dnstt stream: %v", err)
			}
		}()
	}
}

func (c *Client) shutdown() {
	c.mu.Lock()
	cancel := c.cancel
	listener := c.listener
	transportConn := c.transportConn
	dnsConn := c.dnsConn
	kcpConn := c.kcpConn
	session := c.session

	c.cancel = nil
	c.listener = nil
	c.transportConn = nil
	c.dnsConn = nil
	c.kcpConn = nil
	c.session = nil
	c.running = false
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if session != nil {
		_ = session.Close()
	}
	if kcpConn != nil {
		_ = kcpConn.SetDeadline(time.Now())
		_ = kcpConn.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if dnsConn != nil {
		_ = dnsConn.Close()
	}
	if transportConn != nil {
		_ = transportConn.Close()
	}
}

func dnsNameCapacity(domain dnsttdns.Name) int {
	capacity := 254
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

func openTransport(dnsAddr string, authoritativeMode bool) (net.PacketConn, net.Addr, error) {
	switch {
	case strings.HasPrefix(dnsAddr, "https://"):
		transport := http.DefaultTransport.(*http.Transport).Clone()
		numSenders := 8
		var config *dnsttclient.HTTPPacketConnConfig
		if authoritativeMode {
			numSenders = 32
		} else {
			config = &dnsttclient.HTTPPacketConnConfig{
				RetryAfterDefault: 2 * time.Second,
				SleepOnRateLimit:  true,
			}
		}
		packetConn, err := dnsttclient.NewHTTPPacketConnWithConfig(transport, dnsAddr, numSenders, config)
		if err != nil {
			return nil, nil, err
		}
		return packetConn, turbotunnel.DummyAddr{}, nil
	case strings.HasPrefix(dnsAddr, "tls://"):
		packetConn, err := dnsttclient.NewTLSPacketConn(strings.TrimPrefix(dnsAddr, "tls://"), (&tls.Dialer{}).DialContext)
		if err != nil {
			return nil, nil, err
		}
		return packetConn, turbotunnel.DummyAddr{}, nil
	case strings.HasPrefix(dnsAddr, "tcp://"):
		packetConn, err := dnsttclient.NewTLSPacketConn(strings.TrimPrefix(dnsAddr, "tcp://"), func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		})
		if err != nil {
			return nil, nil, err
		}
		return packetConn, turbotunnel.DummyAddr{}, nil
	default:
		remoteAddr, err := net.ResolveUDPAddr("udp", dnsAddr)
		if err != nil {
			return nil, nil, err
		}
		packetConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, nil, err
		}
		return packetConn, remoteAddr, nil
	}
}

func dnsPacketConnConfig(authoritativeMode bool) *dnsttclient.DNSPacketConnConfig {
	if authoritativeMode {
		return &dnsttclient.DNSPacketConnConfig{
			PollLimit:     16,
			InitPollDelay: 200 * time.Millisecond,
			MaxPollDelay:  4 * time.Second,
		}
	}
	return &dnsttclient.DNSPacketConnConfig{PollLimit: 8}
}

func effectiveMaxPayload(requested int, mtu int) int {
	if requested >= 50 && requested < mtu {
		return requested
	}
	return 0
}

type addrNormConn struct {
	net.PacketConn
	fixedAddr net.Addr
}

func (a *addrNormConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := a.PacketConn.ReadFrom(p)
	return n, a.fixedAddr, err
}

func proxyTCPConn(local *net.TCPConn, session *smux.Session, conv uint32) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x open stream: %w", conv, err)
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(stream, local)
		if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, io.ErrClosedPipe) {
			log.Printf("embedded dnstt stream %08x:%d local->remote: %v", conv, stream.ID(), copyErr)
		}
		_ = local.CloseRead()
		_ = stream.Close()
	}()

	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(local, stream)
		if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, io.ErrClosedPipe) {
			log.Printf("embedded dnstt stream %08x:%d remote->local: %v", conv, stream.ID(), copyErr)
		}
		_ = local.CloseWrite()
	}()

	wg.Wait()
	return nil
}
