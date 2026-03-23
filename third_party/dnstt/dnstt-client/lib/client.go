package dnstt_client

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

var sigChan = make(chan os.Signal, 1)

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name.
func dnsNameCapacity(domain dns.Name) int {
	// Names must be 255 octets or shorter in total length.
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	capacity := 255
	// Subtract the length of the null terminator.
	capacity -= 1
	for _, label := range domain {
		// Subtract the length of the label and the length octet.
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to
	// encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// SampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func SampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		_ = stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		_ = local.CloseRead()
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		_ = local.CloseWrite()
	}()
	wg.Wait()

	return err
}

func AcceptLoop(ln *pt.SocksListener, utlsClientHelloID *utls.ClientHelloID, shutdown chan struct{}, wg *sync.WaitGroup) {
	defer func() {
		_ = ln.Close()
	}()

	for {
		local, err := ln.AcceptSocks()
		if err != nil {
			//goland:noinspection GoDeprecation
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}

			log.Printf("SOCKS accept error: %s", err)
			break
		}
		log.Printf("SOCKS accepted: %v", local.Req)

		wg.Add(1)
		go func() {
			defer func() {
				_ = local.Close()
				wg.Done()
			}()

			var pubkey []byte
			var remoteAddr net.Addr
			var pconn net.PacketConn
			var err error

			if arg, ok := local.Req.Args.Get("doh"); ok {
				remoteAddr = turbotunnel.DummyAddr{}
				var rt http.RoundTripper
				if utlsClientHelloID == nil {
					transport := http.DefaultTransport.(*http.Transport).Clone()
					// Disable DefaultTransport's default Proxy =
					// ProxyFromEnvironment setting, for conformity
					// with utlsRoundTripper and with DoT mode,
					// which do not take a proxy from the
					// environment.
					transport.Proxy = nil
					rt = transport
				} else {
					rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
				}
				pconn, err = NewHTTPPacketConn(rt, arg, 12)

			} else if arg, ok := local.Req.Args.Get("dot"); ok {
				remoteAddr = turbotunnel.DummyAddr{}
				var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
				if utlsClientHelloID == nil {
					dialTLSContext = (&tls.Dialer{}).DialContext
				} else {
					dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
					}
				}
				pconn, err = NewTLSPacketConn(arg, dialTLSContext)

			} else if arg, ok := local.Req.Args.Get("udp"); ok {
				remoteAddr, err = net.ResolveUDPAddr("udp", arg)
				if err == nil {
					pconn, err = net.ListenUDP("udp", nil)
				}
			}

			if err != nil {
				log.Printf("DNS server error: %v\n", err)
				_ = local.Reject()
				return
			}

			if remoteAddr == nil || pconn == nil {
				log.Printf("Missing DNS server. Use 'doh', 'dot' or 'udp' argument to provide one!")
				_ = local.Reject()
				return
			}

			if arg, ok := local.Req.Args.Get("pubkey"); ok {
				pubkey, err = noise.DecodeKey(arg)
				if err != nil {
					log.Printf("pubkey format error: %v", err)
					_ = local.Reject()
					return
				}
			} else {
				log.Print("Missing pubkey")
				_ = local.Reject()
				return
			}

			var domain dns.Name

			if arg, ok := local.Req.Args.Get("domain"); ok {
				domain, err = dns.ParseName(arg)
				if err != nil {
					log.Printf("invalid domain %+q: %v\n", arg, err)
					_ = local.Reject()
					return
				}
			} else {
				log.Print("Missing domain")
				_ = local.Reject()
				return
			}

			mtu := dnsNameCapacity(domain) - 8 - 1 - numPadding - 1 // clientid + padding length prefix + padding + data length prefix
			if mtu < 80 {
				log.Printf("domain %s leaves only %d bytes for payload", domain, mtu)

				_ = local.Reject()

				return
			}
			log.Printf("effective MTU %d", mtu)

			pconn = NewDNSPacketConn(pconn, remoteAddr, domain)

			defer func() {
				_ = pconn.Close()
			}()

			// Open a KCP conn on the PacketConn.
			conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
			if err != nil {
				log.Printf("opening KCP conn: %v", err)

				_ = local.Reject()

				return
			}
			log.Printf("begin session %08x", conn.GetConv())

			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				_ = conn.Close()
			}()

			// Permit coalescing the payloads of consecutive sends.
			conn.SetStreamMode(true)
			// Disable the dynamic congestion window (limit only by the maximum of
			// local and remote static windows).
			conn.SetNoDelay(
				0, // default nodelay
				0, // default interval
				0, // default resend
				1, // nc=1 => congestion window off
			)
			conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
			if rc := conn.SetMtu(mtu); !rc {
				panic(rc)
			}

			// Put a Noise channel on top of the KCP conn.
			rw, err := noise.NewClient(conn, pubkey)
			if err != nil {
				log.Printf("Opening noise channel: %v", err)

				_ = local.Reject()

				return
			}

			// Start a smux session on the Noise channel.
			smuxConfig := smux.DefaultConfig()
			smuxConfig.Version = 2
			smuxConfig.KeepAliveTimeout = idleTimeout
			smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
			sess, err := smux.Client(rw, smuxConfig)
			if err != nil {
				log.Printf("opening smux session: %v", err)

				_ = local.Reject()

				return
			}

			defer func() {
				_ = sess.Close()
			}()

			err = local.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				log.Printf("conn.Grant error: %s", err)

				return
			}

			handler := make(chan struct{})
			go func() {
				defer close(handler)

				err := handle(local.Conn.(*net.TCPConn), sess, conn.GetConv())
				if err != nil {
					log.Printf("handle: %v", err)
				}
			}()

			select {
			case <-shutdown:
				log.Println("Received shutdown signal")
			case <-handler:
				log.Println("Handler ended")
			}

			return
		}()
	}
}

func Start(listenAddr string, utlsClientHelloID *utls.ClientHelloID) {

	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	if flag.NArg() != 0 {
		flag.Usage()
		return
	}

	if utlsClientHelloID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Begin goptlib client process.
	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatal(err)
	}

	if ptInfo.ProxyURL != nil {
		_ = pt.ProxyError("proxy is not supported")
		return
	}

	listeners := make([]net.Listener, 0)
	shutdown := make(chan struct{})
	var wg sync.WaitGroup

	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "dnstt":

			ln, err := pt.ListenSocks("tcp", listenAddr)

			if err != nil {
				_ = pt.CmethodError(methodName, err.Error())
				break
			}

			go AcceptLoop(ln, utlsClientHelloID, shutdown, &wg)

			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)

		default:
			_ = pt.CmethodError(methodName, "no such method")
		}
	}

	pt.CmethodsDone()

	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
				log.Printf("calling io.Copy(ioutil.Discard, os.Stdin) returned error: %v", err)
			}
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// Wait for a signal.
	<-sigChan
	log.Println("stopping dnstt")

	// Signal received, shut down.
	for _, ln := range listeners {
		_ = ln.Close()
	}
	close(shutdown)
	wg.Wait()
	log.Println("dnstt is done.")
}

//goland:noinspection GoUnusedExportedFunction
func Stop() {
	log.Println("synthesizing SIGTERM because of explicit Stop call")
	sigChan <- syscall.SIGTERM
}
