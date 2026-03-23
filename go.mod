module range-scout

go 1.24.0

toolchain go1.24.1

require (
	github.com/gdamore/tcell/v2 v2.13.8
	github.com/miekg/dns v1.1.68
	github.com/refraction-networking/utls v1.8.2
	github.com/rivo/tview v0.42.0
	github.com/xtaci/kcp-go/v5 v5.6.61
	github.com/xtaci/smux v1.5.50
	golang.org/x/net v0.49.0
	www.bamsoftware.com/git/dnstt.git v0.0.0-00010101000000-000000000000
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/term v0.39.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
)

replace www.bamsoftware.com/git/dnstt.git => ./third_party/dnstt
