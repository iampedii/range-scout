module range-scout

go 1.25.0

require (
	github.com/gdamore/tcell/v2 v2.13.8
	github.com/miekg/dns v1.1.68
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/rivo/tview v0.42.0
	github.com/xtaci/kcp-go/v5 v5.6.61
	github.com/xtaci/smux v1.5.50
	golang.org/x/net v0.51.0
	www.bamsoftware.com/git/dnstt.git v0.0.0-00010101000000-000000000000
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
)

replace www.bamsoftware.com/git/dnstt.git => ./third_party/dnstt

require range-scout/third_party/stormdns v0.0.0-local

replace range-scout/third_party/stormdns => ./third_party/stormdns
