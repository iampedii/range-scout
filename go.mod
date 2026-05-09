module range-scout

go 1.25.0

require (
	github.com/gdamore/tcell/v2 v2.13.8
	github.com/miekg/dns v1.1.68
	github.com/rivo/tview v0.42.0
	golang.org/x/net v0.51.0 // indirect
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.42.0 // indirect
)

require range-scout/third_party/stormdns v0.0.0-local

replace range-scout/third_party/stormdns => ./third_party/stormdns
