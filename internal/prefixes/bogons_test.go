package prefixes

import (
	"net/netip"
	"testing"
)

func TestPrefixIsFullyBogon(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		expect bool
	}{
		{"exact-rfc1918-10", "10.0.0.0/8", true},
		{"sub-prefix-rfc1918", "10.5.0.0/16", true},
		{"micro-sub-prefix", "10.0.0.0/30", true},
		{"exact-rfc1918-172", "172.16.0.0/12", true},
		{"exact-cgnat", "100.64.0.0/10", true},
		{"sub-cgnat", "100.100.0.0/16", true},
		{"public-supernet-spans-bogon", "172.0.0.0/8", false},
		{"public-supernet-of-public", "8.8.8.0/24", false},
		{"public", "1.1.1.0/24", false},
		{"slash-zero-not-fully-bogon", "0.0.0.0/0", false},
		{"loopback-host", "127.0.0.1/32", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			got := PrefixIsFullyBogon(p)
			if got != tc.expect {
				t.Fatalf("PrefixIsFullyBogon(%s) = %v, want %v", tc.prefix, got, tc.expect)
			}
		})
	}
}

func TestIsBogon(t *testing.T) {
	cases := []struct {
		name   string
		ip     string
		expect bool
	}{
		{"this-network-first", "0.0.0.0", true},
		{"this-network-mid", "0.123.45.6", true},
		{"this-network-last", "0.255.255.255", true},
		{"public-1.1.1.1", "1.1.1.1", false},
		{"rfc1918-10-first", "10.0.0.0", true},
		{"rfc1918-10-last", "10.255.255.255", true},
		{"public-11.0.0.1", "11.0.0.1", false},
		{"cgnat-first", "100.64.0.0", true},
		{"cgnat-last", "100.127.255.255", true},
		{"public-100.128.0.1", "100.128.0.1", false},
		{"loopback-first", "127.0.0.0", true},
		{"loopback-last", "127.255.255.255", true},
		{"public-128.0.0.1", "128.0.0.1", false},
		{"link-local-first", "169.254.0.0", true},
		{"link-local-last", "169.254.255.255", true},
		{"rfc1918-172-first", "172.16.0.0", true},
		{"rfc1918-172-last", "172.31.255.255", true},
		{"public-172.32.0.1", "172.32.0.1", false},
		{"public-172.15.255.255", "172.15.255.255", false},
		{"ietf-protocol", "192.0.0.5", true},
		{"test-net-1", "192.0.2.50", true},
		{"6to4-relay", "192.88.99.1", true},
		{"rfc1918-192-first", "192.168.0.0", true},
		{"rfc1918-192-last", "192.168.255.255", true},
		{"benchmarking-first", "198.18.0.0", true},
		{"benchmarking-last", "198.19.255.255", true},
		{"test-net-2", "198.51.100.10", true},
		{"test-net-3", "203.0.113.10", true},
		{"public-198.20.0.1", "198.20.0.1", false},
		{"multicast-first", "224.0.0.0", true},
		{"multicast-last", "239.255.255.255", true},
		{"reserved-first", "240.0.0.0", true},
		{"reserved-last", "255.255.255.254", true},
		{"broadcast", "255.255.255.255", true},
		{"public-google-dns", "8.8.8.8", false},
		{"public-cloudflare-dns", "1.1.1.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBogon(netip.MustParseAddr(tc.ip))
			if got != tc.expect {
				t.Fatalf("IsBogon(%s) = %v, want %v", tc.ip, got, tc.expect)
			}
		})
	}
}
