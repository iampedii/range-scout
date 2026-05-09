package prefixes

import "net/netip"

var bogonPrefixes = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8",       // "this network"
		"10.0.0.0/8",      // RFC1918
		"100.64.0.0/10",   // CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local
		"172.16.0.0/12",   // RFC1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.88.99.0/24",  // 6to4 relay anycast (deprecated)
		"192.168.0.0/16",  // RFC1918
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved (incl. 255.255.255.255)
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsBogon returns true if addr is in any IANA IPv4 special-use range.
// Returns false for non-IPv4 addresses.
func IsBogon(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, p := range bogonPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PrefixIsFullyBogon reports whether every host in p is a bogon (i.e. p is
// contained in some bogon range). Used by Merge to drop user-supplied
// fully-private prefixes.
func PrefixIsFullyBogon(p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	for _, b := range bogonPrefixes {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
