package prefixes

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"range-scout/internal/model"
)

type SourcePrefix struct {
	ASN    string
	Prefix string
}

// Merge dedupes prefixes by string, attaches all source ASNs, and returns the
// merged entries sorted by address+bits. Fully-bogon prefixes (entirely inside
// an IANA special-use range) are dropped from the result and returned in
// droppedBogons so the UI can surface a warning.
func Merge(records []SourcePrefix) ([]model.PrefixEntry, uint64, uint64, []string, error) {
	byPrefix := make(map[string]map[string]struct{})
	droppedBogons := []string{}
	seenDropped := map[string]struct{}{}

	for _, record := range records {
		prefix := strings.TrimSpace(record.Prefix)
		if prefix == "" {
			continue
		}

		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			return nil, 0, 0, nil, fmt.Errorf("parse prefix %q: %w", prefix, err)
		}
		if !parsed.Addr().Is4() {
			continue
		}

		if PrefixIsFullyBogon(parsed) {
			if _, seen := seenDropped[prefix]; !seen {
				droppedBogons = append(droppedBogons, prefix)
				seenDropped[prefix] = struct{}{}
			}
			continue
		}

		if _, ok := byPrefix[prefix]; !ok {
			byPrefix[prefix] = make(map[string]struct{})
		}
		byPrefix[prefix][record.ASN] = struct{}{}
	}

	entries := make([]model.PrefixEntry, 0, len(byPrefix))
	var totalAddresses uint64
	var totalScanHosts uint64

	for prefix, asnSet := range byPrefix {
		parsed, _ := netip.ParsePrefix(prefix)
		addressCount := addressCount(parsed)
		scanCount := usableHostCount(parsed)
		asns := make([]string, 0, len(asnSet))
		for asn := range asnSet {
			asns = append(asns, asn)
		}
		sort.Strings(asns)

		entries = append(entries, model.PrefixEntry{
			Prefix:         prefix,
			SourceASNs:     asns,
			TotalAddresses: addressCount,
			ScanHosts:      scanCount,
		})
		totalAddresses += addressCount
		totalScanHosts += scanCount
	}

	sort.Slice(entries, func(i, j int) bool {
		left, _ := netip.ParsePrefix(entries[i].Prefix)
		right, _ := netip.ParsePrefix(entries[j].Prefix)
		leftAddr := ipv4AsUint64(left.Masked().Addr())
		rightAddr := ipv4AsUint64(right.Masked().Addr())
		if leftAddr != rightAddr {
			return leftAddr < rightAddr
		}
		return left.Bits() < right.Bits()
	})

	return entries, totalAddresses, totalScanHosts, droppedBogons, nil
}

func EstimateScanTargets(entries []model.PrefixEntry, limit uint64) uint64 {
	var total uint64
	for _, entry := range entries {
		total += entry.ScanHosts
	}
	if limit > 0 && limit < total {
		return limit
	}
	return total
}

func WalkHosts(entries []model.PrefixEntry, limit uint64, yield func(addr netip.Addr, prefix string) bool) (uint64, error) {
	walked, _, err := WalkHostsCounted(entries, limit, yield)
	return walked, err
}

// WalkHostsCounted is like WalkHosts but additionally returns the number of
// host IPs skipped because they were in an IANA bogon range.
func WalkHostsCounted(entries []model.PrefixEntry, limit uint64, yield func(addr netip.Addr, prefix string) bool) (uint64, uint64, error) {
	var emitted, skipped uint64

	for _, entry := range entries {
		parsed, err := netip.ParsePrefix(entry.Prefix)
		if err != nil {
			return emitted, skipped, fmt.Errorf("parse prefix %q: %w", entry.Prefix, err)
		}
		if !parsed.Addr().Is4() {
			continue
		}

		start, end, ok := hostBounds(parsed)
		if !ok {
			continue
		}

		for current := start; current <= end; current++ {
			if limit > 0 && emitted >= limit {
				return emitted, skipped, nil
			}
			addr := uint64ToIPv4(current)
			if IsBogon(addr) {
				skipped++
				continue
			}
			if !yield(addr, entry.Prefix) {
				return emitted, skipped, nil
			}
			emitted++
		}
	}

	return emitted, skipped, nil
}

func addressCount(prefix netip.Prefix) uint64 {
	return uint64(1) << uint(32-prefix.Bits())
}

func usableHostCount(prefix netip.Prefix) uint64 {
	total := addressCount(prefix)
	if prefix.Bits() < 31 && total >= 2 {
		return total - 2
	}
	return total
}

func hostBounds(prefix netip.Prefix) (uint64, uint64, bool) {
	masked := prefix.Masked()
	base := ipv4AsUint64(masked.Addr())
	total := addressCount(masked)
	if total == 0 {
		return 0, 0, false
	}

	if masked.Bits() < 31 && total >= 2 {
		return base + 1, base + total - 2, true
	}

	return base, base + total - 1, true
}

func ipv4AsUint64(addr netip.Addr) uint64 {
	octets := addr.As4()
	return uint64(binary.BigEndian.Uint32(octets[:]))
}

func uint64ToIPv4(value uint64) netip.Addr {
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], uint32(value))
	return netip.AddrFrom4(octets)
}

func CompactASNLabel(asns []string) string {
	if len(asns) == 0 {
		return "-"
	}
	if len(asns) == 1 {
		return asns[0]
	}
	cloned := slices.Clone(asns)
	sort.Strings(cloned)
	return strings.Join(cloned, ", ")
}
