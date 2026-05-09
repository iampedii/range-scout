package stormdns

import (
	"fmt"
	"net/netip"
	"strings"

	"range-scout/internal/model"
	"range-scout/internal/prefixes"
)

// CollectNearbyResolvers returns new model.Resolver entries for each /24-neighbor
// of any seed resolver that:
//   - has StormDNSPassed == true
//   - is not already present in the resolvers slice
//   - is not a bogon address (per prefixes.IsBogon)
//
// Each returned resolver has StormDNSNearby = true. Nearby-discovered resolvers
// do not trigger further fan-out.
func CollectNearbyResolvers(resolvers []model.Resolver, seedIndexes []int) []model.Resolver {
	seenIPs := make(map[string]struct{}, len(resolvers))
	for _, r := range resolvers {
		seenIPs[r.IP] = struct{}{}
	}

	expandedSubnets := make(map[string]struct{})
	nearby := make([]model.Resolver, 0)

	for _, idx := range seedIndexes {
		if idx < 0 || idx >= len(resolvers) {
			continue
		}
		seed := resolvers[idx]
		if seed.StormDNSNearby {
			// Never expand a nearby resolver again.
			continue
		}
		if !seed.StormDNSPassed {
			continue
		}

		ip, ok := parseIPv4(seed.IP)
		if !ok {
			continue
		}

		subnetKey, subnetPrefix := subnetLabel(ip)
		if _, ok := expandedSubnets[subnetKey]; ok {
			continue
		}
		expandedSubnets[subnetKey] = struct{}{}

		for lastOctet := 0; lastOctet < 256; lastOctet++ {
			candidate := netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], byte(lastOctet)})
			candidateStr := candidate.String()
			if _, exists := seenIPs[candidateStr]; exists {
				continue
			}
			if prefixes.IsBogon(candidate) {
				continue
			}
			seenIPs[candidateStr] = struct{}{}
			nearby = append(nearby, model.Resolver{
				IP:             candidateStr,
				Prefix:         subnetPrefix,
				StormDNSNearby: true,
			})
		}
	}

	return nearby
}

func parseIPv4(raw string) ([4]byte, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return [4]byte{}, false
	}
	return addr.As4(), true
}

func subnetLabel(ip [4]byte) (string, string) {
	subnet := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
	return subnet, fmt.Sprintf("%s.0/24", subnet)
}
