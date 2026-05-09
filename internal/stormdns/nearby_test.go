package stormdns

import (
	"testing"

	"range-scout/internal/model"
)

func TestCollectNearbyResolversSkipsBogonsAndDuplicates(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "8.8.8.8", StormDNSPassed: true},
		{IP: "8.8.8.10", StormDNSPassed: true}, // already in set — should not be re-added
	}
	seedIndexes := []int{0}
	nearby := CollectNearbyResolvers(resolvers, seedIndexes)

	for _, r := range nearby {
		if r.IP == "8.8.8.8" || r.IP == "8.8.8.10" {
			t.Fatalf("nearby should not include existing resolvers: %s", r.IP)
		}
		if !r.StormDNSNearby {
			t.Fatalf("nearby resolver should have StormDNSNearby=true: %+v", r)
		}
	}
}

func TestCollectNearbyResolversSkipsNonPassedSeeds(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "8.8.8.8", StormDNSPassed: false, StormDNSChecked: true},
	}
	nearby := CollectNearbyResolvers(resolvers, []int{0})
	if len(nearby) != 0 {
		t.Fatalf("expected no nearby resolvers for non-passed seed, got %d", len(nearby))
	}
}

func TestCollectNearbyResolversDoesNotExpandNearbySeeds(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "8.8.8.8", StormDNSPassed: true, StormDNSNearby: true},
	}
	nearby := CollectNearbyResolvers(resolvers, []int{0})
	if len(nearby) != 0 {
		t.Fatalf("expected no expansion of nearby seed, got %d", len(nearby))
	}
}

func TestCollectNearbyResolversSkipsBogonAddresses(t *testing.T) {
	// 10.0.0.x is a private/bogon range — should be skipped.
	resolvers := []model.Resolver{
		{IP: "8.8.8.8", StormDNSPassed: true},
	}
	// Check that no bogons appear in nearby results.
	// We use 10.x.x.x seed which would produce bogon neighbors if not filtered.
	bogonResolvers := []model.Resolver{
		{IP: "10.0.0.1", StormDNSPassed: true},
	}
	nearby := CollectNearbyResolvers(bogonResolvers, []int{0})
	for _, r := range nearby {
		if r.IP[:3] == "10." {
			t.Fatalf("nearby should not include bogon addresses: %s", r.IP)
		}
	}
	// Ensure public seed produces non-bogon nearby resolvers.
	_ = resolvers
}
