package stormdns

import (
	"testing"

	"range-scout/internal/model"
)

func TestEligibleResolvers(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 3},
		{IP: "3.0.0.3", TunnelScore: 1},
		{IP: "4.0.0.4", TunnelScore: 0},
	}
	got := EligibleResolvers(resolvers, 2)
	want := []int{0, 1}
	if !equalIndexes(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func equalIndexes(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
