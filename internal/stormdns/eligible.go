package stormdns

import "range-scout/internal/model"

// EligibleResolvers returns indexes (into resolvers) of entries whose
// TunnelScore is >= scoreThreshold.
func EligibleResolvers(resolvers []model.Resolver, scoreThreshold int) []int {
	out := make([]int, 0, len(resolvers))
	for i, r := range resolvers {
		if r.TunnelScore >= scoreThreshold {
			out = append(out, i)
		}
	}
	return out
}
