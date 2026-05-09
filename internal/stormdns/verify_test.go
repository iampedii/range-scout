package stormdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"range-scout/internal/model"
	"range-scout/internal/stormdnsembed"
)

type stubProber struct {
	results map[string]stormdnsembed.ProbeResult
}

func (s stubProber) ProbeMTU(ctx context.Context, opts stormdnsembed.ProbeOptions) stormdnsembed.ProbeResult {
	if r, ok := s.results[opts.ResolverIP]; ok {
		return r
	}
	return stormdnsembed.ProbeResult{Passed: false, Err: errors.New("stub: no result configured")}
}

func TestVerifyEmptyInputReturnsCleanly(t *testing.T) {
	r, err := Verify(context.Background(), nil, Config{Domain: "t.example.com", Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, nil)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if r.PassedCount != 0 || r.TestedCount != 0 {
		t.Fatalf("expected zero counts, got %+v", r)
	}
}

func TestVerifyMixedResults(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 6},
		{IP: "3.0.0.3", TunnelScore: 6},
	}
	stub := stubProber{
		results: map[string]stormdnsembed.ProbeResult{
			"1.0.0.1": {Passed: true, UpMTUBytes: 64, DownMTUBytes: 120},
			"2.0.0.2": {Passed: false, Err: stormdnsembed.ErrProbeTimeout},
			"3.0.0.3": {Passed: true, UpMTUBytes: 60, DownMTUBytes: 100},
		},
	}
	cfg := Config{
		Domain:         "t.example.com",
		Key:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ScoreThreshold: 2,
		Workers:        4,
		Timeout:        2 * time.Second,
		Prober:         stub,
	}
	r, err := Verify(context.Background(), resolvers, cfg, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.PassedCount != 2 {
		t.Fatalf("expected 2 passes, got %d", r.PassedCount)
	}
	if !r.Resolvers[0].StormDNSPassed {
		t.Fatalf("expected resolver 0 to pass; got %+v", r.Resolvers[0])
	}
	if r.Resolvers[1].StormDNSPassed {
		t.Fatalf("expected resolver 1 to fail; got %+v", r.Resolvers[1])
	}
}

func TestVerifyAbortsOnFiveKeyMismatches(t *testing.T) {
	resolvers := []model.Resolver{
		{IP: "1.0.0.1", TunnelScore: 6},
		{IP: "2.0.0.2", TunnelScore: 6},
		{IP: "3.0.0.3", TunnelScore: 6},
		{IP: "4.0.0.4", TunnelScore: 6},
		{IP: "5.0.0.5", TunnelScore: 6},
		{IP: "6.0.0.6", TunnelScore: 6},
		{IP: "7.0.0.7", TunnelScore: 6},
	}
	results := map[string]stormdnsembed.ProbeResult{}
	for _, r := range resolvers {
		results[r.IP] = stormdnsembed.ProbeResult{Passed: false, Err: stormdnsembed.ErrKeyMismatch}
	}
	cfg := Config{
		Domain:         "t.example.com",
		Key:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ScoreThreshold: 2,
		Workers:        1, // sequential to make abort behavior deterministic
		Timeout:        2 * time.Second,
		Prober:         stubProber{results: results},
	}
	_, err := Verify(context.Background(), resolvers, cfg, nil)
	if err == nil || !errors.Is(err, ErrKeyMismatchAbort) {
		t.Fatalf("expected ErrKeyMismatchAbort, got %v", err)
	}
}

func TestVerifyValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{"empty domain", Config{Key: "AAAA"}, ErrInvalidConfig},
		{"empty key", Config{Domain: "t.example.com"}, ErrInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(context.Background(), nil, tc.cfg, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
