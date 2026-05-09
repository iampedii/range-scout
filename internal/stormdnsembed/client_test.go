package stormdnsembed

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProbeMTUValidatesInputs(t *testing.T) {
	cases := []struct {
		name string
		opts ProbeOptions
		want error
	}{
		{
			name: "empty domain",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			want: ErrInvalidDomain,
		},
		{
			name: "empty key",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Domain: "t.example.com"},
			want: ErrInvalidKey,
		},
		{
			name: "non-base64 key",
			opts: ProbeOptions{ResolverIP: "1.1.1.1", ResolverPort: 53, Domain: "t.example.com", Key: "not!base64!"},
			want: ErrInvalidKey,
		},
		{
			name: "empty resolver IP",
			opts: ProbeOptions{ResolverPort: 53, Domain: "t.example.com", Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
			want: ErrInvalidResolver,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ProbeMTU(context.Background(), tc.opts)
			if res.Passed {
				t.Fatalf("expected Passed=false")
			}
			if !errors.Is(res.Err, tc.want) {
				t.Fatalf("got err %v, want %v", res.Err, tc.want)
			}
		})
	}
}

func TestProbeMTUTimesOutOnUnreachable(t *testing.T) {
	opts := ProbeOptions{
		ResolverIP:   "192.0.2.1",
		ResolverPort: 53,
		Domain:       "t.example.com",
		Key:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Timeout:      300 * time.Millisecond,
	}
	res := ProbeMTU(context.Background(), opts)
	if res.Passed {
		t.Fatalf("expected Passed=false on unreachable")
	}
	if res.Err == nil {
		t.Fatalf("expected non-nil Err")
	}
	if !errors.Is(res.Err, ErrProbeTimeout) {
		t.Fatalf("expected ErrProbeTimeout, got %v", res.Err)
	}
}
