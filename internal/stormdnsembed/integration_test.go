//go:build integration

package stormdnsembed

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestProbeMTUAgainstRealServer(t *testing.T) {
	domain := os.Getenv("STORMDNS_DOMAIN")
	key := os.Getenv("STORMDNS_KEY")
	if domain == "" || key == "" {
		t.Skip("set STORMDNS_DOMAIN and STORMDNS_KEY to run integration test")
	}
	resolver := os.Getenv("STORMDNS_RESOLVER")
	if resolver == "" {
		resolver = "8.8.8.8"
	}

	res := ProbeMTU(context.Background(), ProbeOptions{
		ResolverIP:   resolver,
		ResolverPort: 53,
		Domain:       domain,
		Key:          key,
		Timeout:      30 * time.Second,
	})
	if !res.Passed {
		t.Fatalf("ProbeMTU failed against real server: err=%v", res.Err)
	}
	if res.UpMTUBytes <= 0 || res.DownMTUBytes <= 0 {
		t.Fatalf("expected positive MTU values, got up=%d down=%d", res.UpMTUBytes, res.DownMTUBytes)
	}
}
