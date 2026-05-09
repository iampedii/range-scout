package ripestat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"range-scout/internal/model"
)

func TestLookupOperatorSurfacesBogonWarning(t *testing.T) {
	// AS returns only a bogon prefix; the result should carry a warning instead
	// of silently dropping it.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"10.0.0.0/24"}]}}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		ASNDelay:   0,
	}

	result, _ := client.LookupOperator(context.Background(), model.Operator{
		Key:  "test",
		Name: "Test",
		ASNs: []string{"AS1"},
	})

	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "bogon") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a bogon warning in result.Warnings, got %v", result.Warnings)
	}
}

func TestLookupOperatorFiltersIPv6AndMergesResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("resource") {
		case "AS1":
			_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"1.1.1.0/24"},{"prefix":"2001:db8::/32"}]}}`))
		case "AS2":
			_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"1.1.2.0/24"},{"prefix":"1.1.1.0/24"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		ASNDelay:   0,
	}

	result, err := client.LookupOperator(context.Background(), model.Operator{
		Key:  "test",
		Name: "Test Operator",
		ASNs: []string{"AS1", "AS2"},
	})
	if err != nil {
		t.Fatalf("LookupOperator returned error: %v", err)
	}

	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 unique IPv4 entries, got %d", len(result.Entries))
	}
	if result.TotalAddresses != 512 {
		t.Fatalf("expected total addresses 512, got %d", result.TotalAddresses)
	}
	if time.Since(result.FetchedAt) > time.Minute {
		t.Fatalf("unexpected fetch time: %v", result.FetchedAt)
	}
}
