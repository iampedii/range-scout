package ripestat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"range-scout/internal/model"
)

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
