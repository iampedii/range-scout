package ripestat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"range-scout/internal/model"
	"range-scout/internal/prefixes"
)

const (
	defaultBaseURL = "https://stat.ripe.net/data/announced-prefixes/data.json"
	defaultSource  = "Automatic API Fetch"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	ASNDelay   time.Duration
}

type announcedPrefixesResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

func NewClient() *Client {
	return &Client{
		BaseURL: defaultBaseURL,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		ASNDelay: time.Second,
	}
}

func (c *Client) LookupOperator(ctx context.Context, operator model.Operator) (model.LookupResult, error) {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	records := make([]prefixes.SourcePrefix, 0)
	warnings := make([]string, 0)

	for index, asn := range operator.ASNs {
		if index > 0 && c.ASNDelay > 0 {
			timer := time.NewTimer(c.ASNDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return model.LookupResult{}, ctx.Err()
			case <-timer.C:
			}
		}

		items, err := c.lookupASN(ctx, httpClient, baseURL, asn)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", asn, err))
			continue
		}
		for _, prefix := range items {
			records = append(records, prefixes.SourcePrefix{
				ASN:    asn,
				Prefix: prefix,
			})
		}
	}

	if len(records) == 0 {
		if len(warnings) == 0 {
			return model.LookupResult{}, errors.New("no prefixes returned")
		}
		return model.LookupResult{}, errors.New(strings.Join(warnings, "; "))
	}

	entries, totalAddresses, totalScanHosts, err := prefixes.Merge(records)
	if err != nil {
		return model.LookupResult{}, err
	}

	result := model.LookupResult{
		Operator:       operator,
		Entries:        entries,
		TotalAddresses: totalAddresses,
		TotalScanHosts: totalScanHosts,
		FetchedAt:      time.Now(),
		Warnings:       warnings,
		SourceLabel:    defaultSource,
		SourceURL:      defaultBaseURL,
	}

	if len(warnings) > 0 {
		return result, errors.New(strings.Join(warnings, "; "))
	}

	return result, nil
}

func (c *Client) lookupASN(ctx context.Context, httpClient *http.Client, baseURL, asn string) ([]string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}

	query := parsedURL.Query()
	query.Set("resource", asn)
	parsedURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "range-scout/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	var payload announcedPrefixesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	prefixesOut := make([]string, 0, len(payload.Data.Prefixes))
	for _, item := range payload.Data.Prefixes {
		if strings.Contains(item.Prefix, ":") {
			continue
		}
		prefixesOut = append(prefixesOut, item.Prefix)
	}

	return prefixesOut, nil
}
