package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"range-scout/internal/model"
	"range-scout/internal/prefixes"
)

type Format string

const (
	FormatTXT  Format = "txt"
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

func (f Format) String() string {
	return string(f)
}

func (f Format) Extension() string {
	return string(f)
}

func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "txt":
		return FormatTXT, nil
	case "csv":
		return FormatCSV, nil
	case "json":
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("unsupported format %q", value)
	}
}

func SavePrefixes(path string, format Format, result model.LookupResult) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}

	var data []byte
	var err error
	switch format {
	case FormatTXT:
		data = buildPrefixTXT(result)
	case FormatCSV:
		data, err = buildPrefixCSV(result)
	case FormatJSON:
		data, err = json.MarshalIndent(result, "", "  ")
	default:
		err = fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func SaveResolvers(path string, format Format, result model.ScanResult) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}

	var data []byte
	var err error
	switch format {
	case FormatTXT:
		data = buildResolverTXT(result)
	case FormatCSV:
		data, err = buildResolverCSV(result)
	case FormatJSON:
		data, err = json.MarshalIndent(result, "", "  ")
	default:
		err = fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func ensureParentDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output path is empty")
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func buildPrefixTXT(result model.LookupResult) []byte {
	var buffer bytes.Buffer
	for _, entry := range result.Entries {
		buffer.WriteString(entry.Prefix)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func buildPrefixCSV(result model.LookupResult) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"operator", "prefix", "source_asns", "total_addresses", "scan_hosts"}); err != nil {
		return nil, err
	}
	for _, entry := range result.Entries {
		record := []string{
			result.Operator.Name,
			entry.Prefix,
			prefixes.CompactASNLabel(entry.SourceASNs),
			fmt.Sprintf("%d", entry.TotalAddresses),
			fmt.Sprintf("%d", entry.ScanHosts),
		}
		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

func buildResolverTXT(result model.ScanResult) []byte {
	var buffer bytes.Buffer
	for _, resolver := range result.Resolvers {
		buffer.WriteString(resolver.IP)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

func buildResolverCSV(result model.ScanResult) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"operator", "ip", "dns_reachable", "recursion_available", "recursion_advertised", "stable", "response_code", "latency_ms", "prefix"}); err != nil {
		return nil, err
	}
	for _, resolver := range result.Resolvers {
		record := []string{
			result.Operator.Name,
			resolver.IP,
			fmt.Sprintf("%t", resolver.DNSReachable),
			fmt.Sprintf("%t", resolver.RecursionAvailable),
			fmt.Sprintf("%t", resolver.RecursionAdvertised),
			fmt.Sprintf("%t", resolver.Stable),
			resolver.ResponseCode,
			fmt.Sprintf("%d", resolver.LatencyMillis),
			resolver.Prefix,
		}
		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}
