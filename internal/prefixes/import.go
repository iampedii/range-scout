package prefixes

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"

	"range-scout/internal/model"
)

const importedASNLabel = "IMPORT"

func ParseTXTTargets(text string) ([]model.PrefixEntry, uint64, uint64, []string, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	records := make([]SourcePrefix, 0)
	warnings := make([]string, 0)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := normalizeImportLine(scanner.Text())
		if line == "" {
			continue
		}

		prefix, err := normalizeImportedTarget(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %v", lineNumber, err))
			continue
		}

		records = append(records, SourcePrefix{
			ASN:    importedASNLabel,
			Prefix: prefix,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, 0, nil, fmt.Errorf("scan txt targets: %w", err)
	}
	if len(records) == 0 {
		return nil, 0, 0, warnings, fmt.Errorf("no valid IPv4 ranges or single IPs found")
	}

	entries, totalAddresses, totalScanHosts, err := Merge(records)
	if err != nil {
		return nil, 0, 0, warnings, err
	}
	return entries, totalAddresses, totalScanHosts, warnings, nil
}

func normalizeImportLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if hashIndex := strings.Index(line, "#"); hashIndex >= 0 {
		line = strings.TrimSpace(line[:hashIndex])
	}
	return line
}

func normalizeImportedTarget(value string) (string, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", fmt.Errorf("invalid target %q", value)
		}
		if !prefix.Addr().Is4() {
			return "", fmt.Errorf("IPv6 target %q is not supported", value)
		}
		return prefix.Masked().String(), nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("invalid target %q", value)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("IPv6 target %q is not supported", value)
	}
	return netip.PrefixFrom(addr, 32).String(), nil
}
