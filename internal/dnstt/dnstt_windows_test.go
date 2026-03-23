//go:build windows

package dnstt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsExecutableRecognizesWindowsExecutableExtensions(t *testing.T) {
	dir := t.TempDir()

	exePath := filepath.Join(dir, "dnstt-client.exe")
	if err := os.WriteFile(exePath, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	info, err := os.Stat(exePath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if !isExecutable(exePath, info) {
		t.Fatal("expected .exe file to be treated as executable on windows")
	}

	textPath := filepath.Join(dir, "dnstt-client.txt")
	if err := os.WriteFile(textPath, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	info, err = os.Stat(textPath)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if isExecutable(textPath, info) {
		t.Fatal("expected .txt file to be treated as non-executable on windows")
	}
}
