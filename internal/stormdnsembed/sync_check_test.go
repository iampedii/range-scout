package stormdnsembed

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSyncMDHasValidCommit(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "third_party/stormdns/SYNC.md"))
	if err != nil {
		t.Fatalf("read SYNC.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^Commit:\s*([0-9a-fA-F]{40})\s*$`)
	if !re.Match(body) {
		t.Fatalf("SYNC.md has no `Commit: <40-char SHA>` line:\n%s", body)
	}
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			b, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
			if strings.HasPrefix(string(b), "module range-scout") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
