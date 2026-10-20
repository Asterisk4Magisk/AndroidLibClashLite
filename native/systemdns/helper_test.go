//go:build android || linux

package systemdns

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHelperReuseAndReplacement(t *testing.T) {
	home := t.TempDir()
	payload := []byte("current embedded dex")
	path, err := ensureHelper(home, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse preserves file identity/mtime, allowing ART to retain its cache.
	oldTime := time.Unix(1234567890, 0)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if _, err = ensureHelper(home, payload); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || !after.ModTime().Equal(oldTime) || after.Mode().Perm() != 0400 {
		t.Fatal("matching helper was rewritten or has incorrect permissions")
	}
	for _, stale := range [][]byte{[]byte("old version"), []byte("xurrent embedded dex"), nil} {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, stale, 0600); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(path)
		if _, err := ensureHelper(home, payload); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(path)
		after, _ := os.Stat(path)
		if err != nil || !bytes.Equal(content, payload) || os.SameFile(before, after) || after.Mode().Perm() != 0400 {
			t.Fatal("stale helper was not atomically replaced")
		}
	}
	files, _ := os.ReadDir(home)
	if len(files) != 1 || files[0].Name() != helperFilename {
		t.Fatal("temporary files left behind")
	}
}

func TestHelperDoesNotFollowSymlink(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, helperFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHelper(home, []byte("embedded dex")); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "keep" {
		t.Fatal("helper update changed the symlink target")
	}
}
