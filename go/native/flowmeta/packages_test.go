// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package flowmeta

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageCacheRefreshesAndKeepsFullUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packages.list")
	cache := PackageCache{Path: path}
	if cache.Lookup(1012345) != "" {
		t.Fatal("missing file returned a package")
	}
	if err := os.WriteFile(path, []byte("first 12345 extra\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if cache.Lookup(1012345) != "first" || cache.Lookup(112345) != "first" {
		t.Fatal("multi-user app ID lost")
	}
	info, _ := os.Stat(path)
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("other 12345 extra\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(replacement, info.ModTime(), info.ModTime())
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if cache.Lookup(1012345) != "other" {
		t.Fatal("same-size atomic replacement was not detected")
	}
	_ = os.Remove(path)
	if cache.Lookup(1012345) != "" {
		t.Fatal("removed package snapshot remained cached")
	}
}
