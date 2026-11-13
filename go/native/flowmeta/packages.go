// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package flowmeta

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

// PackageCache reloads Android's package snapshot only when the file changes.
// Socket ownership is deliberately not cached across connections.
type PackageCache struct {
	Path     string
	mu       sync.Mutex
	info     os.FileInfo
	packages map[uint32]string
}

func (c *PackageCache) Lookup(uid uint32) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(c.Path)
	if err != nil {
		c.info, c.packages = nil, nil
		return ""
	}
	if c.info == nil || !os.SameFile(info, c.info) || info.Size() != c.info.Size() || !info.ModTime().Equal(c.info.ModTime()) {
		file, err := os.Open(c.Path)
		if err != nil {
			return ""
		}
		defer file.Close()
		info, err = file.Stat()
		if err != nil {
			return ""
		}
		packages := make(map[uint32]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}
			id, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil {
				if _, exists := packages[uint32(id)]; !exists {
					packages[uint32(id)] = fields[0]
				}
			}
		}
		if scanner.Err() != nil {
			return ""
		}
		c.info, c.packages = info, packages
	}
	return c.packages[uid%100000]
}
