// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

package flowmeta

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// PackageCache publishes immutable snapshots, updated by directory events.
// Socket ownership is deliberately not cached across connections.
type PackageCache struct {
	Path     string
	once     sync.Once
	mu       sync.Mutex
	info     os.FileInfo
	packages atomic.Pointer[map[uint32]string]
	watching atomic.Bool
	stop     func()
}

func (c *PackageCache) Lookup(uid uint32) string {
	c.once.Do(func() {
		c.watching.Store(true)
		stop, err := watchPackageFile(c.Path, c.refresh, func() { c.watching.Store(false) })
		if err != nil {
			c.watching.Store(false)
		} else {
			c.stop = stop
		}
		c.refresh()
	})
	// Unsupported watchers retain the stat-based compatibility behavior.
	if !c.watching.Load() {
		c.refresh()
	}
	if packages := c.packages.Load(); packages != nil {
		return (*packages)[uid%100000]
	}
	return ""
}

func (c *PackageCache) Close() {
	if c.stop != nil {
		c.stop()
	}
}

func (c *PackageCache) refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(c.Path)
	if err != nil {
		c.info = nil
		c.packages.Store(nil)
		return
	}
	if c.info == nil || !os.SameFile(info, c.info) || info.Size() != c.info.Size() || !info.ModTime().Equal(c.info.ModTime()) {
		file, err := os.Open(c.Path)
		if err != nil {
			return
		}
		defer file.Close()
		info, err = file.Stat()
		if err != nil {
			return
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
			return
		}
		c.info = info
		c.packages.Store(&packages)
	}
}
