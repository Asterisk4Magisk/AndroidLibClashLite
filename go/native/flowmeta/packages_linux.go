// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: LGPL-3.0

//go:build linux

package flowmeta

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func watchPackageFile(path string, changed, stopped func()) (func(), error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	_, err = syscall.InotifyAddWatch(fd, filepath.Dir(path), syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO|syscall.IN_DELETE|syscall.IN_MOVED_FROM|syscall.IN_ATTRIB)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "package-events")
	go func() {
		defer stopped()
		defer file.Close()
		var buffer [4096]byte
		for {
			n, err := file.Read(buffer[:])
			if err != nil {
				return
			}
			refresh := false
			for offset := 0; offset+syscall.SizeofInotifyEvent <= n; {
				event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
				end := offset + syscall.SizeofInotifyEvent + int(event.Len)
				if end > n {
					break
				}
				name := strings.TrimRight(string(buffer[offset+syscall.SizeofInotifyEvent:end]), "\x00")
				refresh = refresh || event.Mask&syscall.IN_Q_OVERFLOW != 0 || name == filepath.Base(path)
				offset = end
			}
			if refresh {
				changed()
			}
		}
	}()
	return func() { _ = file.Close() }, nil
}
