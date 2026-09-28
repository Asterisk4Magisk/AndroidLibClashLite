package config

import (
	"io"
	"os"
	"sync/atomic"

	"github.com/metacubex/mihomo/constant"
)

type OverrideSlot int

const (
	OverrideSlotPersist OverrideSlot = iota
	OverrideSlotSession
)

const defaultPersistOverride = `{}`
const defaultSessionOverride = `{}`

var sessionOverride atomic.Value // string; nil means the default override

func overridePersistPath() string {
	return constant.Path.Resolve("override.json")
}

func ReadOverride(slot OverrideSlot) string {
	switch slot {
	case OverrideSlotPersist:
		file, err := os.OpenFile(overridePersistPath(), os.O_RDONLY, 0600)
		if err != nil {
			return defaultPersistOverride
		}
		defer file.Close()

		buf, err := io.ReadAll(file)
		if err != nil {
			return defaultPersistOverride
		}

		return string(buf)
	case OverrideSlotSession:
		if value := sessionOverride.Load(); value != nil {
			return value.(string)
		}
		return defaultSessionOverride
	}

	return ""
}

func WriteOverride(slot OverrideSlot, content string) {
	switch slot {
	case OverrideSlotPersist:
		file, err := os.OpenFile(overridePersistPath(), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
		if err != nil {
			return
		}
		defer file.Close()

		_, err = file.Write([]byte(content))
	case OverrideSlotSession:
		sessionOverride.Store(content)
	}
}

func ClearOverride(slot OverrideSlot) {
	switch slot {
	case OverrideSlotPersist:
		_ = os.Remove(overridePersistPath())
	case OverrideSlotSession:
		sessionOverride.Store(defaultSessionOverride)
	}
}
