// Package libclash exposes the Android Mihomo core through gomobile bindings.
// Initialize once per process before calling the other functions. JNI callbacks
// may run on Go worker threads; Android callers must marshal UI work themselves.
package libclash

import (
	"errors"
	"runtime"
	"runtime/debug"
	"sync"

	"cfa/native/app"
	"cfa/native/config"
	"cfa/native/delegate"
	"cfa/native/profilecache"
	"cfa/native/tunnel"

	"github.com/metacubex/mihomo/constant"
)

// ContentResolver opens content:// URIs. Return a detached, owned file descriptor;
// the core closes it after reading. Throwing in Java is converted to a Go error.
type ContentResolver interface {
	OpenContent(uri string) (int32, error)
}

var initOnce sync.Once

// Init configures Android embedding. The platform resolver is retained for the
// process lifetime. The standalone CLI never calls this function.
func Init(home, appVersion string, sdkVersion int32, resolver ContentResolver) error {
	if home == "" || resolver == nil {
		return errors.New("home and content resolver are required")
	}
	initOnce.Do(func() {
		app.ApplyContentContext(func(uri string) (int, error) {
			fd, err := resolver.OpenContent(uri)
			if err == nil && fd < 0 {
				err = errors.New("content resolver returned a negative file descriptor")
			}
			return int(fd), err
		})
		delegate.Init(home, appVersion, int(sdkVersion))
		Reset()
	})
	return nil
}

func CoreVersion() string { return constant.Version }

func Reset() {
	config.LoadDefault()
	tunnel.ResetStatistic()
	tunnel.CloseAllConnections()
	profilecache.Reset()
	runtime.GC()
	debug.FreeOSMemory()
}
