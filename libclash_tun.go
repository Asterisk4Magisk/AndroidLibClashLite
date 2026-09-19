package libclash

import (
	"context"
	"errors"
	"io"
	"sync"

	"cfa/native/app"
	"cfa/native/tun"
	"golang.org/x/sync/semaphore"
)

// TunInterface connects Android socket protection and UID lookup to the core.
// Callbacks must finish promptly and must not call StopTun/StopTunContext.
type TunInterface interface {
	MarkSocket(fd int32)
	QuerySocketUid(protocol int32, source, target string) int32
}

var tunLock sync.Mutex
var activeTun *remoteTun

type remoteTun struct {
	closer   io.Closer
	callback TunInterface
	closed   bool
	limit    *semaphore.Weighted
}

func (t *remoteTun) markSocket(fd int) {
	_ = t.limit.Acquire(context.Background(), 1)
	defer t.limit.Release(1)
	if !t.closed {
		t.callback.MarkSocket(int32(fd))
	}
}

func (t *remoteTun) querySocketUid(protocol int, source, target string) int {
	_ = t.limit.Acquire(context.Background(), 1)
	defer t.limit.Release(1)
	if t.closed {
		return -1
	}
	return int(t.callback.QuerySocketUid(int32(protocol), source, target))
}

func (t *remoteTun) close() {
	_ = t.limit.Acquire(context.Background(), 4)
	t.closed = true
	t.callback = nil
	t.limit.Release(4)
	// Closing the stack must not hold the callback semaphore: shutdown can wait
	// for workers that still need to observe closed.
	if t.closer != nil {
		_ = t.closer.Close()
	}
	app.ApplyTunContext(nil, nil)
}

// StartTun borrows the Android VPN descriptor and retains its own duplicate.
// The caller must close its descriptor after this call, on success or failure.
func StartTun(fd int32, stack, gateway, portal, dns string, callback TunInterface) error {
	if fd <= 0 || callback == nil {
		return errors.New("valid TUN fd and callback are required")
	}
	tunLock.Lock()
	defer tunLock.Unlock()
	if activeTun != nil {
		activeTun.close()
		activeTun = nil
	}
	remote := &remoteTun{callback: callback, limit: semaphore.NewWeighted(4)}
	app.ApplyTunContext(remote.markSocket, remote.querySocketUid)
	closer, err := tun.Start(int(fd), stack, gateway, portal, dns)
	if err != nil {
		remote.close()
		return err
	}
	remote.closer = closer
	activeTun = remote
	return nil
}

// StartTunContext installs protection/UID callbacks without creating a TUN stack.
func StartTunContext(callback TunInterface) error {
	if callback == nil {
		return errors.New("TUN callback is required")
	}
	tunLock.Lock()
	defer tunLock.Unlock()
	if activeTun != nil {
		activeTun.close()
	}
	activeTun = &remoteTun{callback: callback, limit: semaphore.NewWeighted(4)}
	app.ApplyTunContext(activeTun.markSocket, activeTun.querySocketUid)
	return nil
}

func StopTunContext() {
	tunLock.Lock()
	defer tunLock.Unlock()
	if activeTun != nil && activeTun.closer == nil {
		activeTun.close()
		activeTun = nil
	}
}

// StopTun waits for in-flight callbacks before releasing their Java references.
func StopTun() {
	tunLock.Lock()
	defer tunLock.Unlock()
	if activeTun != nil {
		activeTun.close()
		activeTun = nil
	}
}
