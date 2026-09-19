package libclash

import (
	"errors"

	"cfa/native/app"
	"cfa/native/tunnel"
)

// Traffic exposes both counters without the old JNI's lossy 32-bit packing.
type Traffic struct {
	Upload   int64
	Download int64
}

func QueryTrafficNow() *Traffic      { up, down := tunnel.Now(); return &Traffic{up, down} }
func QueryTrafficTotal() *Traffic    { up, down := tunnel.Total(); return &Traffic{up, down} }
func QueryMemory() int64             { return int64(tunnel.Memory()) }
func QueryConnectionCount() int32    { return int32(tunnel.ConnectionCount()) }
func QueryConnections() string       { return marshalJSON(tunnel.Snapshot()) }
func CloseConnection(id string) bool { return tunnel.CloseConnection(id) }
func CloseAllConnections()           { tunnel.CloseAllConnections() }
func QueryTunnelState() string       { return marshalJSON(map[string]string{"mode": tunnel.QueryMode()}) }
func QueryProxies() string           { return marshalJSON(map[string]any{"proxies": tunnel.QueryProxies()}) }
func QueryProxyDelay(name, url string, timeoutMillis int32, expectedStatus string) string {
	delay, err := tunnel.QueryProxyDelay(name, url, int(timeoutMillis), expectedStatus)
	if err != nil {
		return errorResponse(err)
	}
	return marshalJSON(map[string]int{"delay": int(delay)})
}

func QueryProviderProxyDelay(provider, name, url string, timeoutMillis int32, expectedStatus string) string {
	delay, err := tunnel.QueryProviderProxyDelay(provider, name, url, int(timeoutMillis), expectedStatus)
	if err != nil {
		return errorResponse(err)
	}
	return marshalJSON(map[string]int{"delay": int(delay)})
}

func QueryGroupDelay(name, url string, timeoutMillis int32, expectedStatus string) string {
	delays, err := tunnel.QueryGroupDelay(name, url, int(timeoutMillis), expectedStatus)
	if err != nil {
		return errorResponse(err)
	}
	return marshalJSON(delays)
}

func PatchSelector(selector, name string) bool { return tunnel.PatchSelector(selector, name) }
func QueryProviders() string                   { return marshalJSON(tunnel.QueryProviders()) }
func QueryProvider(kind, name string) string {
	provider, err := tunnel.QueryProvider(kind, name, app.SubtitlePattern())
	if err != nil {
		return errorResponse(err)
	}
	return marshalJSON(provider)
}

func UpdateProvider(callback Completion, kind, name string) error {
	if callback == nil {
		return errors.New("completion callback is required")
	}
	go func() { callback.Complete(errorText(tunnel.UpdateProvider(kind, name))) }()
	return nil
}
