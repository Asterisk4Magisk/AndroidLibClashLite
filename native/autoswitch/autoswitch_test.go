package autoswitch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfa/native/autoswitch/option"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// fakeNode dials the local test server when healthy, regardless of the URL host.
type fakeNode struct {
	*outbound.Base
	target  string
	healthy bool
}

func (n *fakeNode) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	if !n.healthy {
		return nil, errors.New("node is down")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", n.target)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, n), nil
}

func installGroup(t *testing.T, server *httptest.Server, selected string, nodes map[string]bool) *outboundgroup.Selector {
	t.Helper()
	// Mirrors config parsing, which always provides the empty-fallback proxy.
	proxies := map[string]C.Proxy{"COMPATIBLE": adapter.NewProxy(outbound.NewCompatible())}
	names := make([]string, 0, len(nodes))
	for _, name := range []string{"A", "B", "HK 01", "C"} {
		healthy, ok := nodes[name]
		if !ok {
			continue
		}
		node := &fakeNode{Base: outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Socks5}),
			target: server.Listener.Addr().String(), healthy: healthy}
		proxies[name] = adapter.NewProxy(node)
		names = append(names, name)
	}
	group, err := outboundgroup.ParseProxyGroup(map[string]any{"name": "G", "type": "select", "proxies": names},
		proxies, map[string]P.ProxyProvider{}, names, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector := group.(*outboundgroup.Selector)
	if err := selector.Set(selected); err != nil {
		t.Fatal(err)
	}
	proxies["G"] = adapter.NewProxy(group)
	tunnel.UpdateProxies(proxies, map[string]P.ProxyProvider{})
	return selector
}

func runUntilEvent(t *testing.T, server *httptest.Server, filter string, kind EventKind) Event {
	t.Helper()
	// History survives checker restarts; only events newer than this point belong to the test.
	previous := len(Snapshot().Events)
	Apply(option.Settings{Enable: true, Groups: []string{"G"}, PreferredFilter: filter,
		URL: server.URL, Timeout: 1000})
	t.Cleanup(func() { Apply(option.Settings{}) })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		events := Snapshot().Events
		for _, event := range events[:len(events)-previous] {
			if event.Kind == kind {
				return event
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s event; state: %+v", kind, Snapshot())
	return Event{}
}

func newServer(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSwitchesToPreferredHealthyNode(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true, "HK 01": true})
	event := runUntilEvent(t, server, "(?i)HK", EventSwitched)
	if event.Node != "A" || event.Target != "HK 01" || !event.Preferred {
		t.Fatalf("event = %+v", event)
	}
	if selector.Now() != "HK 01" {
		t.Fatalf("selection = %s", selector.Now())
	}
}

func TestFallsBackToOtherNodesWhenPreferredAreDown(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true, "HK 01": false})
	event := runUntilEvent(t, server, "(?i)HK", EventSwitched)
	if event.Target != "B" || event.Preferred || event.Tested != 2 || event.Available != 1 {
		t.Fatalf("event = %+v", event)
	}
	if selector.Now() != "B" {
		t.Fatalf("selection = %s", selector.Now())
	}
}

func TestKeepsSelectionWhenNoNodeIsHealthy(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": false, "C": false})
	event := runUntilEvent(t, server, "", EventNoReplacement)
	if event.Node != "A" || event.Tested != 2 {
		t.Fatalf("event = %+v", event)
	}
	if selector.Now() != "A" {
		t.Fatalf("selection = %s", selector.Now())
	}
}

func TestPatchOverridesConfigurationUntilCleared(t *testing.T) {
	Apply(option.Settings{})
	t.Cleanup(func() { Apply(option.Settings{}) })
	if err := Patch(option.Settings{Enable: true}); err == nil {
		t.Fatal("Patch accepted an enabled value without groups")
	}
	if err := Patch(option.Settings{Interval: 60, ExpectedDelay: 150}); err != nil {
		t.Fatal(err)
	}
	Apply(option.Settings{Interval: 20})
	if state := Snapshot(); state.Source != SourceControl || state.Settings.Interval != 60 || state.Settings.ExpectedDelay != 150 {
		t.Fatalf("after reload: %+v", state)
	}
	ClearOverride()
	if state := Snapshot(); state.Source != SourceConfig || state.Settings.Interval != 20 || state.Settings.ExpectedDelay != 0 {
		t.Fatalf("after clear: %+v", state)
	}
}

func TestServedSinceRequiresNewConnectionWithData(t *testing.T) {
	since := time.Now()
	time.Sleep(time.Millisecond)
	node := &fakeNode{Base: outbound.NewBase(outbound.BaseOption{Name: "A", Type: C.Socks5})}
	group := outbound.NewBase(outbound.BaseOption{Name: "G", Type: C.Selector})
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	conn := outbound.NewConn(client, node)
	conn.AppendToChains(group)
	tracker := statistic.NewTCPTracker(conn, statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { _ = tracker.Close() })

	if servedSince("G", "A", since) {
		t.Fatal("a connection without received data proved health")
	}
	tracker.Info().DownloadTotal.Store(128)
	for _, test := range []struct {
		group, node string
		since       time.Time
		want        bool
	}{
		{"G", "A", since, true},
		{"G", "B", since, false},
		{"Other", "A", since, false},
		{"G", "A", time.Now(), false},
	} {
		if got := servedSince(test.group, test.node, test.since); got != test.want {
			t.Errorf("servedSince(%s, %s) = %v, want %v", test.group, test.node, got, test.want)
		}
	}
}

func TestEventsAreNewestFirstAndBounded(t *testing.T) {
	e := &engine{}
	for i := range maxEvents + 5 {
		e.record(Event{Failures: i})
	}
	events := e.snapshot().Events
	if len(events) != maxEvents || events[0].Failures != maxEvents+4 || events[maxEvents-1].Failures != 5 {
		t.Fatalf("got %d events, first %d, last %d", len(events), events[0].Failures, events[len(events)-1].Failures)
	}
}
