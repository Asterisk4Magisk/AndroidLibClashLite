package autoswitch

import (
	"context"
	"testing"
	"time"

	"cfa/native/autoswitch/option"

	"github.com/metacubex/mihomo/tunnel"
)

// newRestoreChecker drives rounds directly; the run loop's 10 s minimum interval
// would make a three-round restore slow.
func newRestoreChecker(t *testing.T, url string, restoreEnabled bool) *checker {
	t.Helper()
	settings := option.Settings{Enable: true, Restore: restoreEnabled, Groups: []string{"G"}, URL: url,
		Timeout: 1000}.Normalized()
	e := &engine{active: settings, groups: make(map[string]GroupStatus), restores: make(map[string]restore)}
	return &checker{engine: e, settings: settings, failures: make(map[string]failure),
		checkedAt: make(map[string]time.Time), startedAt: time.Now()}
}

func setHealthy(t *testing.T, name string, healthy bool) {
	t.Helper()
	node, ok := tunnel.Proxies()[name].Adapter().(*fakeNode)
	if !ok {
		t.Fatalf("%s is not a fake node", name)
	}
	node.healthy = healthy
}

func lastEvent(c *checker) Event {
	events := c.engine.snapshot().Events
	if len(events) == 0 {
		return Event{}
	}
	return events[0]
}

func TestRestoresOriginalAfterConsecutiveSuccesses(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true})
	c := newRestoreChecker(t, server.URL, true)
	ctx := context.Background()

	c.round(ctx)
	if selector.Now() != "B" {
		t.Fatalf("selection = %s", selector.Now())
	}
	if status := c.engine.snapshot().Groups[0]; status.Origin != "A" || status.OriginSuccesses != 0 {
		t.Fatalf("status = %+v", status)
	}

	setHealthy(t, "A", true)
	c.round(ctx)
	setHealthy(t, "A", false)
	c.round(ctx) // a failure restarts the count
	setHealthy(t, "A", true)
	for i := 1; i < option.RestoreSuccesses; i++ {
		c.round(ctx)
		if status := c.engine.snapshot().Groups[0]; selector.Now() != "B" || status.OriginSuccesses != i {
			t.Fatalf("round %d: selection = %s, status = %+v", i, selector.Now(), status)
		}
	}
	c.round(ctx)
	if selector.Now() != "A" {
		t.Fatalf("selection = %s", selector.Now())
	}
	if event := lastEvent(c); event.Kind != EventRestored || event.Node != "B" || event.Target != "A" {
		t.Fatalf("event = %+v", event)
	}
	if status := c.engine.snapshot().Groups[0]; status.Origin != "" || status.Node != "A" {
		t.Fatalf("status = %+v", status)
	}
}

func TestRestoreKeepsFirstOriginAcrossSwitches(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true, "C": false})
	c := newRestoreChecker(t, server.URL, true)
	ctx := context.Background()

	c.round(ctx)
	setHealthy(t, "B", false)
	setHealthy(t, "C", true)
	c.round(ctx)
	if selector.Now() != "C" || c.engine.restores["G"].origin != "A" {
		t.Fatalf("selection = %s, restore = %+v", selector.Now(), c.engine.restores["G"])
	}
}

func TestManualSelectionCancelsRestore(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true, "C": true})
	c := newRestoreChecker(t, server.URL, true)
	ctx := context.Background()

	c.round(ctx)
	if err := selector.Set("C"); err != nil {
		t.Fatal(err)
	}
	setHealthy(t, "A", true)
	for range option.RestoreSuccesses {
		c.round(ctx)
	}
	if selector.Now() != "C" || len(c.engine.restores) != 0 {
		t.Fatalf("selection = %s, restores = %+v", selector.Now(), c.engine.restores)
	}
}

func TestNoRestoreWhenDisabled(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true})
	c := newRestoreChecker(t, server.URL, false)
	ctx := context.Background()

	c.round(ctx)
	setHealthy(t, "A", true)
	for range option.RestoreSuccesses {
		c.round(ctx)
	}
	if selector.Now() != "B" || len(c.engine.restores) != 0 {
		t.Fatalf("selection = %s, restores = %+v", selector.Now(), c.engine.restores)
	}
}

func TestRestartKeepsRestoresOnlyWhileEnabled(t *testing.T) {
	server := newServer(t)
	installGroup(t, server, "B", map[string]bool{"A": false, "B": true})
	Apply(option.Settings{})
	t.Cleanup(func() { Apply(option.Settings{}) })
	// No checker runs while the engine is disabled, so the map can be seeded directly.
	current.restores = map[string]restore{"G": {origin: "A", target: "B"}}
	settings := option.Settings{Enable: true, Restore: true, Groups: []string{"G"}, URL: server.URL,
		Timeout: 1000}
	Apply(settings)
	Apply(settings)
	waitForOrigin(t, "A")

	settings.Restore = false
	Apply(settings)
	waitForOrigin(t, "")
}

// waitForOrigin reads the published status; the running checker owns the restores map.
func waitForOrigin(t *testing.T, origin string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if groups := Snapshot().Groups; len(groups) == 1 && groups[0].Kind == GroupHealthy &&
			groups[0].Origin == origin {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("origin %q not reported; state: %+v", origin, Snapshot())
}
