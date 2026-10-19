package autoswitch

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"cfa/native/autoswitch/option"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

// Embed the unused interface surface; these tests exercise the real scan with
// controlled URLTest results instead of measuring local HTTP scheduling delays.
type probeProxy struct {
	C.Proxy
	name  string
	probe func(context.Context) (uint16, error)
}

func (p *probeProxy) Name() string { return p.name }

func (p *probeProxy) URLTest(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
	return p.probe(ctx)
}

func newTestChecker(expectedDelay, concurrency int) *checker {
	return &checker{
		engine:    &engine{groups: make(map[string]GroupStatus)},
		settings:  (option.Settings{ExpectedDelay: expectedDelay, Concurrency: concurrency}).Normalized(),
		failures:  make(map[string]failure),
		checkedAt: make(map[string]time.Time),
		startedAt: time.Now(),
	}
}

func TestExpectedDelayScan(t *testing.T) {
	for _, test := range []struct {
		name          string
		threshold     int
		delays        []uint16
		want          string
		wantDelay     uint16
		wantTested    int
		wantAvailable int
	}{
		{"disabled scans all", 0, []uint16{90, 20, 60}, "B", 20, 3, 3},
		{"first acceptable wins", 100, []uint16{90, 20, 60}, "A", 90, 1, 1},
		{"equal is not below", 100, []uint16{100, 90, 20}, "B", 90, 2, 2},
		{"none below scans all", 10, []uint16{90, 20, 60}, "B", 20, 3, 3},
		{"successful zero delay", 100, []uint16{0, 20}, "A", 0, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			proxies := make([]C.Proxy, 0, len(test.delays))
			for i, delay := range test.delays {
				proxies = append(proxies, &probeProxy{name: string(rune('A' + i)),
					probe: func(context.Context) (uint16, error) {
						calls.Add(1)
						return delay, nil
					}})
			}
			c := newTestChecker(test.threshold, 1)
			c.engine.setProgress(Progress{Total: len(proxies)})
			best, delay, tested, available := c.testAll(context.Background(), proxies)
			if best != test.want || delay != test.wantDelay || tested != test.wantTested || available != test.wantAvailable {
				t.Fatalf("scan = %s/%d/%d/%d, want %s/%d/%d/%d", best, delay, tested, available,
					test.want, test.wantDelay, test.wantTested, test.wantAvailable)
			}
			if int(calls.Load()) != tested || c.engine.snapshot().Progress.Completed != tested {
				t.Fatalf("calls=%d, progress=%+v, tested=%d", calls.Load(), c.engine.snapshot().Progress, tested)
			}
		})
	}
}

func TestExpectedDelayIgnoresFailedProbe(t *testing.T) {
	proxies := []C.Proxy{
		&probeProxy{name: "down", probe: func(context.Context) (uint16, error) { return 0, errors.New("down") }},
		&probeProxy{name: "healthy", probe: func(context.Context) (uint16, error) { return 150, nil }},
	}
	best, delay, tested, available := newTestChecker(100, 1).testAll(context.Background(), proxies)
	if best != "healthy" || delay != 150 || tested != 2 || available != 1 {
		t.Fatalf("scan = %s/%d/%d/%d", best, delay, tested, available)
	}
}

func TestExpectedDelayCancelsInFlightAndQueuedProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := make(chan struct{})
	var cancelled, queued atomic.Bool
	proxies := []C.Proxy{
		&probeProxy{name: "slow", probe: func(ctx context.Context) (uint16, error) {
			close(started)
			<-ctx.Done()
			cancelled.Store(true)
			// Even a late success must not overwrite the accepted winner.
			return 1, nil
		}},
		&probeProxy{name: "winner", probe: func(ctx context.Context) (uint16, error) {
			select {
			case <-started:
				return 90, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}},
		&probeProxy{name: "queued", probe: func(context.Context) (uint16, error) {
			queued.Store(true)
			return 1, nil
		}},
	}
	c := newTestChecker(100, 2)
	best, delay, tested, available := c.testAll(ctx, proxies)
	if ctx.Err() != nil || !cancelled.Load() || queued.Load() {
		t.Fatalf("parent=%v, cancelled=%v, queued=%v", ctx.Err(), cancelled.Load(), queued.Load())
	}
	if best != "winner" || delay != 90 || tested != 1 || available != 1 {
		t.Fatalf("scan = %s/%d/%d/%d", best, delay, tested, available)
	}
	// The next group/round uses the same parent, which must still be usable.
	best, _, tested, _ = c.testAll(ctx, []C.Proxy{&probeProxy{name: "next",
		probe: func(context.Context) (uint16, error) { return 20, nil }}})
	if best != "next" || tested != 1 {
		t.Fatalf("next scan = %s/%d", best, tested)
	}
}

func TestExpectedDelayParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		<-started
		cancel()
	}()
	t.Cleanup(cancel)
	proxies := []C.Proxy{&probeProxy{name: "slow", probe: func(ctx context.Context) (uint16, error) {
		close(started)
		<-ctx.Done()
		return 0, ctx.Err()
	}}}
	best, _, tested, available := newTestChecker(100, 1).testAll(ctx, proxies)
	<-finished
	if best != "" || tested != 0 || available != 0 {
		t.Fatalf("cancelled scan = %s/%d/%d", best, tested, available)
	}
}

func TestExpectedDelayKeepsPreferredTier(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": false, "B": true, "HK 01": true, "C": true})
	c := newTestChecker(99999, 1)
	c.settings.URL = server.URL
	var err error
	c.filter, err = (option.Settings{PreferredFilter: "HK"}).CompileFilter()
	if err != nil {
		t.Fatal(err)
	}
	best, _, summary := c.findReplacement(context.Background(), "G", selector, "A")
	if best != "HK 01" || !summary.Preferred || summary.Tested != 1 || summary.Available != 1 {
		t.Fatalf("replacement = %s, summary = %+v", best, summary)
	}
}

func TestExpectedDelayKeepsHealthyCurrentNode(t *testing.T) {
	server := newServer(t)
	selector := installGroup(t, server, "A", map[string]bool{"A": true, "B": true})
	c := newTestChecker(99999, 1)
	c.settings.URL = server.URL
	c.checkGroup(context.Background(), "G")
	if selector.Now() != "A" || len(c.engine.snapshot().Events) != 0 {
		t.Fatalf("healthy node was replaced: selection=%s, events=%+v", selector.Now(), c.engine.snapshot().Events)
	}
}
