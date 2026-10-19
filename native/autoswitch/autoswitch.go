// Package autoswitch replaces a failed node selected in a Selector group with a
// healthy member of the same group. It runs inside the core, so the embedded
// VPN runtime and the standalone ROOT CLI share one implementation and need no
// application process. Like url-test/fallback groups, it only changes in-core
// routing; it never touches ROOT/system resources.
package autoswitch

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"cfa/native/autoswitch/option"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const maxEvents = 100

// A replacement scan that finds nothing is retried after 1, 2, 4 and then at
// most 8 further failing rounds, so an offline device does not probe every node
// at every interval.
const maxScanBackoff = 8

const filterMatchTimeout = 50 * time.Millisecond

type EventKind string

const (
	EventFailed           EventKind = "failed"
	EventSwitched         EventKind = "switched"
	EventNoReplacement    EventKind = "no-replacement"
	EventSelectionChanged EventKind = "selection-changed"
)

type GroupStatusKind string

const (
	GroupHealthy GroupStatusKind = "healthy"
	GroupFailed  GroupStatusKind = "failed"
	// GroupSkipped means the selection is DIRECT/REJECT or a nested group.
	GroupSkipped GroupStatusKind = "skipped"
	// GroupUnavailable means the name is missing or is not a Selector.
	GroupUnavailable GroupStatusKind = "unavailable"
)

type Event struct {
	Time      int64     `json:"time"`
	Group     string    `json:"group"`
	Kind      EventKind `json:"kind"`
	Node      string    `json:"node,omitempty"`
	Target    string    `json:"target,omitempty"`
	Delay     uint16    `json:"delay,omitempty"`
	Failures  int       `json:"failures,omitempty"`
	Threshold int       `json:"threshold,omitempty"`
	Tested    int       `json:"tested,omitempty"`
	Available int       `json:"available,omitempty"`
	Preferred bool      `json:"preferred,omitempty"`
}

type GroupStatus struct {
	Name     string          `json:"name"`
	Kind     GroupStatusKind `json:"kind"`
	Node     string          `json:"node,omitempty"`
	Delay    uint16          `json:"delay,omitempty"`
	Failures int             `json:"failures,omitempty"`
	// InUse marks a healthy result proven by live traffic instead of a probe.
	InUse     bool  `json:"inUse,omitempty"`
	CheckedAt int64 `json:"checkedAt"`
}

type ProgressStage string

const (
	StageCurrent   ProgressStage = "current"
	StagePreferred ProgressStage = "preferred"
	StageAll       ProgressStage = "all"
)

type Progress struct {
	Group     string        `json:"group"`
	Stage     ProgressStage `json:"stage"`
	Completed int           `json:"completed"`
	Total     int           `json:"total"`
}

type Phase string

const (
	PhaseStopped  Phase = "stopped"
	PhaseChecking Phase = "checking"
	PhaseWaiting  Phase = "waiting"
)

type SettingsSource string

const (
	SourceConfig  SettingsSource = "config"
	SourceControl SettingsSource = "control"
)

// State is a point-in-time copy. Events are newest first and survive restarts
// of the checker within one core process, but never persist to disk.
type State struct {
	Settings    option.Settings `json:"settings"`
	Source      SettingsSource  `json:"source"`
	Phase       Phase           `json:"phase"`
	NextCheckAt int64           `json:"nextCheckAt,omitempty"`
	Progress    *Progress       `json:"progress,omitempty"`
	Groups      []GroupStatus   `json:"groups"`
	Events      []Event         `json:"events"`
}

type engine struct {
	// lifecycle serializes restarts; mu only guards the observable state.
	// override is a control-API value that lasts until ClearOverride.
	lifecycle  sync.Mutex
	configured option.Settings
	override   *option.Settings
	cancel     context.CancelFunc
	done       chan struct{}

	mu          sync.Mutex
	active      option.Settings
	source      SettingsSource
	phase       Phase
	nextCheckAt int64
	progress    *Progress
	groups      map[string]GroupStatus
	events      []Event
}

var current = &engine{phase: PhaseStopped, source: SourceConfig}

// Apply is called after every configuration apply. The proxy set may have
// changed, so failure counters always restart. A control override stays in
// effect across hot reloads until ClearOverride.
func Apply(settings option.Settings) {
	current.lifecycle.Lock()
	defer current.lifecycle.Unlock()
	current.configured = settings
	current.restartLocked()
}

// Patch replaces the configured settings for the rest of this core session.
func Patch(settings option.Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	current.lifecycle.Lock()
	defer current.lifecycle.Unlock()
	current.override = &settings
	current.restartLocked()
	return nil
}

// ClearOverride returns to the configured settings when the embedded runtime is
// reset between service sessions. A standalone process never needs it.
func ClearOverride() {
	current.lifecycle.Lock()
	defer current.lifecycle.Unlock()
	if current.override == nil {
		return
	}
	current.override = nil
	current.restartLocked()
}

func Snapshot() State { return current.snapshot() }

func (e *engine) snapshot() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := State{
		Settings:    e.active,
		Source:      e.source,
		Phase:       e.phase,
		NextCheckAt: e.nextCheckAt,
		Groups:      make([]GroupStatus, 0, len(e.active.Groups)),
		Events:      make([]Event, len(e.events)),
	}
	for i, event := range e.events {
		state.Events[len(e.events)-1-i] = event
	}
	if e.progress != nil {
		progress := *e.progress
		state.Progress = &progress
	}
	for _, name := range e.active.Groups {
		if status, ok := e.groups[name]; ok {
			state.Groups = append(state.Groups, status)
		}
	}
	return state
}

func (e *engine) restartLocked() {
	if e.cancel != nil {
		e.cancel()
		<-e.done
		e.cancel, e.done = nil, nil
	}
	settings, source := e.configured, SourceConfig
	if e.override != nil {
		settings, source = *e.override, SourceControl
	}
	settings = settings.Normalized()
	filter, err := settings.CompileFilter()
	if err != nil {
		log.Warnln("[AutoSwitch] Invalid preferred-filter: %s", err.Error())
		filter = nil
	} else if filter != nil {
		// A hand-written raw-profile pattern must not burn CPU on backtracking.
		filter.MatchTimeout = filterMatchTimeout
	}
	expected, err := utils.NewUnsignedRanges[uint16](settings.ExpectedStatus)
	if err != nil {
		log.Warnln("[AutoSwitch] Invalid expected-status: %s", err.Error())
		expected = nil
	}

	e.mu.Lock()
	e.active, e.source = settings, source
	e.phase, e.nextCheckAt, e.progress = PhaseStopped, 0, nil
	e.groups = make(map[string]GroupStatus)
	e.mu.Unlock()
	if !settings.Enable || len(settings.Groups) == 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.cancel, e.done = cancel, done
	checker := &checker{engine: e, settings: settings, filter: filter, expected: expected,
		failures: make(map[string]failure), checkedAt: make(map[string]time.Time), startedAt: time.Now()}
	go func() {
		defer close(done)
		checker.run(ctx)
	}()
}

func (e *engine) setPhase(phase Phase, nextCheckAt int64) {
	e.mu.Lock()
	e.phase, e.nextCheckAt, e.progress = phase, nextCheckAt, nil
	e.mu.Unlock()
}

func (e *engine) setProgress(progress Progress) {
	e.mu.Lock()
	e.progress = &progress
	e.mu.Unlock()
}

func (e *engine) advanceProgress() {
	e.mu.Lock()
	if e.progress != nil {
		e.progress.Completed++
	}
	e.mu.Unlock()
}

func (e *engine) setGroup(status GroupStatus) {
	status.CheckedAt = time.Now().UnixMilli()
	e.mu.Lock()
	e.groups[status.Name] = status
	e.mu.Unlock()
}

func (e *engine) record(event Event) {
	event.Time = time.Now().UnixMilli()
	e.mu.Lock()
	// Stored oldest first so appending does not copy the history; Snapshot reverses it.
	if len(e.events) == maxEvents {
		copy(e.events, e.events[1:])
		e.events[maxEvents-1] = event
	} else {
		e.events = append(e.events, event)
	}
	e.mu.Unlock()
}

type failure struct {
	node    string
	count   int
	backoff int
	skip    int
}

type checker struct {
	engine   *engine
	settings option.Settings
	filter   *regexp2.Regexp
	expected utils.IntRanges[uint16]
	failures map[string]failure
	// checkedAt holds each group's previous check; traffic newer than it proves health.
	checkedAt map[string]time.Time
	startedAt time.Time
}

func (c *checker) run(ctx context.Context) {
	defer c.engine.setPhase(PhaseStopped, 0)
	interval := time.Duration(c.settings.Interval) * time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c.engine.setPhase(PhaseChecking, 0)
		for _, group := range c.settings.Groups {
			if ctx.Err() != nil {
				return
			}
			c.checkGroup(ctx, group)
		}
		// A long round delays the next one instead of overlapping it.
		c.engine.setPhase(PhaseWaiting, time.Now().Add(interval).UnixMilli())
		timer.Reset(interval)
	}
}

func (c *checker) checkGroup(ctx context.Context, name string) {
	selector := lookupSelector(name)
	if selector == nil {
		delete(c.failures, name)
		c.engine.setGroup(GroupStatus{Name: name, Kind: GroupUnavailable})
		return
	}
	selected := selector.Now()
	proxy := member(selector, selected)
	if proxy == nil || !isLeaf(proxy) {
		delete(c.failures, name)
		c.engine.setGroup(GroupStatus{Name: name, Kind: GroupSkipped, Node: selected})
		return
	}

	since, ok := c.checkedAt[name]
	if !ok {
		since = c.startedAt
	}
	c.checkedAt[name] = time.Now()
	// While the device is in use, new connections through the node already prove it works;
	// skipping the probe saves a radio wakeup and traffic on every interval.
	if servedSince(name, selected, since) {
		delete(c.failures, name)
		c.engine.setGroup(GroupStatus{Name: name, Kind: GroupHealthy, Node: selected, InUse: true})
		return
	}

	c.engine.setProgress(Progress{Group: name, Stage: StageCurrent, Total: 1})
	delay, ok := c.test(ctx, proxy)
	if ctx.Err() != nil {
		return
	}
	if ok {
		delete(c.failures, name)
		c.engine.setGroup(GroupStatus{Name: name, Kind: GroupHealthy, Node: selected, Delay: delay})
		return
	}

	threshold := c.settings.FailureThreshold
	state := c.failures[name]
	if state.node != selected {
		state = failure{node: selected}
	}
	if state.count < threshold {
		state.count++
		c.engine.record(Event{Group: name, Kind: EventFailed, Node: selected,
			Failures: state.count, Threshold: threshold})
		log.Warnln("[AutoSwitch] %s: %s failed the health check (%d/%d)", name, selected, state.count, threshold)
	}
	c.engine.setGroup(GroupStatus{Name: name, Kind: GroupFailed, Node: selected, Failures: state.count})
	if state.count < threshold {
		c.failures[name] = state
		return
	}
	if state.skip > 0 {
		state.skip--
		c.failures[name] = state
		return
	}

	replacement, replacementDelay, summary := c.findReplacement(ctx, name, selector, selected)
	if ctx.Err() != nil {
		return
	}
	if replacement == "" {
		state.backoff = min(max(state.backoff*2, 1), maxScanBackoff)
		state.skip = state.backoff
		c.failures[name] = state
		summary.Group, summary.Kind, summary.Node = name, EventNoReplacement, selected
		c.engine.record(summary)
		log.Warnln("[AutoSwitch] %s: no healthy replacement among %d candidates", name, summary.Tested)
		return
	}

	delete(c.failures, name)
	// Compare and set: a manual selection made during the scan always wins.
	if selector.Now() != selected || selector.Set(replacement) != nil {
		c.engine.record(Event{Group: name, Kind: EventSelectionChanged, Node: selected, Target: replacement})
		return
	}
	cachefile.Cache().SetSelected(name, replacement)
	closeConnectionsThrough(name)
	summary.Group, summary.Kind, summary.Node, summary.Target, summary.Delay =
		name, EventSwitched, selected, replacement, replacementDelay
	c.engine.record(summary)
	c.engine.setGroup(GroupStatus{Name: name, Kind: GroupHealthy, Node: replacement, Delay: replacementDelay})
	log.Infoln("[AutoSwitch] %s: %s -> %s (%d ms)", name, selected, replacement, replacementDelay)
}

// findReplacement tests preferred members first and other members only when no
// preferred member is healthy. Within a tier, the first result below expected-delay
// wins, trying the fastest members of earlier scans first; otherwise all members
// are tested and the lowest delay wins.
func (c *checker) findReplacement(ctx context.Context, group string, selector *outboundgroup.Selector,
	selected string) (string, uint16, Event) {
	var preferred, others []C.Proxy
	seen := map[string]struct{}{selected: {}}
	for _, proxy := range selector.Proxies() {
		if _, ok := seen[proxy.Name()]; ok || !isLeaf(proxy) {
			continue
		}
		seen[proxy.Name()] = struct{}{}
		if c.prefers(proxy.Name()) {
			preferred = append(preferred, proxy)
		} else {
			others = append(others, proxy)
		}
	}
	summary := Event{}
	tiers := []struct {
		stage   ProgressStage
		proxies []C.Proxy
	}{{StagePreferred, preferred}, {StageAll, others}}
	for _, tier := range tiers {
		if len(tier.proxies) == 0 {
			continue
		}
		c.engine.setProgress(Progress{Group: group, Stage: tier.stage, Total: len(tier.proxies)})
		best, delay, tested, available := c.testAll(ctx, tier.proxies)
		if ctx.Err() != nil {
			return "", 0, summary
		}
		summary.Tested += tested
		summary.Available += available
		summary.Preferred = tier.stage == StagePreferred
		if best != "" {
			return best, delay, summary
		}
	}
	return "", 0, summary
}

// testAll returns as soon as a member answers below expected-delay. Queued
// members are then never probed, while probes already in flight finish in the
// background instead of being cancelled: URLTest would record a cancelled probe
// as a timeout in the node's delay history, and they end within the timeout.
func (c *checker) testAll(ctx context.Context, proxies []C.Proxy) (string, uint16, int, int) {
	if c.settings.ExpectedDelay > 0 {
		proxies = c.byLastDelay(proxies)
	}
	var (
		mu        sync.Mutex
		best      string
		bestDelay uint16
		tested    int
		available int
		accepted  bool
		wg        sync.WaitGroup
	)
	stop := make(chan struct{})
	jobs := make(chan C.Proxy)
	for range min(c.settings.Concurrency, len(proxies)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxy := range jobs {
				mu.Lock()
				done := accepted
				mu.Unlock()
				if done || ctx.Err() != nil {
					return
				}
				delay, ok := c.test(ctx, proxy)
				mu.Lock()
				// Late and cancelled probes do not count as failures or replace the winner.
				if !accepted && ctx.Err() == nil {
					tested++
					c.engine.advanceProgress()
					if ok {
						available++
						if best == "" || delay < bestDelay {
							best, bestDelay = proxy.Name(), delay
						}
						if c.settings.ExpectedDelay > 0 && int(delay) < c.settings.ExpectedDelay {
							accepted = true
							close(stop)
						}
					}
				}
				mu.Unlock()
			}
		}()
	}
dispatch:
	for _, proxy := range proxies {
		select {
		case <-ctx.Done():
			break dispatch
		case <-stop:
			break dispatch
		case jobs <- proxy:
		}
	}
	close(jobs)
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-stop:
	}
	mu.Lock()
	defer mu.Unlock()
	return best, bestDelay, tested, available
}

// byLastDelay probes the members that answered fastest last time first, so an
// expected-delay scan usually ends after one probe instead of waiting on dead
// nodes. Untested and failed members (0xffff) keep their group order at the end.
func (c *checker) byLastDelay(proxies []C.Proxy) []C.Proxy {
	type candidate struct {
		proxy C.Proxy
		delay uint16
	}
	// Snapshot once: background probes may update the history during the sort.
	candidates := make([]candidate, len(proxies))
	for i, proxy := range proxies {
		candidates[i] = candidate{proxy, proxy.LastDelayForTestUrl(c.settings.URL)}
	}
	slices.SortStableFunc(candidates, func(a, b candidate) int { return cmp.Compare(a.delay, b.delay) })
	sorted := make([]C.Proxy, len(candidates))
	for i, candidate := range candidates {
		sorted[i] = candidate.proxy
	}
	return sorted
}

func (c *checker) test(ctx context.Context, proxy C.Proxy) (uint16, bool) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.settings.Timeout)*time.Millisecond)
	defer cancel()
	delay, err := proxy.URLTest(ctx, c.settings.URL, c.expected)
	return delay, err == nil
}

func (c *checker) prefers(name string) bool {
	if c.filter == nil {
		return false
	}
	matched, err := c.filter.MatchString(name)
	return err == nil && matched
}

// lookupSelector accepts only manual Selector groups; url-test, fallback and
// load-balance groups already manage their own selection.
func lookupSelector(name string) *outboundgroup.Selector {
	proxy := tunnel.Proxies()[name]
	if proxy == nil {
		return nil
	}
	selector, _ := proxy.Adapter().(*outboundgroup.Selector)
	return selector
}

func member(selector *outboundgroup.Selector, name string) C.Proxy {
	for _, proxy := range selector.Proxies() {
		if proxy.Name() == name {
			return proxy
		}
	}
	return nil
}

func isLeaf(proxy C.Proxy) bool {
	if _, ok := proxy.Adapter().(outboundgroup.ProxyGroup); ok {
		return false
	}
	switch proxy.Type() {
	case C.Direct, C.Reject, C.RejectDrop, C.Compatible, C.Pass, C.Dns:
		return false
	}
	return true
}

// servedSince reports whether a connection opened through group and node after since has
// received data. Only new connections count, so a stale long-lived stream cannot hide a node
// that no longer accepts connections.
func servedSince(group, node string, since time.Time) bool {
	served := false
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		info := tracker.Info()
		if info.DownloadTotal.Load() == 0 || !info.Start.After(since) {
			return true
		}
		chains := tracker.Chains()
		// Chains run from the leaf node outwards through each enclosing group.
		if len(chains) > 0 && chains[0] == node && slices.Contains(chains[1:], group) {
			served = true
			return false
		}
		return true
	})
	return served
}

// closeConnectionsThrough matches the embedded selector patch: connections still
// bound to the failed node are closed so clients reconnect through the new one.
func closeConnectionsThrough(group string) {
	statistic.DefaultManager.Range(func(tracker statistic.Tracker) bool {
		for _, chain := range tracker.Chains() {
			if chain == group {
				_ = tracker.Close()
				break
			}
		}
		return true
	})
}
