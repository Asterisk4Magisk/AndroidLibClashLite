# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Prepare Mihomo/Go sources and CLI/CMFA overlays without editing pinned upstream."""
import json
import re
import shutil


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f'Upstream changed: expected exactly one {old!r}')
    return text.replace(old, new, 1)


def prepare_sources(repo, work, core):
    source = work / 'source'
    source.mkdir(exist_ok=True)
    for folder in ('native', 'environment'):
        shutil.copytree(repo / folder, source / folder, dirs_exist_ok=True)
    for name in ('go.mod', 'go.sum'):
        shutil.copyfile(repo / name, source / name)
    for name in repo.glob('libclash*.go'):
        shutil.copyfile(name, source / name.name)
    main = (core / 'main.go').read_text(encoding='utf-8')
    main = replace_once(main, 'func init() {', 'func initMihomoCLI() {')
    main = replace_once(main, 'func main() {', 'func mihomoCLIMain() {')
    main = replace_once(main, '\tif geodataMode {',
                        '\tif !testConfig {\n'
                        '\t\tstopSystemDNS := startSystemDNS(C.Path.HomeDir())\n'
                        '\t\tdefer stopSystemDNS()\n'
                        '\t}\n\n\tif geodataMode {')
    cli = work / 'cli'
    cli.mkdir(exist_ok=True)
    (cli / 'mihomo_cli.go').write_text(main, encoding='utf-8')
    shutil.copyfile(repo / 'native/cli/export.go.txt', cli / 'cli_export.go')

    patches = {}
    def patch(name, old, new):
        text = patches.get(name, (core / name).read_text(encoding='utf-8'))
        patches[name] = replace_once(text, old, new)

    patch_proxy_ip(patch)

    patch('listener/socks/tcp.go', '\tcase socks5.Version:\n',
          '\tcase FlowHeaderByte:\n\t\tHandleFlow(bufConn, tunnel, store, additions...)\n\tcase socks5.Version:\n')
    patch('listener/mixed/mixed.go', '\tcase socks5.Version:\n',
          '\tcase socks.FlowHeaderByte:\n\t\tsocks.HandleFlow(bufConn, tunnel, store, additions...)\n\tcase socks5.Version:\n')
    patch('listener/socks/udp.go', '\t\t\thandleSocksUDP(l, tunnel, data, put, remoteAddr, additions...)',
          '\t\t\tif len(data) > 0 && data[0] == FlowHeaderByte {\n'
          '\t\t\t\thandleFlowUDP(l, tunnel, data, put, remoteAddr, config.AuthStore, additions...)\n'
          '\t\t\t} else { handleSocksUDP(l, tunnel, data, put, remoteAddr, additions...) }')

    patch('tunnel/tunnel.go', '\t\t\t\tattemptProcessLookup = false\n',
          '\t\t\t\tattemptProcessLookup = false\n'
          '\t\t\t\tif process.AsteriskFlowOwner(metadata) {\n\t\t\t\t\treturn\n\t\t\t\t}\n')
    # Manual JNI/API group tests use the caller's URL. Background health checks
    # and automatic selection keep the group's configured testUrl.
    patch('adapter/outboundgroup/urltest.go',
          '\treturn u.GroupBase.URLTest(ctx, u.testUrl, expectedStatus)',
          '\tif url == "" {\n\t\turl = u.testUrl\n\t}\n'
          '\treturn u.GroupBase.URLTest(ctx, url, expectedStatus)')

    # A single binary must support both Android embedding and standalone ROOT.
    patch('constant/features/cmfa.go', 'const CMFA = true',
          'import "cfa/environment"\n\nvar CMFA = !environment.IsCLI')
    patch('hub/route/patch_android.go', 'package route',
          'package route\n\nimport "cfa/environment"')
    patch('hub/route/patch_android.go', 'SetEmbedMode(true)', 'SetEmbedMode(!environment.IsCLI)')
    patch('listener/sing_tun/server_android.go', '//go:build android && !cmfa', '//go:build android')
    patch('listener/sing_tun/server_android.go',
          'func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {',
          'func (l *Listener) buildAndroidRules(tunOptions *tun.Options) error {\n'
          '\tif features.CMFA { return nil }')
    patch('listener/sing_tun/server_notandroid.go', '//go:build !android || cmfa', '//go:build !android')
    # Borrow Android's VPN descriptor. Duplicate only when sing-tun adopts it,
    # so early validation errors cannot leak a duplicate or close the caller's fd.
    patch('listener/sing_tun/server_notwindows.go', 'import (',
          'import (\n\t"github.com/metacubex/mihomo/constant/features"\n\t"golang.org/x/sys/unix"')
    patch('listener/sing_tun/server_notwindows.go', '\treturn tun.New(options)',
          '\tif features.CMFA && options.FileDescriptor > 0 {\n'
          '\t\tfd, err := unix.FcntlInt(uintptr(options.FileDescriptor), unix.F_DUPFD_CLOEXEC, 1)\n'
          '\t\tif err != nil { return nil, err }\n'
          '\t\toptions.FileDescriptor = fd\n'
          '\t\tdevice, err := tun.New(options)\n'
          '\t\tif err != nil { _ = unix.Close(fd) }\n'
          '\t\treturn device, err\n'
          '\t}\n\treturn tun.New(options)')
    # Compile both DNS implementations, keeping the CMFA callback-based one for JNI.
    patch('dns/system_common.go', '//go:build !(android && cmfa)', '//go:build android && cmfa')
    patch('dns/system_common.go', 'func (c *systemClient) getDnsClients()',
          'func (c *systemClient) getNativeDnsClients()')
    patch('dns/system_common.go', 'func (c *systemClient) ResetConnection()',
          'func (c *systemClient) resetNativeConnection()')
    patch('dns/patch_android.go', 'package dns',
          'package dns\n\nimport "cfa/environment"\nimport "github.com/metacubex/mihomo/constant/features"\nimport "sync/atomic"')
    # Android network notifications race DNS exchanges and connection resets.
    # Publish immutable slices so workers can retain a consistent snapshot.
    patch('dns/patch_android.go', 'var systemResolver []dnsClient',
          'var systemResolver atomic.Pointer[[]dnsClient]\n\n'
          'func systemResolverSnapshot() []dnsClient {\n'
          '\tif clients := systemResolver.Load(); clients != nil { return *clients }\n'
          '\treturn nil\n}')
    patch('dns/patch_android.go',
          '\tif len(addr) == 0 {\n\t\tsystemResolver = nil\n\t}', '')
    patch('dns/patch_android.go', '\tsystemResolver = transform(ns, nil)',
          '\tclients := transform(ns, nil)\n\tsystemResolver.Store(&clients)')
    patch('dns/patch_android.go', '\treturn systemResolver, nil',
          '\treturn systemResolverSnapshot(), nil')
    patch('dns/patch_android.go', '\tfor _, r := range systemResolver {',
          '\tfor _, r := range systemResolverSnapshot() {')
    patch('dns/patch_android.go', 'func (c *systemClient) getDnsClients() ([]dnsClient, error) {',
          'func (c *systemClient) getDnsClients() ([]dnsClient, error) {\n'
          '\tif !features.CMFA && !environment.ManagedSystemDNS() { return c.getNativeDnsClients() }')
    patch('dns/patch_android.go', 'func (c *systemClient) ResetConnection() {',
          'func (c *systemClient) ResetConnection() {\n'
          '\tif !features.CMFA && !environment.ManagedSystemDNS() { c.resetNativeConnection(); return }')
    # Carry the top-level asterisk-auto-switch key through both JNI and CLI
    # configuration applies, including hot profile reloads.
    patch('config/config.go', 'package config\n',
          'package config\n\nimport autoswitchoption "cfa/native/autoswitch/option"\n')
    patch('config/config.go',
          '\tClashForAndroid RawClashForAndroid `yaml:"clash-for-android" json:"clash-for-android"`\n',
          '\tClashForAndroid RawClashForAndroid `yaml:"clash-for-android" json:"clash-for-android"`\n'
          '\tAsteriskAutoSwitch autoswitchoption.Settings `yaml:"asterisk-auto-switch" json:"asterisk-auto-switch"`\n')
    patch('config/config.go', '\tSniffer       *sniffer.Config\n\tTLS           *TLS\n}',
          '\tSniffer       *sniffer.Config\n\tTLS           *TLS\n'
          '\tAsteriskAutoSwitch autoswitchoption.Settings\n}')
    patch('config/config.go', '\tconfig := &Config{}\n',
          '\tconfig := &Config{AsteriskAutoSwitch: rawCfg.AsteriskAutoSwitch}\n')
    patch('hub/executor/executor.go', '\t"github.com/metacubex/mihomo/tunnel"\n)',
          '\t"github.com/metacubex/mihomo/tunnel"\n\n\t"cfa/native/autoswitch"\n)')
    patch('hub/executor/executor.go', '\ttunnel.OnRunning()\n',
          '\ttunnel.OnRunning()\n\tautoswitch.Apply(cfg.AsteriskAutoSwitch)\n')
    # Stamp log events when they are created; a subscriber-side clock would
    # include queueing delay.
    patch('log/log.go', '\t"os"\n', '\t"os"\n\t"time"\n')
    patch('log/log.go', '\tPayload  string\n}', '\tPayload  string\n\tTime     time.Time\n}')
    patch('log/log.go', '\t\tPayload:  fmt.Sprintf(format, v...),\n',
          '\t\tPayload:  fmt.Sprintf(format, v...),\n\t\tTime:     time.Now(),\n')

    # Dependencies enforce ordering before even package-level cached env settings.
    replacements = {}
    for original in core.rglob('*.go'):
        if original.name.endswith('_test.go'):
            continue
        relative = original.relative_to(core)
        name = relative.as_posix()
        text = patches.get(name, original.read_text(encoding='utf-8'))
        reads_env = re.search(r'os\.(?:Getenv|LookupEnv)\(', text)
        if not reads_env and name not in patches:
            continue
        if reads_env:
            text, count = re.subn(r'(?m)^(package \w+)\s*$',
                                 r'\1\n\nimport _ "cfa/environment"', text, count=1)
            if count != 1:
                raise ValueError(f'Cannot insert environment bootstrap: {relative}')
        replacement = work / 'overlay' / relative
        replacement.parent.mkdir(parents=True, exist_ok=True)
        replacement.write_text(text, encoding='utf-8')
        replacements[str(original)] = str(replacement)
    # The cache singleton is private; reset it from inside its own package so
    # the compiler checks the state this depends on.
    cache_reset = core / 'component/profile/cachefile/asterisk_reset.go'
    if cache_reset.exists():
        raise ValueError(f'Upstream changed: {cache_reset.name} now exists')
    replacement = work / 'overlay' / cache_reset.relative_to(core)
    replacement.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repo / 'native/profilecache/cachefile_reset.go.txt', replacement)
    replacements[str(cache_reset)] = str(replacement)
    flow_inbound = core / 'listener/socks/asterisk_flow.go'
    replacement = work / 'overlay/listener/socks/asterisk_flow.go'
    replacement.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repo / 'native/flowmeta/mihomo.go.txt', replacement)
    replacements[str(flow_inbound)] = str(replacement)
    for filename in ('asterisk_flow.go', 'asterisk_flow_android.go'):
        target = core / 'component/process' / filename
        replacement = work / 'overlay/component/process' / filename
        replacement.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / 'native/flowmeta' / (filename + '.txt'), replacement)
        replacements[str(target)] = str(replacement)
    overlay = work / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': replacements}), encoding='utf-8')
    return source, overlay


def patch_proxy_ip(patch):
    groups = 'adapter/outboundgroup/'
    for name in ('selector.go', 'fallback.go', 'urltest.go', 'loadbalance.go'):
        patch(groups + name, 'import (', 'import (\n\t"cfa/native/proxyip"')

    base = groups + 'groupbase.go'
    patch(base, 'func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {',
          'func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {\n'
          '\treturn gb.groupProxies(touch, true)\n}\n\n'
          'func (gb *GroupBase) groupProxies(touch, cache bool) []C.Proxy {')
    patch(base, '\tproviderVersions := make([]uint32, len(gb.providers))',
          '\thasUnloadedProvider := false\n\tproviderVersions := make([]uint32, len(gb.providers))')
    patch(base, '\t\tproviderVersions[i] = pd.Version()',
          '\t\tproviderVersions[i] = pd.Version()\n'
          '\t\tif !cache && providerVersions[i] == 0 && pd.VehicleType() != P.Compatible {\n'
          '\t\t\thasUnloadedProvider = true\n\t\t}')
    patch(base, '\t\treturn []C.Proxy{gb.EmptyFallback()}',
          '\t\tif hasUnloadedProvider {\n\t\t\treturn nil\n\t\t}\n'
          '\t\treturn []C.Proxy{gb.EmptyFallback()}')
    patch(base, '\tgb.providerVersions = providerVersions\n\tgb.providerProxies = proxies',
          '\tif cache {\n\t\tgb.providerVersions = providerVersions\n'
          '\t\tgb.providerProxies = proxies\n\t}')
    patch(base, 'type GroupBase struct {',
          'var errProbeNoCandidates = errors.New("no active proxy candidates")\n\ntype GroupBase struct {')

    selector = groups + 'selector.go'
    fallback = groups + 'fallback.go'
    urltest = groups + 'urltest.go'
    for path in (selector, fallback, urltest):
        patch(path, '\tC "github.com/metacubex/mihomo/constant"',
              '\t"github.com/metacubex/mihomo/common/atomic"\n'
              '\tC "github.com/metacubex/mihomo/constant"')
    patch(selector, 'selected   string', 'selected   atomic.TypedValue[string]')
    patch(selector, 'selected:   selectorOption.DefaultSelected,',
          'selected:   atomic.NewTypedValue(selectorOption.DefaultSelected),')
    patch(selector, '\t\t\ts.selected = name', '\t\t\ts.selected.Store(name)')
    patch(selector, '\ts.selected = name', '\ts.selected.Store(name)')
    for method in ('DialContext', 'ListenPacketContext'):
        patch(selector, f's.selectedProxy(true).{method}(ctx, metadata)',
              f'proxy.{method}(ctx, metadata)')
    for call in ('c, err := proxy.DialContext', 'pc, err := proxy.ListenPacketContext'):
        patch(selector, '\t' + call, '\tproxy := s.dialProxy(ctx)\n'
              '\tif proxy == nil {\n\t\treturn nil, errProbeNoCandidates\n\t}\n\t' + call)
    patch(selector, '\tproxies := s.GetProxies(touch)\n\tfor _, proxy := range proxies {\n'
          '\t\tif proxy.Name() == s.selected {',
          '\treturn s.selectFrom(s.GetProxies(touch))\n}\n\n'
          'func (s *Selector) dialProxy(ctx context.Context) C.Proxy {\n'
          '\tif proxyip.ReadOnly(ctx) {\n\t\tproxies := s.groupProxies(false, false)\n'
          '\t\tif len(proxies) == 0 {\n\t\t\treturn nil\n\t\t}\n'
          '\t\treturn s.selectFrom(proxies)\n\t}\n'
          '\treturn s.selectedProxy(true)\n}\n\n'
          'func (s *Selector) selectFrom(proxies []C.Proxy) C.Proxy {\n'
          '\tselected := s.selected.Load()\n\tfor _, proxy := range proxies {\n'
          '\t\tif proxy.Name() == selected {')

    patch(fallback, 'selected       string', 'selected       atomic.TypedValue[string]')
    patch(fallback, '"fixed":          f.selected,', '"fixed":          f.selected.Load(),')
    patch(fallback, '\tf.selected = name\n\tif !p.AliveForTestUrl',
          '\tf.selected.Store(name)\n\tif !p.AliveForTestUrl')
    patch(fallback, '\tf.selected = name\n}', '\tf.selected.Store(name)\n}')
    patch(fallback, '\tproxies := f.GetProxies(touch)\n\tfor _, proxy := range proxies {\n'
          '\t\tif len(f.selected) == 0 {',
          '\treturn f.findAliveFrom(f.GetProxies(touch), true)\n}\n\n'
          'func (f *Fallback) dialProxy(ctx context.Context) C.Proxy {\n'
          '\tif proxyip.ReadOnly(ctx) {\n\t\tproxies := f.groupProxies(false, false)\n'
          '\t\tif len(proxies) == 0 {\n\t\t\treturn nil\n\t\t}\n'
          '\t\treturn f.findAliveFrom(proxies, false)\n\t}\n'
          '\treturn f.findAliveProxy(true)\n}\n\n'
          'func (f *Fallback) findAliveFrom(proxies []C.Proxy, persist bool) C.Proxy {\n'
          '\tselected := f.selected.Load()\n\tfor _, proxy := range proxies {\n'
          '\t\tif selected == "" {')
    patch(fallback, 'proxy.Name() == f.selected {', 'proxy.Name() == selected {')
    patch(fallback, '\t\t\t\t\tf.selected = ""',
          '\t\t\t\t\tif persist {\n\t\t\t\t\t\tf.selected.CompareAndSwap(selected, "")\n\t\t\t\t\t}\n'
          '\t\t\t\t\tselected = ""')

    patch(urltest, 'selected       string', 'selected       atomic.TypedValue[string]')
    patch(urltest, 'fastNode       C.Proxy', 'fastNode       atomic.TypedValue[C.Proxy]')
    patch(urltest, '\tu.selected = name', '\tu.selected.Store(name)')
    patch(urltest, '"fixed":          u.selected,', '"fixed":          u.selected.Load(),')
    patch(urltest, '''\t\tproxies := u.GetProxies(touch)
		if u.selected != "" {
			for _, proxy := range proxies {
				if !proxy.AliveForTestUrl(u.testUrl) {
					continue
				}
				if proxy.Name() == u.selected {
					u.fastNode = proxy
					return proxy, nil
				}
			}
		}

		fast := proxies[0]
		minDelay := fast.LastDelayForTestUrl(u.testUrl)
		fastNotExist := true

		for _, proxy := range proxies[1:] {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.AliveForTestUrl(u.testUrl) {
				continue
			}

			delay := proxy.LastDelayForTestUrl(u.testUrl)
			if delay < minDelay {
				fast = proxy
				minDelay = delay
			}

		}
		// tolerance
		if u.fastNode == nil || fastNotExist || !u.fastNode.AliveForTestUrl(u.testUrl) || u.fastNode.LastDelayForTestUrl(u.testUrl) > fast.LastDelayForTestUrl(u.testUrl)+u.tolerance {
			u.fastNode = fast
		}
		return u.fastNode, nil''',
          '''\t\tchosen := u.fastFrom(u.GetProxies(touch))
		u.fastNode.Store(chosen)
		return chosen, nil''')
    patch(urltest, '// SupportUDP implements C.ProxyAdapter',
          '''func (u *URLTest) dialProxy(ctx context.Context) C.Proxy {
	if proxyip.ReadOnly(ctx) {
		proxies := u.groupProxies(false, false)
		if len(proxies) == 0 {
			return nil
		}
		return u.fastFrom(proxies)
	}
	return u.fast(true)
}

func (u *URLTest) fastFrom(proxies []C.Proxy) C.Proxy {
	if selected := u.selected.Load(); selected != "" {
		for _, proxy := range proxies {
			if proxy.AliveForTestUrl(u.testUrl) && proxy.Name() == selected {
				return proxy
			}
		}
	}

	incumbent := u.fastNode.Load()
	fast := proxies[0]
	minDelay := fast.LastDelayForTestUrl(u.testUrl)
	fastNotExist := true
	for _, proxy := range proxies[1:] {
		if incumbent != nil && proxy.Name() == incumbent.Name() {
			fastNotExist = false
		}
		if !proxy.AliveForTestUrl(u.testUrl) {
			continue
		}
		if delay := proxy.LastDelayForTestUrl(u.testUrl); delay < minDelay {
			fast = proxy
			minDelay = delay
		}
	}
	if incumbent == nil || fastNotExist || !incumbent.AliveForTestUrl(u.testUrl) || incumbent.LastDelayForTestUrl(u.testUrl) > fast.LastDelayForTestUrl(u.testUrl)+u.tolerance {
		return fast
	}
	return incumbent
}

// SupportUDP implements C.ProxyAdapter''')

    balance = groups + 'loadbalance.go'
    strategy_args = 'proxies []C.Proxy, metadata *C.Metadata, touch bool'
    patch(balance, f'type strategyFn = func({strategy_args})',
          f'type readOnlySelection struct{{}}\n\ntype strategyFn = func({strategy_args}, probe ...readOnlySelection)')
    for mode, first_line in (
        ('_', 'idxMutex.Lock()'),
        ('_', 'key := utils.MapHash(keyOf(metadata))\n\t\tbuckets :='),
        ('probe', 'key := utils.MapHash(keyOf(metadata))\n\t\tlength :='),
    ):
        anchor = f'return func({strategy_args}) C.Proxy {{\n\t\t{first_line}'
        patch(balance, anchor, anchor.replace('touch bool)', f'touch bool, {mode} ...readOnlySelection)'))
    patch(balance, 'idx, has := lruCache.Get(key)',
          'readOnly := len(probe) != 0\n'
          '\t\tvar idx int\n\t\tvar has bool\n\t\tif readOnly {\n\t\t\tidx, has = lruCache.Peek(key)\n\t\t} else {\n'
          '\t\t\tidx, has = lruCache.Get(key)\n\t\t}')
    patch(balance, 'if !has || nowIdx != idx {', 'if !readOnly && (!has || nowIdx != idx) {')
    patch(balance, '\t\tlruCache.Set(key, 0)', '\t\tif !readOnly {\n\t\t\tlruCache.Set(key, 0)\n\t\t}')
    patch(balance, 'return lb.strategyFn(proxies, metadata, touch)',
          'return lb.strategyFn(proxies, metadata, touch)\n}\n\n'
          'func (lb *LoadBalance) dialProxy(ctx context.Context, metadata *C.Metadata) C.Proxy {\n'
          '\tif proxyip.ReadOnly(ctx) {\n'
          '\t\tproxies := lb.groupProxies(false, false)\n'
          '\t\tif len(proxies) == 0 {\n\t\t\treturn nil\n\t\t}\n'
          '\t\treturn lb.strategyFn(proxies, metadata, false, readOnlySelection{})\n\t}\n'
          '\treturn lb.Unwrap(metadata, true)')

    for path, group, pick, method in (
        (fallback, 'f', 'f.findAliveProxy(true)', 'f.dialProxy(ctx)'),
        (urltest, 'u', 'u.fast(true)', 'u.dialProxy(ctx)'),
        (balance, 'lb', 'lb.Unwrap(metadata, true)', 'lb.dialProxy(ctx, metadata)'),
    ):
        pick_read_only = '\tproxy := ' + method + '\n\tif proxy == nil {\n\t\treturn nil, errProbeNoCandidates\n\t}\n'
        patch(path, '\tproxy := ' + pick + '\n\tc', pick_read_only + '\tc')
        second = '\tproxy := ' + pick + '\n'
        patch(path, second, pick_read_only)
        failure = '\n\t\t' + group + '.onDialFailed(proxy.Type(), err, ' + group + '.healthCheck)\n\t}\n\n\tif N.NeedHandshake'
        patch(path, '\t} else {' + failure, '\t} else if !proxyip.ReadOnly(ctx) {' + failure)
        patch(path, '\tif N.NeedHandshake(c) {', '\tif !proxyip.ReadOnly(ctx) && N.NeedHandshake(c) {')
    patch(urltest, '\t} else {\n\t\tu.onDialFailed(proxy.Type(), err, u.healthCheck)\n\t}\n\n\treturn pc',
          '\t} else if !proxyip.ReadOnly(ctx) {\n\t\tu.onDialFailed(proxy.Type(), err, u.healthCheck)\n\t}\n\n\treturn pc')

    patch('common/lru/lrucache.go', '// Get returns any representation',
          '''// Peek reads a live entry without moving it or expiring it from the cache.
func (c *LruCache[K, V]) Peek(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.cache[key]
	if el == nil || (!c.staleReturn && c.maxAge > 0 && el.Value.expires <= time.Now().Unix()) {
		return lo.Empty[V](), false
	}
	return el.Value.value, true
}

// Get returns any representation''')

    reject = 'adapter/outbound/reject.go'
    patch(reject, 'import (', 'import (\n\t"cfa/native/proxyip"')
    for signature in (
        'func (r *Reject) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {',
        'func (r *Reject) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {',
    ):
        patch(reject, signature, signature + '\n'
              '\tif proxyip.ReadOnly(ctx) && (r.Type() == C.Reject || r.Type() == C.RejectDrop) {\n'
              '\t\treturn nil, proxyip.ErrBlocked\n\t}')

    tunnel = 'tunnel/tunnel.go'
    patch(tunnel, '\tconfigMux     sync.RWMutex', '\tconfigMux     sync.RWMutex\n'
          '\tproxyIPRuntime context.Context\n\tstopProxyIP context.CancelFunc')
    patch(tunnel, 'func OnSuspend() {\n\tstatus.Store(Suspend)\n}',
          '''func OnSuspend() {
	configMux.Lock()
	defer configMux.Unlock()
	status.Store(Suspend)
	if stopProxyIP != nil {
		stopProxyIP()
		proxyIPRuntime, stopProxyIP = nil, nil
	}
}''')
    patch(tunnel, 'func OnRunning() {\n\tstatus.Store(Running)\n}',
          '''func OnRunning() {
	configMux.Lock()
	defer configMux.Unlock()
	if stopProxyIP != nil {
		stopProxyIP()
	}
	proxyIPRuntime, stopProxyIP = context.WithCancel(context.Background())
	status.Store(Running)
}

// ProxyIPProbeTarget captures the target and the lifetime of its running config.
func ProxyIPProbeTarget(name string) (C.Proxy, context.Context) {
	configMux.RLock()
	defer configMux.RUnlock()
	return proxies[name], proxyIPRuntime
}''')
    patch('hub/executor/executor.go', 'func Shutdown() {', 'func Shutdown() {\n\ttunnel.OnSuspend()')
