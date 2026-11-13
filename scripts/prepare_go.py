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
