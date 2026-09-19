"""Generate CLI/CMFA runtime overlays without editing pinned upstream sources."""
import json
import pathlib
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
    cli = work / 'cli'
    cli.mkdir(exist_ok=True)
    (cli / 'mihomo_cli.go').write_text(main, encoding='utf-8')
    shutil.copyfile(repo / 'native/cli/export.go.txt', cli / 'cli_export.go')

    patches = {}
    def patch(name, old, new):
        text = patches.get(name, (core / name).read_text(encoding='utf-8'))
        patches[name] = replace_once(text, old, new)

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
          'package dns\n\nimport "github.com/metacubex/mihomo/constant/features"')
    patch('dns/patch_android.go', 'func (c *systemClient) getDnsClients() ([]dnsClient, error) {',
          'func (c *systemClient) getDnsClients() ([]dnsClient, error) {\n'
          '\tif !features.CMFA { return c.getNativeDnsClients() }')
    patch('dns/patch_android.go', 'func (c *systemClient) ResetConnection() {',
          'func (c *systemClient) ResetConnection() {\n'
          '\tif !features.CMFA { c.resetNativeConnection(); return }')
    patches['log/log.go'] = (repo / 'overlay/mihomo/log/log.go').read_text(encoding='utf-8')

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
    overlay = work / 'overlay.json'
    overlay.write_text(json.dumps({'Replace': replacements}), encoding='utf-8')
    return source, overlay
