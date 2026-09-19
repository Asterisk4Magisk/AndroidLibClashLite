"""Build gomobile bindings plus a CLI sharing one Mihomo library (Python 3.10+)."""
import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from prepare_sources import prepare_sources

ARCHES = {
    'arm': ('armeabi-v7a', 'armv7a-linux-androideabi'),
    'arm64': ('arm64-v8a', 'aarch64-linux-android'),
    '386': ('x86', 'i686-linux-android'),
    'amd64': ('x86_64', 'x86_64-linux-android'),
}


def copy_writable(source, target):
    target = pathlib.Path(target)
    if target.exists():
        target.chmod(stat.S_IREAD | stat.S_IWRITE)
    return shutil.copyfile(source, target)


def writable_directories(root):
    # copytree preserves the Unix module cache's read-only directory modes.
    for directory, _, _ in os.walk(root, followlinks=False):
        path = pathlib.Path(directory)
        path.chmod(path.stat().st_mode | stat.S_IRWXU)


def reset_staging(work):
    stage = work / 'androidlibclash-staging'
    marker = stage / '.owned-by-build-shared'
    if stage.exists():
        if stage.is_symlink() or stage.resolve().parent != work.resolve() or not marker.is_file():
            raise ValueError(f'Refusing to replace unrecognized staging directory: {stage}')
        writable_directories(stage)
        shutil.rmtree(stage)
    stage.mkdir()
    marker.touch()
    return stage


def run(command, cwd, env, log=None):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    result = subprocess.run(list(map(str, command)), cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if log:
        pathlib.Path(log).write_text(result.stdout, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stdout)
    return result.stdout.strip()


def package_aar(baseline, target, artifacts):
    replacements = {}
    for abi, (core, launcher) in artifacts.items():
        replacements[f'jni/{abi}/libgojni.so'] = core
        replacements[f'jni/{abi}/libmihomo.so'] = launcher
    with zipfile.ZipFile(baseline) as original, zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as package:
        expected = {f'jni/{abi}/libgojni.so' for abi in artifacts}
        actual = {name for name in original.namelist() if name.startswith('jni/') and name.endswith('.so')}
        if actual != expected:
            raise ValueError(f'Unexpected gomobile native entries: {actual}')
        for entry in original.infolist():
            if entry.filename not in replacements:
                package.writestr(entry, original.read(entry))
        for name, path in replacements.items():
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100755 << 16
            package.writestr(entry, path.read_bytes())


def build(args, work):
    repo = pathlib.Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    for name in ('GOOS', 'GOARCH', 'GOARM', 'CC', 'CXX', 'CGO_ENABLED'):
        env.pop(name, None)
    temp = pathlib.Path('C:/Temp') if os.name == 'nt' else work / 'tmp'
    temp.mkdir(parents=True, exist_ok=True)
    env.update(TEMP=str(temp), TMP=str(temp), TMPDIR=str(temp))
    env['JAVA_TOOL_OPTIONS'] = env.get('JAVA_TOOL_OPTIONS', '') + f' -Djava.io.tmpdir="{temp}"'
    ndk = pathlib.Path(env['ANDROID_NDK_HOME']).resolve()
    host = {'Windows': 'windows-x86_64', 'Linux': 'linux-x86_64', 'Darwin': 'darwin-x86_64'}[platform.system()]
    suffix = '.exe' if os.name == 'nt' else ''
    clang = ndk / 'toolchains/llvm/prebuilt' / host / ('bin/clang' + suffix)
    if not clang.is_file():
        raise ValueError(f'NDK clang missing: {clang}')
    module = json.loads(run(['go', 'mod', 'download', '-json', 'github.com/metacubex/mihomo'], repo, env))
    stage = reset_staging(work)
    core = stage / 'mihomo'
    shutil.copytree(module['Dir'], core, dirs_exist_ok=True, copy_function=copy_writable)
    writable_directories(core)
    version = module['Version']
    source, overlay = prepare_sources(repo, stage, core)
    run(['go', 'mod', 'edit', '-replace=github.com/metacubex/mihomo=../mihomo'], source, env)
    epoch = int(env.get('SOURCE_DATE_EPOCH', datetime.datetime.now(datetime.timezone.utc).timestamp()))
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    stamp = date.strftime('%Y-%m-%dT%H:%M:%SZ')
    ldflags = f'-s -w -buildid= -X github.com/metacubex/mihomo/constant.Version={version} -X github.com/metacubex/mihomo/constant.BuildTime={stamp}'
    mobile = run(['go', 'list', '-m', '-f', '{{.Version}}', 'golang.org/x/mobile'], source, env)
    tools = work / 'tools'
    tools.mkdir(exist_ok=True)
    env['GOBIN'] = str(tools)
    env['PATH'] = str(tools) + os.pathsep + env['PATH']
    env['CGO_LDFLAGS'] = '-Wl,-z,max-page-size=16384'
    for name in ('gomobile', 'gobind'):
        run(['go', 'install', f'golang.org/x/mobile/cmd/{name}@{mobile}'], source, env)
    baseline = stage / 'baseline.aar'
    output = run([tools / ('gomobile' + suffix), 'bind', '-work', '-x', '-target',
        ','.join('android/' + arch for arch in args.arch), '-androidapi', str(args.api),
        '-overlay', overlay, '-tags=foss,with_gvisor,cmfa', '-trimpath', '-ldflags=' + ldflags,
        '-o', baseline, '.'], source, env, work / 'gomobile.log')
    matches = re.findall(r'^WORK=(.+)$', output, re.MULTILINE)
    if not matches:
        raise ValueError('gomobile did not report its work directory')
    generated = pathlib.Path(matches[-1].strip())
    jni = stage / 'jni'
    artifacts = {}
    for arch in args.arch:
        abi, triple = ARCHES[arch]
        output = jni / abi
        output.mkdir(parents=True, exist_ok=True)
        target = f'--target={triple}{args.api}'
        goenv = dict(env, GOOS='android', GOARCH=arch, GOARM='7', CGO_ENABLED='1',
                     CC=f'"{clang}" {target}', CGO_LDFLAGS='-Wl,-z,max-page-size=16384')
        bound_module = generated / ('src-android-' + arch)
        for cli_source in (stage / 'cli').glob('*.go'):
            shutil.copyfile(cli_source, bound_module / 'gobind' / cli_source.name)
        # gomobile tidies before it sees the injected CLI, which adds dependencies
        # such as automaxprocs. Resolve those in the generated module only.
        run(['go', 'mod', 'tidy'], bound_module, goenv, work / (abi + '-modules.log'))
        run(['go', 'build', '-mod=readonly', '-overlay', overlay, '-trimpath',
             '-tags=foss,with_gvisor,cmfa', '-ldflags=' + ldflags, '-buildmode=c-shared',
             '-o', output / 'libgojni.so', './gobind'], bound_module, goenv, work / (abi + '.log'))
        common = [clang, target, '-O2', '-fPIC', '-Wl,-z,max-page-size=16384', '-Wl,--build-id=none', '-Wl,-s']
        run(common + ['-fPIE', '-pie', '-Wall', '-Wextra', '-Werror',
            '-o', output / 'libmihomo.so', repo / 'native/cli/launcher.c', '-ldl'], repo, env)
        artifacts[abi] = (output / 'libgojni.so', output / 'libmihomo.so')
    aar = stage / 'libclash.aar'
    package_aar(baseline, aar, artifacts)
    target = pathlib.Path(args.output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(aar, target)
    shutil.copyfile(stage / 'baseline-sources.jar', target.with_name(target.stem + '-sources.jar'))
    (work / 'build-info.json').write_text(json.dumps({'core': version, 'abis': args.arch,
        'mobile': mobile, 'gomobile_work': str(generated),
        'output': str(target), 'source_date_epoch': int(date.timestamp())}, indent=2))
    print(f'Built {target}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', nargs='+', choices=ARCHES, default=list(ARCHES))
    parser.add_argument('--api', type=int, default=26)
    parser.add_argument('--output', default='libclash.aar')
    parser.add_argument('--work-dir', help='Retain native artifacts, generated sources and build logs')
    args = parser.parse_args()
    if args.api < 26 or len(args.arch) != len(set(args.arch)):
        parser.error('API must be >= 26 and architectures must be unique')
    if args.work_dir:
        work = pathlib.Path(args.work_dir).resolve()
        work.mkdir(parents=True, exist_ok=True)
        build(args, work)
    else:
        if os.name == 'nt':
            pathlib.Path('C:/Temp').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='clash-shared-', dir='C:/Temp' if os.name == 'nt' else None) as directory:
            build(args, pathlib.Path(directory))


if __name__ == '__main__':
    main()
