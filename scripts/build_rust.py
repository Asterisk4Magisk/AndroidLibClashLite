# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Build the meow JNI library and its ROOT launcher (Python 3.12+, Rust, JDK, SDK/NDK)."""
import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
import zipfile
from prepare_rust import prepare
from build_android import system_dns_dex, binding_sources, compile_bindings

ARCHES = {
    'arm': ('armeabi-v7a', 'armv7-linux-androideabi', 'armv7a-linux-androideabi'),
    'arm64': ('arm64-v8a', 'aarch64-linux-android', 'aarch64-linux-android'),
    '386': ('x86', 'i686-linux-android', 'i686-linux-android'),
    'amd64': ('x86_64', 'x86_64-linux-android', 'x86_64-linux-android'),
}
CORE_LIBRARY = 'librsjni.so'
LAUNCHER = 'libmeow.so'


def run(command, cwd, env):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)


def zip_files(output, entries, epoch):
    stamp = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.timezone.utc)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data, executable in sorted(entries):
            info = zipfile.ZipInfo(name, stamp.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            archive.writestr(info, data)


def verify_elf(readelf, library, launcher):
    for path in (library, launcher):
        headers = subprocess.check_output([str(readelf), '-lW', str(path)], text=True)
        loads = [line.split() for line in headers.splitlines() if line.strip().startswith('LOAD ')]
        if not loads or any(int(row[-1], 16) < 16384 for row in loads):
            raise ValueError(f'ELF is not aligned for 16 KB pages: {path}')
        dynamic = subprocess.check_output([str(readelf), '-dW', str(path)], text=True)
        dependencies = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
        allowed = {'libc.so', 'libm.so', 'libdl.so', 'liblog.so', 'libandroid.so'}
        if set(dependencies) - allowed:
            raise ValueError(f'Unbundled native dependencies in {path}: {dependencies}')
    symbols = subprocess.check_output([str(readelf), '--dyn-syms', '-W', str(library)], text=True)
    for symbol in ('AndroidMeowCLI_v1', 'Java_libclash_NativeBridge_startFromBytes',
                   'Java_libclash_NativeBridge_stop', 'Java_libclash_NativeBridge_notifyDnsChanged'):
        if symbol not in symbols:
            raise ValueError(f'Missing native entry point: {symbol}')


def build(args, work):
    repo = pathlib.Path(__file__).resolve().parents[1]
    prepare()
    pin = json.loads((repo / 'rust/upstream.json').read_text())
    env = os.environ.copy()
    ndk_value = env.get('ANDROID_NDK_HOME') or env.get('ANDROID_NDK_ROOT')
    if not ndk_value:
        raise ValueError('Set ANDROID_NDK_HOME to an installed Android NDK')
    ndk = pathlib.Path(ndk_value).resolve()
    host = {'Windows': 'windows-x86_64', 'Linux': 'linux-x86_64', 'Darwin': 'darwin-x86_64'}[platform.system()]
    suffix = '.exe' if os.name == 'nt' else ''
    bin_dir = ndk / 'toolchains/llvm/prebuilt' / host / 'bin'
    clang = bin_dir / ('clang' + suffix)
    if not clang.is_file():
        raise ValueError(f'NDK clang not found: {clang}')
    for name in ('tmp', 'classes', 'jni', 'toolchains'):
        (work / name).mkdir(parents=True, exist_ok=True)
    env.update(TEMP=str(work / 'tmp'), TMP=str(work / 'tmp'), TMPDIR=str(work / 'tmp'))
    env['CARGO_TARGET_DIR'] = str(work / 'target')
    env['ANDROID_NDK_HOME'] = str(ndk)
    env['BORING_BSSL_RUST_CPPLIB'] = 'c++_static'
    env['LIBCLASH_SYSTEM_DNS_DEX'] = str(system_dns_dex(repo, work, env))
    # bindgen needs a host libclang shared library, which the Windows NDK does
    # not ship. Respect LIBCLANG_PATH or clang-sys's system discovery.
    # In particular Windows CMake must not pick the Visual Studio generator.
    env.setdefault('CMAKE_GENERATOR', 'Ninja')
    env['PATH'] = str(bin_dir) + os.pathsep + env['PATH']
    artifacts = {}
    for arch in args.arch:
        abi, rust_target, clang_target = ARCHES[arch]
        target_env = env.copy()
        compiler_target = clang_target + str(args.api)
        key = rust_target.replace('-', '_')
        target_env[f'CARGO_TARGET_{key.upper()}_LINKER'] = str(clang)
        target_env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join([
            '-C', f'link-arg=--target={compiler_target}',
            '-C', 'link-arg=-Wl,-z,max-page-size=16384',
            '-C', 'link-arg=-Wl,--build-id=none',
        ])
        target_env[f'CC_{key}'] = str(clang)
        target_env[f'CXX_{key}'] = str(bin_dir / ('clang++' + suffix))
        target_env[f'CFLAGS_{key}'] = f'--target={compiler_target}'
        target_env[f'CXXFLAGS_{key}'] = f'--target={compiler_target}'
        target_env[f'AR_{key}'] = str(bin_dir / ('llvm-ar' + suffix))
        wrapper = work / 'toolchains' / (rust_target + '.cmake')
        wrapper.write_text(
            f'set(ANDROID_ABI {abi})\nset(ANDROID_PLATFORM android-{args.api})\n'
            f'include("{(ndk / "build/cmake/android.toolchain.cmake").as_posix()}")\n', encoding='utf-8')
        target_env[f'CMAKE_TOOLCHAIN_FILE_{key}'] = str(wrapper)
        command = ['cargo', 'check' if args.check else 'build', '--locked', '--target', rust_target]
        if args.profile == 'release':
            command.append('--release')
        run(command, repo / 'rust', target_env)
        if args.check:
            continue
        directory = work / 'jni' / abi
        directory.mkdir(parents=True, exist_ok=True)
        core = directory / CORE_LIBRARY
        shutil.copyfile(work / 'target' / rust_target / args.profile / CORE_LIBRARY, core)
        launcher = directory / LAUNCHER
        run([clang, f'--target={compiler_target}', '-O2', '-fPIE', '-pie', '-Wall', '-Wextra', '-Werror',
             '-Wl,-z,max-page-size=16384', '-Wl,--build-id=none', '-Wl,-s',
             '-o', launcher, repo / 'rust/native/launcher.c', '-ldl'], repo, target_env)
        verify_elf(bin_dir / ('llvm-readelf' + suffix), core, launcher)
        artifacts[abi] = (core, launcher)
    if args.check:
        return
    compiled = compile_bindings(repo, 'rust', work, env)
    sources = binding_sources(repo, 'rust')
    epoch = int(env.get('SOURCE_DATE_EPOCH', '315532800'))
    classes = work / 'classes.jar'
    zip_files(classes, [(name, data, False) for name, data in compiled], epoch)
    manifest = (f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="libclash">'
                f'<uses-sdk android:minSdkVersion="{args.api}"/></manifest>')
    entries = [('AndroidManifest.xml', manifest.encode(), False),
               ('classes.jar', classes.read_bytes(), False),
               ('proguard.txt', b'-keep class libclash.** { *; }\n', False)]
    for abi, binaries in artifacts.items():
        entries.extend((f'jni/{abi}/{p.name}', p.read_bytes(), True) for p in binaries)
    entries.extend((f'META-INF/licenses/{p.name}', p.read_bytes(), False)
                   for p in sorted((repo / 'rust/licenses').glob('*.txt')))
    entries.append(('META-INF/licenses/AndroidLibClashLite.txt', (repo / 'LICENSE').read_bytes(), False))
    output = pathlib.Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    zip_files(output, entries, epoch)
    zip_files(output.with_name(output.stem + '-sources.jar'),
              [(name, source.read_bytes(), False) for source, name in sources], epoch)
    (work / 'build-info.json').write_text(json.dumps({
        'core': 'meow', 'version': pin['version'], 'revision': pin['revision'],
        'abis': list(artifacts), 'api': args.api, 'profile': args.profile, 'output': str(output),
    }, indent=2), encoding='utf-8')
    print(f'Built {output}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', nargs='+', choices=ARCHES, default=list(ARCHES))
    parser.add_argument('--api', type=int, default=26)
    parser.add_argument('--profile', choices=('debug', 'release'), default='release')
    parser.add_argument('--check', action='store_true', help='Type-check selected Android targets without packaging')
    parser.add_argument('--output', default='libclash-rs.aar')
    parser.add_argument('--work-dir', help='Retain Cargo cache, artifacts and build metadata')
    args = parser.parse_args()
    if args.api < 26 or len(args.arch) != len(set(args.arch)):
        parser.error('API must be >= 26 and architectures must be unique')
    if args.work_dir:
        work = pathlib.Path(args.work_dir).resolve()
        work.mkdir(parents=True, exist_ok=True)
        build(args, work)
    else:
        with tempfile.TemporaryDirectory(prefix='clash-rs-') as directory:
            build(args, pathlib.Path(directory))


if __name__ == '__main__':
    main()
