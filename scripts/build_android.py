# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Android helper shared by the Go and Rust packages."""
import pathlib
import os
import subprocess


def binding_sources(repo, core):
    """Return source files and their package-relative paths in the sources JAR."""
    sources = []
    for root in (repo / 'android', repo / core):
        sources.extend((source, source.relative_to(root).as_posix())
                       for source in sorted((root / 'libclash').rglob('*.java')))
    return sources


def compile_bindings(repo, core, work, env, classpath=()):
    sdk = pathlib.Path(env.get('ANDROID_HOME') or env['ANDROID_SDK_ROOT'])
    android = sdk / 'platforms/android-37.0/android.jar'
    suffix = '.exe' if os.name == 'nt' else ''
    javac = pathlib.Path(env['JAVA_HOME']) / 'bin' / ('javac' + suffix)
    classes = work / 'binding-classes'
    classes.mkdir(parents=True, exist_ok=True)
    # javac otherwise retains classes whose sources were removed between builds.
    for stale in classes.rglob('*.class'):
        stale.unlink()
    sources = binding_sources(repo, core)
    subprocess.run([str(javac), '--release', '8', '-classpath',
                    os.pathsep.join(map(str, [android, *classpath])), '-d', str(classes),
                    *[str(source) for source, _ in sources]], env=env, check=True)
    return [(p.relative_to(classes).as_posix(), p.read_bytes()) for p in sorted(classes.rglob('*.class'))]


def system_dns_dex(repo, work, env):
    sdk = pathlib.Path(env.get('ANDROID_HOME') or env['ANDROID_SDK_ROOT']).resolve()
    android_jar = sdk / 'platforms/android-37.0/android.jar'
    d8 = sdk / 'build-tools/37.0.0/lib/d8.jar'
    for required in (android_jar, d8):
        if not required.is_file():
            raise ValueError(f'Android SDK component missing: {required}')
    suffix = '.exe' if os.name == 'nt' else ''
    def java_tool(name):
        return str(pathlib.Path(env['JAVA_HOME']) / 'bin' / (name + suffix)) if env.get('JAVA_HOME') else name + suffix
    classes, dex = work / 'system-dns-classes', work / 'system-dns-dex'
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(parents=True, exist_ok=True)
    subprocess.run([java_tool('javac'), '--release', '8', '-classpath', str(android_jar),
                    '-d', str(classes), *map(str, sorted((repo / 'android/systemdns').glob('*.java')))], env=env, check=True)
    subprocess.run([java_tool('java'), '-cp', str(d8), 'com.android.tools.r8.D8', '--release',
                    '--min-api', '26', '--lib', str(android_jar), '--output', str(dex),
                    *map(str, sorted(classes.rglob('*.class')))], env=env, check=True)
    if sorted(p.name for p in dex.iterdir()) != ['classes.dex']:
        raise ValueError('System DNS helper must fit in one dex')
    return dex / 'classes.dex'
