# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Run the libclash facade smoke on a selected Android emulator/device (no root required)."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--aar', required=True)
    parser.add_argument('--abi', default='x86_64')
    parser.add_argument('--core', choices=['meow', 'mihomo'], default='meow')
    parser.add_argument('--bindings-only', action='store_true', help='Run the shared Android API smoke against either AAR')
    args = parser.parse_args()
    if args.core == 'mihomo' and not args.bindings_only:
        parser.error('The Mihomo smoke uses --bindings-only')
    libraries = ['librsjni.so', 'libmeow.so'] if args.core == 'meow' else ['libgojni.so', 'libmihomo.so']
    source = Path(__file__).with_name('BindingSmoke.java' if args.bindings_only else 'CompatSmoke.java')
    main_class = 'libclash.BindingSmoke' if args.bindings_only else 'libclash.CompatSmoke'
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ['ANDROID_SDK_ROOT'])
    java = Path(os.environ['JAVA_HOME']) / 'bin'
    suffix = '.exe' if os.name == 'nt' else ''
    adb = [str(sdk / 'platform-tools' / ('adb' + suffix)), '-s', args.serial]
    android = sdk / 'platforms/android-37.0/android.jar'
    with tempfile.TemporaryDirectory(prefix='meow-compat-') as directory:
        work = Path(directory)
        classes, dex = work / 'classes', work / 'dex'
        classes.mkdir(); dex.mkdir()
        with zipfile.ZipFile(args.aar) as archive:
            (work / 'classes.jar').write_bytes(archive.read('classes.jar'))
            for name in libraries:
                (work / name).write_bytes(archive.read(f'jni/{args.abi}/{name}'))
        subprocess.run([str(java / ('javac' + suffix)), '--release', '8', '-classpath',
                        os.pathsep.join([str(android), str(work / 'classes.jar')]), '-d', str(classes),
                        str(source)], check=True)
        subprocess.run([str(java / ('java' + suffix)), '-cp', str(sdk / 'build-tools/37.0.0/lib/d8.jar'),
                        'com.android.tools.r8.D8', '--min-api', '26', '--lib', str(android), '--output', str(dex),
                        str(work / 'classes.jar'), *map(str, classes.rglob('*.class'))], check=True)
        remote = f'/data/local/tmp/{work.name}'
        subprocess.run([*adb, 'shell', 'mkdir', '-p', remote], check=True)
        try:
            for artifact in [dex / 'classes.dex', *[work / name for name in libraries]]:
                subprocess.run([*adb, 'push', str(artifact), remote + '/' + artifact.name], check=True)
            subprocess.run([*adb, 'shell', 'chmod', '755', remote + '/' + libraries[1]], check=True)
            subprocess.run([*adb, 'shell', f'CLASSPATH={remote}/classes.dex app_process -Djava.library.path={remote} /system/bin {main_class} {remote}/home'], check=True, timeout=120)
        finally:
            # This exact directory was allocated by TemporaryDirectory above.
            subprocess.run([*adb, 'shell', 'rm', '-rf', remote], check=True)


if __name__ == '__main__':
    main()
