"""Smoke-test the standalone helper on an already running, rootable AVD.

Pass a D8-compiled helper dex with --dex, the NDK-compiled socketpair launcher
with --launcher and an adb serial with --serial.
No APK installation or Android Application/Service is involved. Temporarily
disables Wi-Fi/mobile data and restores their initial enabled states.
"""
import argparse
import json
import pathlib
import selectors
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--dex', required=True, type=pathlib.Path)
    parser.add_argument('--launcher', required=True, type=pathlib.Path)
    args = parser.parse_args()
    adb = ['adb', '-s', args.serial]

    def run(*command):
        return subprocess.check_output(adb + list(command), text=True, timeout=40).strip()

    def shell(*command):
        return run('shell', shlex.join(command))

    assert shell('getprop', 'ro.kernel.qemu') == '1', 'This test expects an AVD'
    run('root')
    run('wait-for-device')
    assert shell('id', '-u') == '0'
    remote = '/data/local/tmp/asteriskmeta-dns-smoke.dex'
    launcher = '/data/local/tmp/asteriskmeta-dns-smoke'
    run('push', str(args.dex.resolve()), remote)
    run('push', str(args.launcher.resolve()), launcher)
    shell('chmod', '700', launcher)
    initial = {
        'wifi': shell('settings', 'get', 'global', 'wifi_on') != '0',
        'data': shell('settings', 'get', 'global', 'mobile_data') != '0',
    }
    process = None
    with tempfile.TemporaryFile() as errors:
        try:
            command = shlex.join([launcher, remote])
            process = subprocess.Popen(adb + ['shell', '-T', command],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, bufsize=0)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(20), 'Helper readiness timed out'
                assert process.stdout.readline().strip() == b'READY 1', 'Helper failed to start'
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                stream = process.stdout
                def snapshot():
                    assert selector.select(30), 'DNS snapshot timed out'
                    frame = stream.readline(8193)
                    assert frame.endswith(b'\n') and len(frame) <= 8192
                    value = json.loads(frame)
                    assert value['version'] == 1 and isinstance(value['servers'], list)
                    print(value, flush=True)
                    return value['servers']

                print('Initial snapshot:', flush=True)
                snapshot()
                for kind in ('data', 'wifi'):
                    shell('svc', kind, 'disable')
                print('Disconnected snapshot:', flush=True)
                while snapshot():
                    pass
                for kind in ('data', 'wifi'):
                    shell('svc', kind, 'enable')
                print('Reconnected snapshot:', flush=True)
                while not snapshot():
                    pass
            process.stdin.close()
            assert process.wait(timeout=10) == 0, 'Helper did not exit on parent-pipe EOF'
            print('PASS: callbacks, empty snapshot, reconnect and parent-pipe EOF', flush=True)
        except BaseException:
            errors.seek(0)
            print(errors.read().decode(errors='replace'))
            raise
        finally:
            for kind, enabled in initial.items():
                shell('svc', kind, 'enable' if enabled else 'disable')
            if process and process.poll() is None:
                if not process.stdin.closed:
                    process.stdin.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
            shell('rm', '-f', remote)
            shell('rm', '-f', launcher)


if __name__ == '__main__':
    main()
