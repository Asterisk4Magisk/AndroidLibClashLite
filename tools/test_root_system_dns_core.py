"""Exercise the real standalone core and its embedded helper on a rootable AVD.

Requires an x86_64 AAR, its javac/D8 helper dex from build staging, and adb.
Owns only /data/local/tmp/libclash-system-dns-test and an optional dedicated home.
Temporarily toggles Wi-Fi/data and restores their original settings.
"""
import argparse
import hashlib
import json
import pathlib
import shlex
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--aar', required=True, type=pathlib.Path)
    parser.add_argument('--dex', required=True, type=pathlib.Path)
    parser.add_argument('--home', help='Dedicated test directory, including under app filesDir')
    parser.add_argument('--force-stop-app', help='Also verify independence from this installed app')
    args = parser.parse_args()
    adb = ['adb', '-s', args.serial]
    remote = '/data/local/tmp/libclash-system-dns-test'
    home = args.home or remote + '/home'
    helper_file = home + '/system-dns-helper.dex'

    def call(*command, check=True):
        result = subprocess.run(adb + list(command), text=True, capture_output=True, timeout=40)
        if check and result.returncode:
            raise RuntimeError((command, result.stdout, result.stderr))
        return result.stdout.strip()

    def shell(*command, check=True):
        return call('shell', shlex.join(command), check=check)

    def until(action, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = action()
                if result:
                    return result
            except (OSError, ValueError):
                pass
            time.sleep(.1)
        raise AssertionError('Timed out: ' + str(action))

    def alive(pid):
        value = shell('cat', '/proc/' + str(pid) + '/stat', check=False)
        return bool(value) and not value.split(') ', 1)[1].startswith('Z')

    def query(name='example.com'):
        return json.load(urllib.request.urlopen(
            'http://127.0.0.1:19090/dns/query?name=' + name + '&type=A', timeout=2))

    def resolved():
        try:
            result = query()
        except urllib.error.HTTPError as error:
            if error.code != 500:
                raise
            return False
        return result.get('Status') == 0 and result.get('Answer')

    def helper_pid(owner):
        for line in shell('ps', '-A', '-o', 'PID,PPID,NAME').splitlines()[1:]:
            pid, parent, name = line.split(maxsplit=2)
            if int(parent) == owner and name == 'libclash-system-dns':
                return int(pid)
        return None

    assert shell('getprop', 'ro.kernel.qemu') == '1', 'Use an AVD'
    call('root')
    call('wait-for-device')
    assert shell('id', '-u') == '0'
    assert shell('getenforce') == 'Enforcing'
    initial = {kind: shell('settings', 'get', 'global', setting) != '0'
               for kind, setting in [('wifi', 'wifi_on'), ('data', 'mobile_data')]}
    shell('mkdir', '-p', remote, home)
    expected = hashlib.sha256(args.dex.read_bytes()).hexdigest()
    process = None
    owner = observer = None

    with tempfile.TemporaryDirectory() as tempdir:
        temp = pathlib.Path(tempdir)
        with zipfile.ZipFile(args.aar) as aar:
            for name in ('libgojni.so', 'libmihomo.so'):
                file = temp / name
                file.write_bytes(aar.read('jni/x86_64/' + name))
                call('push', str(file), remote + '/' + name)
        shell('chmod', '755', remote + '/libmihomo.so')
        config = temp / 'config.yaml'
        config.write_text('''mixed-port: 18080
external-controller: 127.0.0.1:19090
log-level: warning
dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [rcode://name_error]
  nameserver-policy:
    'example.com': system
  direct-nameserver: [system]
rules: ["MATCH,DIRECT"]
''')
        call('push', str(config), home + '/config.yaml')
        for port in ('19090', '18080'):
            call('forward', 'tcp:' + port, 'tcp:' + port)
        logs = open(temp / 'core.log', 'w+')

        def start():
            nonlocal process, owner, observer
            shell('rm', '-f', remote + '/core.pid')
            command = ('echo $$ > ' + shlex.quote(remote + '/core.pid') + '; exec ' +
                       shlex.join([remote + '/libmihomo.so', '-d', home, '-f', home + '/config.yaml']))
            process = subprocess.Popen(adb + ['shell', '-T', command], stdin=subprocess.DEVNULL,
                                       stdout=logs, stderr=subprocess.STDOUT)
            owner = int(until(lambda: shell('cat', remote + '/core.pid', check=False)))
            until(resolved)
            observer = until(lambda: helper_pid(owner))
            assert shell('sha256sum', helper_file).split()[0] == expected
            assert shell('stat', '-c', '%a %u', helper_file) == '400 0'
            return observer

        def stop():
            if process is not None and process.poll() is None:
                shell('kill', '-TERM', str(owner))
                assert process.wait(timeout=10) == 0
            if observer is not None:
                until(lambda: not alive(observer))

        try:
            # Use a separate empty home so a previous retained cache is harmless.
            tools_home = home + '/tools-home'
            shell('mkdir', '-p', tools_home)
            for flags in [('-v',), ('-h',), ('-t', '-f', home + '/config.yaml')]:
                shell(remote + '/libmihomo.so', '-d', tools_home, *flags)
                assert not shell('ls', tools_home + '/system-dns-helper.dex', check=False)
            print('PASS tool commands do not create helper dex', flush=True)
            start()
            if args.force_stop_app:
                shell('am', 'force-stop', args.force_stop_app)
                assert alive(owner) and alive(observer) and resolved()
                print('PASS app force-stop leaves core/helper running and resolving', flush=True)
            assert query('example.org')['Status'] == 3
            with socket.create_connection(('127.0.0.1', 18080), timeout=15) as proxy:
                proxy.settimeout(15)
                proxy.sendall(b'CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n')
                response = b''
                while b'\r\n\r\n' not in response:
                    part = proxy.recv(512)
                    assert part, 'CONNECT closed before response'
                    response += part
                assert b'200' in response.split(b'\r\n', 1)[0]
                with ssl.create_default_context().wrap_socket(proxy, server_hostname='example.org') as tls:
                    assert tls.version()
            print('PASS system nameserver-policy and DIRECT resolution', flush=True)
            assert shell('readlink', '/proc/' + str(observer) + '/fd/0') == shell(
                'readlink', '/proc/' + str(observer) + '/fd/3')
            assert 'asterisk.system-dns' not in shell('cat', '/proc/net/unix')
            print('PASS inherited socketpair supplies snapshots and parent lifeline', flush=True)
            for kind in ('data', 'wifi'):
                shell('svc', kind, 'disable')
            until(lambda: not resolved())
            for kind in ('data', 'wifi'):
                shell('svc', kind, 'enable')
            until(resolved, timeout=30)
            print('PASS offline empty snapshot and online DNS recovery', flush=True)
            identity = shell('stat', '-c', '%i %Y', helper_file)
            stop()
            assert shell('sha256sum', helper_file).split()[0] == expected
            start()
            assert shell('stat', '-c', '%i %Y', helper_file) == identity
            stop()
            print('PASS graceful exit retains dex; restart reuses inode and mtime', flush=True)
            corrupt = temp / 'stale.dex'
            data = bytearray(args.dex.read_bytes())
            data[-1] ^= 1
            corrupt.write_bytes(data)
            call('push', str(corrupt), helper_file)
            start()
            assert shell('stat', '-c', '%i %Y', helper_file) != identity
            print('PASS same-size stale dex replaced before ART loads it', flush=True)
            shell('kill', '-KILL', str(observer))
            assert process.wait(timeout=10) == 70
            until(lambda: not alive(observer))
            print('PASS helper failure exits core with status 70', flush=True)
            start()
            shell('kill', '-STOP', str(observer))
            shell('kill', '-KILL', str(owner))
            assert process.wait(timeout=10) == 137
            until(lambda: not alive(observer))
            print('PASS core SIGKILL also kills stopped helper via pinned-thread PDEATHSIG', flush=True)
        except BaseException:
            logs.flush()
            logs.seek(0)
            print(logs.read())
            raise
        finally:
            for kind, enabled in initial.items():
                shell('svc', kind, 'enable' if enabled else 'disable')
            if process is not None and process.poll() is None:
                stop()
            logs.close()
            for port in ('19090', '18080'):
                call('forward', '--remove', 'tcp:' + port, check=False)


if __name__ == '__main__':
    main()
