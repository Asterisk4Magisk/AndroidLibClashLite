# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Materialize the pinned meow sources and apply the reviewed Android patches."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile


def prepare(source=None, root=None):
    root = pathlib.Path(root) if root is not None else pathlib.Path(__file__).resolve().parents[1]
    rust = root / 'rust'
    pin = json.loads((rust / 'upstream.json').read_text())
    patches = sorted((rust / 'patches').glob('*.patch'))
    digest = hashlib.sha256((rust / 'upstream.json').read_bytes())
    for patch in patches:
        digest.update(patch.name.encode())
        digest.update(patch.read_bytes())
    generated = rust / '.upstream'
    generated.mkdir(exist_ok=True)
    stamp = generated / 'prepared'
    if stamp.exists() and stamp.read_text() == digest.hexdigest():
        return generated / 'meow'
    if source is None:
        source = generated / 'repository'
        if not (source / 'HEAD').exists():
            subprocess.run(['git', 'init', '--bare', str(source)], check=True)
        subprocess.run(['git', '-C', str(source), 'fetch', '--depth=1',
                        pin['repository'], pin['revision']], check=True)
    source = pathlib.Path(source).resolve()
    revision = subprocess.check_output(
        ['git', '-C', str(source), 'rev-parse', pin['revision'] + '^{commit}'], text=True).strip()
    if revision != pin['revision']:
        raise ValueError('Upstream revision mismatch')
    archive = generated / 'source.tar'
    subprocess.run(['git', '-C', str(source), 'archive', '--format=tar',
                    '--output=' + str(archive), revision], check=True)
    destination = generated / 'meow'
    # A failed rebuild must not leave a valid stamp for the previous sources.
    stamp.unlink(missing_ok=True)
    # This directory is generated, never a checkout edited by the user.
    if destination.exists():
        if destination.is_symlink() or destination.resolve().parent != generated.resolve():
            raise ValueError('Unexpected generated source path')
        shutil.rmtree(destination)
    destination.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(destination, filter='data')
    archive.unlink()
    env = os.environ.copy()
    env['GIT_CEILING_DIRECTORIES'] = str(generated.parent.resolve())
    for patch in patches:
        command = ['git', 'apply', '--unsafe-paths', '--directory=' + destination.as_posix()]
        subprocess.run([*command, '--check', str(patch)], cwd=generated, env=env, check=True)
        subprocess.run([*command, str(patch)], cwd=generated, env=env, check=True)
    stamp.write_text(digest.hexdigest())
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', help='Existing upstream Git checkout for offline preparation')
    print(prepare(parser.parse_args().source))
