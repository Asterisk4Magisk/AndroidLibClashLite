# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Check stable Mihomo/meow releases and prepare one combined core update."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
import urllib.error
import urllib.parse
import urllib.request

MODULE = 'github.com/metacubex/mihomo'
UPSTREAM = 'MetaCubeX/mihomo'
STABLE = re.compile(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)')


def version(tag):
    match = STABLE.fullmatch(tag)
    if not match:
        raise ValueError(f'Not a stable version tag: {tag!r}')
    return tuple(map(int, match.groups()))


def select_stable(releases):
    tags = [r['tag_name'] for r in releases
            if not r.get('draft') and not r.get('prerelease')
            and STABLE.fullmatch(r.get('tag_name', ''))]
    if not tags:
        raise ValueError('Upstream has no published stable vMAJOR.MINOR.PATCH release')
    return max(tags, key=version)


def plan_update(current, latest, tags):
    target = {core: max((current[core], latest[core]), key=version) for core in current}
    go_update = target['go'] != current['go']
    rust_update = target['rust'] != current['rust']
    pattern = re.compile(re.escape(target['go']) + r'(?:-android\.([1-9]\d*))?')
    revisions = [int(match.group(1) or 0) for tag in tags if (match := pattern.fullmatch(tag))]
    if go_update or not revisions:
        revision = 0
    elif rust_update:
        revision = max(revisions) + 1
    else:
        revision = max(revisions)
    tag = target['go'] + (f'-android.{revision}' if revision else '')
    return dict(update=go_update or rust_update, go_update=go_update, rust_update=rust_update,
                go_tag=target['go'], rust_tag=target['rust'], tag=tag)


def github(path, missing_ok=False):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'AndroidLibClashLite'}
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise


def latest_stable(repository):
    releases = []
    page = 1
    while True:
        batch = github(f'repos/{repository}/releases?per_page=100&page={page}')
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return select_stable(releases)


def tag_commit(repository, tag):
    # Annotated release tags point to a tag object, not directly to a commit.
    obj = github(f'repos/{repository}/git/ref/tags/{urllib.parse.quote(tag, safe="")}')['object']
    while obj['type'] == 'tag':
        obj = github(f'repos/{repository}/git/tags/{obj["sha"]}')['object']
    if obj['type'] != 'commit':
        raise ValueError('Release tag must resolve to a commit')
    return obj['sha']


def check(repo, repository=None):
    pin = json.loads((repo / 'rust/upstream.json').read_text())
    meow = pin['repository'].removeprefix('https://github.com/').removesuffix('.git')
    current = {
        'go': re.search(r'(?m)^\s*(?:require\s+)?' + re.escape(MODULE) + r'\s+(\S+)',
                        (repo / 'go/go.mod').read_text()).group(1),
        'rust': 'v' + pin['version'],
    }
    latest = {'go': latest_stable(UPSTREAM), 'rust': latest_stable(meow)}
    tags = subprocess.check_output(['git', 'tag', '--list'], cwd=repo, text=True).splitlines()
    plan = plan_update(current, latest, tags)
    release = github(f'repos/{repository}/releases/tags/{plan["tag"]}', missing_ok=True) if repository else None
    published = bool(release and not release['draft'])
    if plan['update'] and published:
        raise ValueError('Selected release is already published but core pins are older; reconcile manually')
    plan.update(build=not published, current=current, latest=latest,
                rust_revision=tag_commit(meow, plan['rust_tag']) if plan['rust_update'] else pin['revision'])
    return plan


def replace_setting(path, key, value):
    content, count = re.subn(r'(?m)^' + re.escape(key) + r'\s*=.*$',
                             f'{key} = {json.dumps(value)}', path.read_text(), count=1)
    if count != 1:
        raise ValueError(f'Missing {key} in {path}')
    path.write_text(content, encoding='utf-8')


def apply(repo, plan):
    if plan['go_update']:
        # Keep dependency upgrades scoped to Mihomo; go get also raises the Go
        # directive if the new core needs a newer toolchain. Generated CLI imports
        # are not present in this checkout, so do not blindly go mod tidy here.
        subprocess.run(['go', 'get', MODULE + '@' + plan['go_tag']], cwd=repo / 'go', check=True)
    if plan['rust_update']:
        from prepare_rust import prepare
        rust = repo / 'rust'
        pin_path = rust / 'upstream.json'
        pin = json.loads(pin_path.read_text())
        pin.update(version=plan['rust_tag'][1:], revision=plan['rust_revision'])
        pin_path.write_text(json.dumps(pin, indent=2) + '\n', encoding='utf-8')
        # A patch conflict aborts the job before committing or dispatching a build.
        upstream = prepare(root=repo)
        package = tomllib.loads((upstream / 'Cargo.toml').read_text())['workspace']['package']
        if package['version'] != pin['version']:
            raise ValueError('meow release tag and workspace version disagree')
        channel = tomllib.loads((upstream / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        replace_setting(rust / 'Cargo.toml', 'version', pin['version'] + '-android.1')
        replace_setting(rust / 'Cargo.toml', 'rust-version', package['rust-version'])
        replace_setting(rust / 'rust-toolchain.toml', 'channel', channel)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', help='Destination owner/repo, to skip already published releases')
    parser.add_argument('--apply', action='store_true', help='Apply core pins and patches; then run cargo check/test to refresh and validate Cargo.lock')
    parser.add_argument('--plan', type=Path, help='Write the checked plan here, or read it with --apply to use the exact checked versions')
    parser.add_argument('--output', help='Append build/update/tag outputs to a GitHub Actions output file')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    plan = json.loads(args.plan.read_text()) if args.apply and args.plan else check(repo, args.repository)
    print(json.dumps(plan))
    if args.plan and not args.apply:
        args.plan.write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    if args.apply:
        apply(repo, plan)
    if args.output:
        with open(args.output, 'a', encoding='utf-8') as output:
            for key, value in plan.items():
                if not isinstance(value, dict):
                    output.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')


if __name__ == '__main__':
    main()
