"""Check published Mihomo stable tags; optionally update the pinned Go module."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
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


def plan_update(current, latest, published):
    if version(latest) < version(current):
        return dict(update=False, build=False, tag='')
    update = version(latest) > version(current)
    if update and published:
        raise ValueError('Latest release is already published but go.mod is older; reconcile manually')
    return dict(update=update, build=not published, tag=latest if not published else '')


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', help='Destination owner/repo, to skip already published releases')
    parser.add_argument('--apply', action='store_true', help='Update go.mod/go.sum when a newer stable tag exists')
    parser.add_argument('--output', help='Append build/update/tag outputs to a GitHub Actions output file')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    current = re.search(r'(?m)^\s*' + re.escape(MODULE) + r'\s+(\S+)',
                        (repo / 'go.mod').read_text()).group(1)
    releases = []
    page = 1
    while True:
        batch = github(f'repos/{UPSTREAM}/releases?per_page=100&page={page}')
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    latest = select_stable(releases)
    release = github(f'repos/{args.repository}/releases/tags/{latest}', missing_ok=True) if args.repository else None
    published = bool(release and not release['draft'])
    plan = plan_update(current, latest, published)
    print(json.dumps(dict(current=current, latest=latest, **plan)))
    if args.apply and plan['update']:
        # Keep dependency upgrades scoped to Mihomo; go get also raises the Go
        # directive if the new core needs a newer toolchain. Generated CLI imports
        # are not present in this checkout, so do not blindly go mod tidy here.
        subprocess.run(['go', 'get', MODULE + '@' + latest], cwd=repo, check=True)
    if args.output:
        with open(args.output, 'a', encoding='utf-8') as output:
            for key, value in plan.items():
                output.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')


if __name__ == '__main__':
    main()
