# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: LGPL-3.0

"""Offline regression tests for the shared core updater."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import check_upstream as updater


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        (self.repo / 'go').mkdir()
        (self.repo / 'rust').mkdir()
        (self.repo / 'go/go.mod').write_text('module cfa\nrequire github.com/metacubex/mihomo v1.19.33\n')
        (self.repo / 'rust/upstream.json').write_text(json.dumps({
            'repository': 'https://github.com/meow-rs/meow-rs',
            'version': '0.26.0', 'revision': 'a' * 40,
        }))
        (self.repo / 'rust/Cargo.toml').write_text('[package]\nname = "libclash-rs"\nversion = "0.26.0-android.2"\nrust-version = "1.89"\n')
        (self.repo / 'rust/rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.98.1"\ncomponents = ["rustfmt"]\n')
        self.current = {'go': 'v1.19.33', 'rust': 'v0.26.0'}

    def test_stable_releases_are_numeric_and_exclude_previews(self):
        releases = [{'tag_name': tag} for tag in ['v0.9.0', 'v0.10.0', 'v0.11.0-rc.1', 'Prerelease-Alpha', 'v01.0.0']]
        releases += [{'tag_name': 'v0.12.0', 'prerelease': True}, {'tag_name': 'v0.13.0', 'draft': True}]
        self.assertEqual(updater.select_stable(releases), 'v0.10.0')

    def test_go_or_both_updates_use_new_go_tag(self):
        for rust in ['v0.26.0', 'v0.28.0']:
            plan = updater.plan_update(self.current, {'go': 'v1.19.34', 'rust': rust}, ['v1.19.33-android.4'])
            self.assertEqual(plan['tag'], 'v1.19.34')
            self.assertTrue(plan['go_update'])
            self.assertEqual(plan['rust_update'], rust == 'v0.28.0')

    def test_rust_only_update_increments_highest_revision(self):
        tags = ['v1.19.33', 'v1.19.33-android.9', 'v1.19.33-android.10', 'meow-v0.28.0', 'v1.19.34-android.99']
        plan = updater.plan_update(self.current, {'go': 'v1.19.33', 'rust': 'v0.28.0'}, tags)
        self.assertEqual(plan['tag'], 'v1.19.33-android.11')
        self.assertFalse(plan['go_update'])
        self.assertTrue(plan['rust_update'])

    def test_initial_release_does_not_require_a_core_update(self):
        plan = updater.plan_update(self.current, self.current, [])
        self.assertEqual(plan['tag'], 'v1.19.33')
        self.assertFalse(plan['update'])

    def test_no_downgrade_and_retry_keeps_existing_wrapper_tag(self):
        plan = updater.plan_update(self.current, {'go': 'v1.19.32', 'rust': 'v0.25.0'}, ['v1.19.33', 'v1.19.33-android.3'])
        self.assertEqual(plan['tag'], 'v1.19.33-android.3')
        self.assertEqual(plan['go_tag'], self.current['go'])
        self.assertEqual(plan['rust_tag'], self.current['rust'])
        self.assertFalse(plan['update'])

    def test_published_release_skips_and_draft_retries(self):
        for draft, build in [(False, False), (True, True), (None, True)]:
            release = None if draft is None else {'draft': draft}
            with patch.object(updater, 'latest_stable', side_effect=self.current.values()), \
                 patch.object(updater.subprocess, 'check_output', return_value='v1.19.33\nv1.19.33-android.2\n'), \
                 patch.object(updater, 'github', return_value=release) as api, \
                 patch.object(updater, 'tag_commit') as commit:
                plan = updater.check(self.repo, 'owner/repo')
            self.assertEqual(plan['build'], build)
            self.assertFalse(plan['update'])
            self.assertEqual(plan['tag'], 'v1.19.33-android.2')
            api.assert_called_once_with('repos/owner/repo/releases/tags/v1.19.33-android.2', missing_ok=True)
            commit.assert_not_called()

    def test_published_new_go_tag_requires_reconciliation(self):
        with patch.object(updater, 'latest_stable', side_effect=['v1.19.34', 'v0.26.0']), \
             patch.object(updater.subprocess, 'check_output', return_value='v1.19.34\n'), \
             patch.object(updater, 'github', return_value={'draft': False}):
            with self.assertRaisesRegex(ValueError, 'already published'):
                updater.check(self.repo, 'owner/repo')

    def test_tag_commit_peels_annotated_and_lightweight_tags(self):
        commit = {'object': {'type': 'commit', 'sha': 'c' * 40}}
        for responses in [[commit], [{'object': {'type': 'tag', 'sha': 'b' * 40}}, commit]]:
            with patch.object(updater, 'github', side_effect=responses):
                self.assertEqual(updater.tag_commit('meow-rs/meow-rs', 'v0.28.0'), 'c' * 40)

    def test_apply_updates_rust_manifests_and_preserves_components(self):
        upstream = self.repo / 'upstream'
        upstream.mkdir()
        (upstream / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.28.0"\nrust-version = "1.90"\n')
        (upstream / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.99.0"\n')
        plan = dict(go_update=False, rust_update=True, rust_tag='v0.28.0', rust_revision='c' * 40)
        with patch('prepare_rust.prepare', return_value=upstream) as prepare, patch.object(updater.subprocess, 'run') as run:
            updater.apply(self.repo, plan)
        prepare.assert_called_once_with(root=self.repo)
        run.assert_not_called()
        pin = json.loads((self.repo / 'rust/upstream.json').read_text())
        self.assertEqual((pin['version'], pin['revision']), ('0.28.0', 'c' * 40))
        package = tomllib.loads((self.repo / 'rust/Cargo.toml').read_text())['package']
        self.assertEqual((package['version'], package['rust-version']), ('0.28.0-android.1', '1.90'))
        toolchain = tomllib.loads((self.repo / 'rust/rust-toolchain.toml').read_text())['toolchain']
        self.assertEqual(toolchain, {'channel': '1.99.0', 'components': ['rustfmt']})

    def test_patch_failure_aborts_apply(self):
        plan = dict(go_update=False, rust_update=True, rust_tag='v0.28.0', rust_revision='c' * 40)
        with patch('prepare_rust.prepare', side_effect=subprocess.CalledProcessError(1, ['git', 'apply'])), \
             self.assertRaises(subprocess.CalledProcessError):
            updater.apply(self.repo, plan)
        self.assertIn('0.26.0-android.2', (self.repo / 'rust/Cargo.toml').read_text())

    def test_apply_uses_saved_plan_without_rechecking_releases(self):
        plan = dict(update=True, go_update=False, rust_update=True, rust_tag='v0.28.0', rust_revision='c' * 40)
        path = self.repo / 'plan.json'
        path.write_text(json.dumps(plan))
        with patch.object(updater, '__file__', str(self.repo / 'scripts/check_upstream.py')), \
             patch('sys.argv', ['check_upstream.py', '--apply', '--plan', str(path)]), \
             patch.object(updater, 'check', side_effect=AssertionError('must not recheck')), \
             patch.object(updater, 'apply') as apply, contextlib.redirect_stdout(io.StringIO()):
            updater.main()
        apply.assert_called_once_with(self.repo, plan)


if __name__ == '__main__':
    unittest.main()
