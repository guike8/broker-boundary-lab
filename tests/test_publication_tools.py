# SPDX-License-Identifier: MIT
"""Synthetic regression checks for publication boundaries and snapshot comparison."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/f'{name}.py')
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


checker = module('check_publication')
sanitizer = module('sanitize_manifest')
corpus = module('artifact_corpus')


class PublicationTools(unittest.TestCase):
    def test_sanitizer_preserves_artifact_identity_and_removes_paths(self):
        installation = '/Applications/Fixture.app'
        local = '/' + 'Users/' + 'synthetic-owner/project'
        raw = {'format':'local-app-artifact-corpus', 'format_version':1, 'bundle_path':installation,
               'artifact_count':1, 'artifacts':{'Contents/MacOS/Fixture':{'sha256':'a'*64, 'diagnostic':installation+'/Contents/MacOS/Fixture failed at '+local}}}
        result = sanitizer.sanitize_manifest(raw)
        artifact = result['artifacts']['Contents/MacOS/Fixture']
        self.assertEqual(artifact['sha256'], 'a'*64)
        self.assertEqual(result['bundle_path'], '<BUNDLE>')
        self.assertNotIn(local, artifact['diagnostic'])
        self.assertNotIn(installation, artifact['diagnostic'])
        self.assertEqual(raw['bundle_path'], installation)

    def test_sanitizer_rejects_unknown_input_format(self):
        with self.assertRaises(ValueError):
            sanitizer.sanitize_manifest({'format':'conversation-export'})

    def test_checker_rejects_local_path_and_credential_without_echoing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root/'notes.txt'
            secret = 'ghp_'+'A'*40
            file.write_text('/'+'Users/'+'synthetic-owner/private '+secret)
            issues = checker.scan_file(file, root)
            self.assertEqual({i['reason'] for i in issues}, {'absolute home path','GitHub credential'})
            self.assertNotIn(secret, str(issues))

    def test_checker_rejects_binary_and_user_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root/'auth.json'
            file.write_bytes(b'\x7fELF\x00synthetic')
            reasons = {i['reason'] for i in checker.scan_file(file, root)}
            self.assertIn('binary payload', reasons)
            self.assertIn('raw application, capture, configuration, or user-state path', reasons)

    def test_comparator_detects_entitlement_change_and_added_removed_artifacts(self):
        old = {'artifacts':{'old':{},'stable':{'sha256':'a','signing':{'entitlements':{'app-sandbox':True}}}},'bundle':{'version':'1'}}
        new = {'artifacts':{'new':{},'stable':{'sha256':'b','signing':{'entitlements':{'app-sandbox':False}}}},'bundle':{'version':'2'}}
        result = corpus.compare(old,new)
        self.assertEqual(result['added'], ['new'])
        self.assertEqual(result['removed'], ['old'])
        self.assertEqual({x['field'] for x in result['changed'][0]['fields']}, {'sha256','signing.entitlements.app-sandbox'})
        self.assertEqual(result['bundle_changes'][0]['after'], '2')
        self.assertEqual(corpus.compare(old,old)['changed'], [])

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the extractor path guard')
    def test_extractor_rejects_direct_and_symlinked_repository_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            scratch = Path(temp)
            link = scratch/'publication-link'
            try:
                link.symlink_to(ROOT, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f'Directory symlinks unavailable: {exc}')
            command = [shutil.which('node'), str(ROOT/'tools/extract-local-methods.mjs'), '--asar', str(scratch/'absent.asar'), '--out']
            direct = subprocess.run(command+[str(ROOT/'guard-test-must-not-exist.json')], capture_output=True, text=True)
            indirect = subprocess.run(command+[str(link/'guard-test-must-not-exist.json')], capture_output=True, text=True)
            self.assertEqual(direct.returncode, 1)
            self.assertIn('outside this repository', direct.stderr)
            self.assertEqual(indirect.returncode, 1)
            self.assertIn('parent resolves inside this repository', indirect.stderr)
            self.assertFalse((ROOT/'guard-test-must-not-exist.json').exists())


if __name__ == '__main__':
    unittest.main()
