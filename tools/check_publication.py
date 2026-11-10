#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check a publication tree for local data, credentials, binaries, and extracted app code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

MAX_TEXT_BYTES = 5 * 1024 * 1024
BLOCKED_SUFFIXES = {'.asar', '.node', '.dylib', '.dll', '.exe', '.sqlite', '.sqlite3', '.db', '.har', '.saz', '.pcap', '.pcapng', '.pem', '.p12', '.pfx', '.key'}
BLOCKED_NAMES = {'auth.json', 'config.toml', '.codex-global-state.json', 'history.jsonl', '.env', 'app.asar', 'preload.js', 'sandbox-preload.js', 'early-bootstrap.js'}
BLOCKED_DIRECTORIES = {'shipped-js', 'app.asar.unpacked', 'node_modules', 'raw', 'captures', 'credentials', 'local', 'work', 'private'}
PATTERNS = {
    'absolute home path': re.compile(r'(?:/Users/|/home/)[A-Za-z0-9_.-]+(?:/|\\)|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\'),
    'GitHub credential': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'API credential': re.compile(r'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'bearer credential': re.compile(r'(?i)\bBearer\s+[A-Za-z0-9_.~+/-]{24,}={0,2}'),
    'credential literal': re.compile(r'''(?ix)["'](?:access_token|refresh_token|client_secret|api_key|password)["']\s*:\s*["'][A-Za-z0-9_./+~=-]{16,}["']'''),
    'JWT': re.compile(r'\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b'),
}
BIN_MAGIC = (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'MZ', b'SQLite format 3\x00')


def files_to_scan(root: Path, tracked: bool):
    if tracked:
        command = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True, check=False)
        if command.returncode:
            raise ValueError('--tracked requires a Git repository')
        return [root / name.decode('utf-8') for name in command.stdout.split(b'\0') if name]
    # Interpreter caches are ignored build products. If explicitly tracked,
    # --tracked still scans and rejects their binary content.
    return [p for p in root.rglob('*') if p.is_file() and not ({'.git','__pycache__'} & set(p.relative_to(root).parts))]


def scan_file(path: Path, root: Path) -> list[dict]:
    relative = path.relative_to(root)
    issues = []
    if path.is_symlink():
        return [{'path': relative.as_posix(), 'reason': 'symlink requires explicit publication review'}]
    if path.suffix.lower() in BLOCKED_SUFFIXES or path.name in BLOCKED_NAMES or any(part in BLOCKED_DIRECTORIES or part.endswith('.app') for part in relative.parts):
        issues.append({'path': relative.as_posix(), 'reason': 'raw application, capture, configuration, or user-state path'})
    raw = path.read_bytes()
    if len(raw) > MAX_TEXT_BYTES:
        issues.append({'path': relative.as_posix(), 'reason': 'large file requires explicit review'})
        return issues
    if raw.startswith(BIN_MAGIC) or b'\0' in raw[:8192]:
        issues.append({'path': relative.as_posix(), 'reason': 'binary payload'})
        return issues
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return issues + [{'path': relative.as_posix(), 'reason': 'non-UTF-8 payload'}]
    for name, pattern in PATTERNS.items():
        match = pattern.search(text)
        if match:
            issues.append({'path': relative.as_posix(), 'reason': name, 'line': text.count('\n', 0, match.start())+1})
    if max((len(line) for line in text.splitlines()), default=0) > 12000:
        issues.append({'path': relative.as_posix(), 'reason': 'long minified line may contain extracted bundle code'})
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--tracked', action='store_true', help='Inspect Git-tracked publication files only')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        root = Path(args.root).resolve(strict=True)
        files = files_to_scan(root, args.tracked)
        issues = [issue for path in files for issue in scan_file(path, root)]
        result = {'files_checked': len(files), 'issues': issues, 'passed': not issues, 'limitations': 'Heuristic scan; review the actual Git diff before publishing'}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f'Publication check: {len(files)} files, {len(issues)} issues')
            for issue in issues:
                print(f'{issue["path"]}:{issue.get("line", "-")}: {issue["reason"]}')
        return 1 if issues else 0
    except (OSError, ValueError) as exc:
        print(f'check_publication: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
