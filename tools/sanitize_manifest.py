#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create a publication copy of an artifact manifest without machine-local paths."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HOME_PATH = re.compile(r"(?:/Users/|/home/)[^\s\"'<>]+|[A-Za-z]:\\Users\\[^\s\"'<>]+")


def sanitize_manifest(data: dict) -> dict:
    if data.get('format') != 'local-app-artifact-corpus' or data.get('format_version') != 1:
        raise ValueError('Unsupported artifact manifest format')
    bundle_path = data.get('bundle_path')
    if not isinstance(bundle_path, str) or not bundle_path:
        raise ValueError('Manifest lacks its source bundle path')

    def visit(value):
        if isinstance(value, dict):
            if any(HOME_PATH.search(str(k)) or bundle_path in str(k) for k in value):
                raise ValueError('Machine-local paths in object keys require manual review')
            return {str(k): visit(v) for k, v in value.items()}
        if isinstance(value, list):
            return [visit(v) for v in value]
        if isinstance(value, str):
            # Preserve relative artifact identity while removing installation and
            # home paths from metadata and tool diagnostics.
            return HOME_PATH.sub('<LOCAL_PATH>', value.replace(bundle_path, '<BUNDLE>'))
        return value

    result = visit(data)
    result['publication'] = {
        'state': 'sanitized_static_artifact_facts',
        'changes': ['Installation path replaced with <BUNDLE>', 'Machine-local home paths removed if present'],
        'content': 'Static metadata and digests only; no application bytes, user state, or credentials',
        'limitations': ['Automated path removal does not replace reviewing the publication diff', 'A sanitized metadata manifest does not license the inspected application'],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input')
    parser.add_argument('--output', '-o', required=True)
    args = parser.parse_args()
    try:
        source = Path(args.input)
        dest = Path(args.output)
        if source.resolve() == dest.resolve():
            raise ValueError('Publication copy must differ from input')
        raw = source.read_bytes()
        result = sanitize_manifest(json.loads(raw))
        result['publication']['source_manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)+'\n', encoding='utf-8')
        print(f'Sanitized {result.get("artifact_count", 0)} artifact records')
        return 0
    except (OSError, ValueError) as exc:
        print(f'sanitize_manifest: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
