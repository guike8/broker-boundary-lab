#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only macOS application snapshot and comparison; Python standard library only."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
from typing import Any

FORMAT_VERSION = 1
DEFAULT_BUNDLE = "/Applications/ChatGPT.app"
MAX_OTHER_HASH_BYTES = 256 * 1024 * 1024
PLIST_KEYS = {
    "CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName",
    "CFBundleShortVersionString", "CFBundleVersion", "CFBundleExecutable",
    "LSMinimumSystemVersion", "LSUIElement", "LSBackgroundOnly",
    "CFBundleURLTypes", "CFBundleDocumentTypes", "NSExtension",
    "NSAppTransportSecurity", "NSAppleEventsUsageDescription",
    "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
    "NSBluetoothAlwaysUsageDescription", "NSBluetoothPeripheralUsageDescription",
    "NSDownloadsFolderUsageDescription", "NSDocumentsFolderUsageDescription",
    "NSDesktopFolderUsageDescription", "NSNetworkVolumesUsageDescription",
    "NSRemovableVolumesUsageDescription", "NSSystemAdministrationUsageDescription",
    "NSInputMonitoringUsageDescription", "NSScreenCaptureUsageDescription",
    "ElectronAsarIntegrity", "SUFeedURL", "SUPublicEDKey",
}
SIGNING_KEYS = {
    "Identifier", "Format", "CodeDirectory", "CDHash", "TeamIdentifier",
    "Runtime Version", "Signature", "Timestamp", "Sealed Resources",
}


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(x) for x in value]
    return value


def read_plist(path: Path) -> dict:
    with path.open("rb") as stream:
        data = plistlib.load(stream)
    if not isinstance(data, dict):
        raise ValueError("Expected a dictionary plist")
    return data


def parse_codesign_entitlements(payload: bytes) -> dict:
    """Decode XML/binary plists or modern codesign's indented entitlement tree."""
    start = payload.find(b"<?xml")
    if start < 0:
        start = payload.find(b"<plist")
    if start >= 0:
        return json_safe(plistlib.loads(payload[start:]))
    if payload.startswith(b"bplist"):
        return json_safe(plistlib.loads(payload))
    lines = []
    for line in payload.decode("utf-8", "strict").splitlines():
        if line.strip():
            lines.append((len(line) - len(line.lstrip("\t")), line.lstrip("\t")))

    def value_at(index: int, depth: int):
        if index >= len(lines) or lines[index][0] != depth:
            raise ValueError("Unexpected codesign entitlement indentation")
        _, text = lines[index]
        index += 1
        if text == "[Dict]":
            result = {}
            while index < len(lines) and lines[index][0] > depth:
                level, key = lines[index]
                if level != depth + 1 or not key.startswith("[Key] "):
                    raise ValueError("Unexpected codesign entitlement dictionary")
                index += 1
                if index >= len(lines) or lines[index] != (depth + 1, "[Value]"):
                    raise ValueError("Missing codesign entitlement value")
                result[key[6:]], index = value_at(index + 1, depth + 2)
            return result, index
        if text == "[Array]":
            result = []
            while index < len(lines) and lines[index][0] > depth:
                item, index = value_at(index, depth + 1)
                result.append(item)
            return result, index
        if text.startswith("[String] "):
            return text[9:], index
        if text == "[String]":
            return "", index
        if text.startswith("[Bool] "):
            if text[7:] not in ("true", "false"):
                raise ValueError("Unexpected codesign entitlement boolean")
            return text[7:] == "true", index
        if text.startswith("[Integer] "):
            return int(text[10:], 0), index
        # Preserve unfamiliar scalar types verbatim rather than infer a value.
        if text.startswith("["):
            return {"codesign_display_value": text}, index
        raise ValueError("Unrecognized codesign entitlement output")

    result, end = value_at(0, 0)
    if end != len(lines) or not isinstance(result, dict):
        raise ValueError("Incomplete codesign entitlement tree")
    return result


def run_codesign(path: Path) -> dict:
    """Extract signing declarations. This does not verify trust or runtime behavior."""
    command = shutil.which("codesign")
    if not command:
        return {"state": "unavailable", "error": "codesign is not installed"}
    result: dict[str, Any] = {"state": "observed", "verification_performed": False}
    try:
        display = subprocess.run(
            [command, "--display", "--verbose=4", str(path)],
            capture_output=True, timeout=15, check=False,
        )
        output = (display.stdout + display.stderr).decode("utf-8", "replace")
        result["metadata_exit_code"] = display.returncode
        fields: dict[str, Any] = {}
        authorities = []
        for line in output.splitlines():
            if line.startswith("Authority="):
                authorities.append(line.partition("=")[2])
            elif "=" in line:
                key, _, value = line.partition("=")
                if key in SIGNING_KEYS:
                    fields[key] = value
        if authorities:
            fields["Authority"] = authorities
        result["metadata"] = fields
        if display.returncode:
            result["metadata_error"] = output.strip()[:2000]
        entitlements = subprocess.run(
            [command, "--display", "--entitlements", "-", str(path)],
            capture_output=True, timeout=15, check=False,
        )
        result["entitlements_exit_code"] = entitlements.returncode
        payload = entitlements.stdout
        diagnostic = entitlements.stderr.decode("utf-8", "replace").strip()
        warnings = [line for line in diagnostic.splitlines() if not line.startswith("Executable=")]
        if warnings:
            result["entitlements_diagnostics"] = warnings
        if payload.strip():
            result["entitlements"] = parse_codesign_entitlements(payload)
        elif entitlements.returncode == 0 and not warnings:
            result["entitlements"] = {}
        else:
            result["entitlements"] = None
            result["entitlements_error"] = (
                diagnostic[:2000]
                or "Entitlements output could not be decoded"
            )
    except (OSError, subprocess.TimeoutExpired, plistlib.InvalidFileException, ValueError) as exc:
        result["state"] = "error"
        result["error"] = str(exc)
    return result


def sha256_file(path: Path) -> tuple[str, bool]:
    digest = hashlib.sha256()
    before = path.stat()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat()
    stable = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    )
    return digest.hexdigest(), stable


def in_bundle(path: Path, bundle: Path) -> bool:
    try:
        path.resolve().relative_to(bundle)
        return True
    except (ValueError, OSError):
        return False


def select_artifacts(bundle: Path) -> tuple[dict[Path, set[str]], list[str]]:
    selected: dict[Path, set[str]] = {}
    errors: list[str] = []

    def add(path: Path, kind: str):
        if path.is_file() and not path.is_symlink() and in_bundle(path, bundle):
            selected.setdefault(path, set()).add(kind)

    def scan_error(exc):
        errors.append(str(exc))

    for root, dirs, files in os.walk(bundle, followlinks=False, onerror=scan_error):
        base = Path(root)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(files):
            path = base / name
            rel = path.relative_to(bundle).as_posix()
            if name == "Info.plist":
                add(path, "bundle_plist")
                try:
                    info = read_plist(path)
                    executable = info.get("CFBundleExecutable")
                    if isinstance(executable, str) and "/" not in executable:
                        # Application/XPC executables and framework executables have
                        # different placement. Only existing, bundle-contained paths count.
                        add(base / "MacOS" / executable, "bundle_executable")
                        add(base.parent / executable, "framework_executable")
                except (OSError, ValueError, plistlib.InvalidFileException) as exc:
                    errors.append(f"{rel}: {exc}")
            elif name == "package.json":
                add(path, "package_manifest")
            elif name.endswith(".asar"):
                add(path, "asar_archive")
            elif name.endswith(".node"):
                if "/native/" in rel or "darwin" in rel or "/prebuilds/" not in rel:
                    add(path, "native_module")
            elif rel in {
                "Contents/Resources/cua_node/bin/node",
                "Contents/Resources/codex-cli/codex",
            }:
                add(path, "bundled_runtime")
    return selected, errors


def snapshot(bundle_path: str) -> dict:
    bundle = Path(bundle_path).expanduser().resolve(strict=True)
    if not bundle.is_dir() or bundle.suffix != ".app":
        raise ValueError("--bundle must name an existing .app directory")
    info = read_plist(bundle / "Contents/Info.plist")
    selected, errors = select_artifacts(bundle)
    artifacts: dict[str, dict] = {}
    for path in sorted(selected, key=lambda p: p.relative_to(bundle).as_posix()):
        rel = path.relative_to(bundle).as_posix()
        kinds = sorted(selected[path])
        entry: dict[str, Any] = {"evidence_type": "observed", "kinds": kinds}
        try:
            stat = path.stat()
            entry["size_bytes"] = stat.st_size
            entry["mode"] = oct(stat.st_mode & 0o777)
            # The ASAR and Codex CLI are primary release artifacts; always hash
            # them. Other huge framework/runtime binaries get signing metadata.
            is_primary = "asar_archive" in kinds or rel.endswith("/MacOS/codex")
            if stat.st_size <= MAX_OTHER_HASH_BYTES or is_primary:
                digest, stable = sha256_file(path)
                entry["sha256"] = digest if stable else None
                entry["hash_state"] = "complete" if stable else "changed_during_read"
            else:
                entry["sha256"] = None
                entry["hash_state"] = "skipped_size_limit"
            if "bundle_plist" in kinds:
                values = read_plist(path)
                entry["plist"] = json_safe({k: v for k, v in values.items() if k in PLIST_KEYS or k.startswith("NSPrivacy") or (k.startswith("NS") and k.endswith("UsageDescription"))})
            if "package_manifest" in kinds:
                with path.open(encoding="utf-8") as stream:
                    package = json.load(stream)
                keys = ("name", "version", "main", "type", "engines", "dependencies", "optionalDependencies")
                entry["package"] = {k: package[k] for k in keys if k in package}
            if any(k in kinds for k in ("bundle_executable", "framework_executable", "native_module", "bundled_runtime")):
                entry["signing"] = run_codesign(path)
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            entry["error"] = str(exc)
        artifacts[rel] = entry
    return {
        "format": "local-app-artifact-corpus", "format_version": FORMAT_VERSION,
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "bundle_path": str(bundle),
        "bundle": json_safe({k: info.get(k) for k in (
            "CFBundleIdentifier", "CFBundleName", "CFBundleShortVersionString", "CFBundleVersion"
        )}),
        "scope": {
            "inputs": "Application bundle files only; no user state, configuration, auth, or logs",
            "selection": "Info.plist, bundle executables, package.json, ASARs, macOS/native .node modules, selected runtimes",
            "symlinks": "Skipped; resolved inputs must remain inside the selected bundle",
            "other_hash_limit_bytes": MAX_OTHER_HASH_BYTES,
            "always_hashed": ["ASAR archives", "MacOS/codex executable"],
            "signature_verification": "Not performed; codesign metadata and entitlements are declarations",
            "runtime_behavior": "Not observed; the snapshot never launches application executables",
            "consistency": "Per-file hash stability checked; the whole bundle is not an atomic filesystem snapshot",
        },
        "artifact_count": len(artifacts), "artifacts": artifacts,
        "scan_errors": errors,
        "inferences": [],
    }


def load_manifest(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get("format") != "local-app-artifact-corpus" or data.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"{path}: unsupported manifest format/version")
    if not isinstance(data.get("artifacts"), dict):
        raise ValueError(f"{path}: artifacts must be an object")
    return data


def diff_values(old: Any, new: Any, prefix: str = "") -> list[dict]:
    if isinstance(old, dict) and isinstance(new, dict):
        changes = []
        for key in sorted(old.keys() | new.keys()):
            name = f"{prefix}.{key}" if prefix else key
            if key not in old:
                changes.append({"field": name, "change": "added", "after": new[key]})
            elif key not in new:
                changes.append({"field": name, "change": "removed", "before": old[key]})
            else:
                changes.extend(diff_values(old[key], new[key], name))
        return changes
    if old != new:
        return [{"field": prefix, "change": "changed", "before": old, "after": new}]
    return []


def compare(old: dict, new: dict) -> dict:
    old_files, new_files = old["artifacts"], new["artifacts"]
    changed = []
    for path in sorted(old_files.keys() & new_files.keys()):
        fields = diff_values(old_files[path], new_files[path])
        if fields:
            changed.append({"path": path, "fields": fields})
    return {
        "format": "local-app-artifact-diff", "format_version": FORMAT_VERSION,
        "compared_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidence_type": "observed_manifest_differences",
        "before_captured_at": old.get("captured_at_utc"),
        "after_captured_at": new.get("captured_at_utc"),
        "bundle_changes": diff_values(old.get("bundle", {}), new.get("bundle", {})),
        "scope_changes": diff_values(old.get("scope", {}), new.get("scope", {})),
        "added": sorted(new_files.keys() - old_files.keys()),
        "removed": sorted(old_files.keys() - new_files.keys()),
        "changed": changed,
        "limitations": [
            "An artifact or entitlement change does not establish a vulnerability or changed runtime behavior.",
            "Only selected artifacts are covered; unchanged hashes do not describe remote configuration or services.",
            "Signing metadata was extracted, not independently verified.",
            "Matching null/skipped hashes do not establish identical binary content.",
        ],
    }


def render_diff(result: dict) -> str:
    lines = ["# Application artifact comparison", "", "Observed differences between two local snapshots.", ""]
    for label, changes in (("Bundle metadata", result["bundle_changes"]), ("Collection scope", result["scope_changes"])):
        if changes:
            lines.extend([f"## {label}", ""])
            for change in changes:
                lines.append(f"- `{change['field']}`: {json.dumps(change.get('before'), ensure_ascii=False)} → {json.dumps(change.get('after'), ensure_ascii=False)}")
            lines.append("")
    lines.extend([f"Added: {len(result['added'])}; removed: {len(result['removed'])}; changed: {len(result['changed'])}.", ""])
    for label, paths in (("Added artifacts", result["added"]), ("Removed artifacts", result["removed"])):
        if paths:
            lines.extend([f"## {label}", ""] + [f"- `{p}`" for p in paths] + [""])
    if result["changed"]:
        lines.extend(["## Changed artifacts", ""])
        for entry in result["changed"]:
            lines.append(f"- `{entry['path']}`")
            for change in entry["fields"]:
                lines.append(f"  - `{change['field']}`: {json.dumps(change.get('before'), ensure_ascii=False)} → {json.dumps(change.get('after'), ensure_ascii=False)}")
        lines.append("")
    lines.extend(["## Interpretation limits", ""] + [f"- {x}" for x in result["limitations"]] + [""])
    return "\n".join(lines)


def write_output(path: str | None, content: str):
    if path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    else:
        print(content, end="" if content.endswith("\n") else "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("snapshot", help="Read selected app artifacts into a JSON manifest")
    capture.add_argument("--bundle", default=DEFAULT_BUNDLE)
    capture.add_argument("--output", "-o")
    diff = subparsers.add_parser("compare", help="Compare two JSON snapshot manifests")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--output", "-o")
    diff.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of Markdown")
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            result = snapshot(args.bundle)
            content = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        else:
            result = compare(load_manifest(args.before), load_manifest(args.after))
            content = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n" if args.json else render_diff(result)
        write_output(args.output, content)
        return 0
    except (OSError, ValueError) as exc:
        print(f"artifact_corpus: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
