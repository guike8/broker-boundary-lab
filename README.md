# Broker Boundary Lab

Reproducible inspection tools and evidence for task, account, and permission-lifetime boundaries in agent desktop software. The first target is the installed macOS Codex distribution.

The repository contains original audit tooling, synthetic tests, static artifact facts, and pinned source references. It does not distribute the inspected application, extracted proprietary source, credentials, conversation records, or a client for reaching the live desktop broker.

No sandbox escape or cross-account access has been demonstrated by the initial artifact investigation. Static observations and isolated tests are labeled separately from behavior of a running product. Broker audit results should retain those distinctions.

The broker audit exercises selected functions extracted from the locally installed build, with synthetic surrounding services. See [the audit findings](docs/BROKER_AUDIT.md) and [machine-readable scenarios](results/isolated-scenarios.json). The application code is extracted by each researcher into scratch space and is not redistributed here.

## Included tools

- `tools/artifact_corpus.py`: collect selected application-bundle metadata, hashes, signing declarations, and entitlements; compare two snapshots.
- `tools/sanitize_manifest.py`: produce a publication copy with the installation path replaced by `<BUNDLE>` and machine-local home paths removed.
- `tools/check_publication.py`: check a publication tree for credential patterns, home paths, user state, binary payloads, and extracted application artifacts.
- `baselines/`: sanitized static metadata for the investigated build.
- `docs/evidence.schema.json`: a common format for an evidence-backed observation.
- `tools/extract-audit-target.mjs`: extract the reviewed broker methods from a local ASAR using the included build adapter.
- `tools/audit-local-methods.mjs`: run account, executor, cancellation, response-correlation, and renderer-lifecycle scenarios against those exact methods.
- `adapters/`: artifact and method fingerprints for the reviewed build, without source snippets.

Python 3.10 or later is sufficient for these tools. Snapshot collection requires macOS and uses the system `codesign` command. Comparison, sanitization, publication checking, and synthetic tests use only the Python standard library and run without the target application.

## Reproduce the artifact baseline

Run from the repository root:

```sh
python3 tools/artifact_corpus.py snapshot \
  --bundle /Applications/ChatGPT.app \
  --output local/current-build.json

python3 tools/sanitize_manifest.py local/current-build.json \
  --output baselines/current-build.json

python3 tools/check_publication.py . --tracked
```

Run the check after staging the files intended for publication. `--tracked` checks exactly the tracked publication files. A full tree check also includes untracked files and intentionally rejects the ignored `local/` directory:

```sh
python3 tools/check_publication.py .
```

Review the actual publication diff as well. The checker uses heuristics and is not a proof that every sensitive value was removed.

## Compare releases

```sh
python3 tools/artifact_corpus.py compare \
  baselines/codex-macos-26.1103.60933-25894.json \
  baselines/current-build.json \
  --json --output local/release-diff.json
```

The included baseline covers 137 selected artifacts. The ASAR and CLI are hashed in full; one large framework hash is explicitly skipped. Signing metadata and entitlements are declarations, not verification of authenticity or runtime enforcement. The collector does not launch the application, read user configuration, or inspect conversation databases. A changed hash is an investigation lead rather than evidence of a vulnerability.

## Run synthetic tests

```sh
python3 -m unittest discover -s tests -v
```

Tests use generated temporary fixtures. A harness that exercises a recovered function must identify the exact artifact digest and state which dependencies are mocked. A model of a rule is not evidence that the shipped implementation enforces it.

## Reproduce the local broker scenarios

Use Node.js `^22.18.0 || >=24.11.0`. Install the pinned parser dependency:

```sh
npm ci --ignore-scripts
audit_scratch="$(mktemp -d)"
node tools/extract-audit-target.mjs \
  --asar /Applications/ChatGPT.app/Contents/Resources/app.asar \
  --out "$audit_scratch/methods.json"
node tools/extract-local-functions.mjs \
  --file /Applications/ChatGPT.app/Contents/Resources/plugins/openai-bundled/plugins/browser/scripts/browser-service.mjs \
  --function Y6 --function wce \
  --out "$audit_scratch/browser-functions.json"
node tools/audit-local-methods.mjs \
  --input "$audit_scratch/methods.json" \
  --input "$audit_scratch/browser-functions.json" \
  --out "$audit_scratch/results.json"
```

The adapter supports the exact artifact identified in the findings. A different release requires reviewing dependencies and adding new fingerprints. Extraction records archive and member hashes; the harness checks reviewed snippet fingerprints before evaluating a method. These are consistency checks, not vendor signature verification.

The extractor parses inert source and does not run application bootstrap. The harness then invokes selected methods with mocked services, synthetic accounts/tasks, and no live broker connection. Node's `vm` module isolates dependency bindings for this experiment; it is not a security sandbox. Use trusted local extraction inputs. Keep the extracted files outside the repository.

The checked-in result contains 65 passing scenarios, including explicitly labeled scope observations and one mutation-sensitivity control. Browser receipt cases use real Ed25519 cryptography with synthetic keys and transport. A passing scope observation records behavior; it is not a claim that a security invariant holds.

## Evidence and provenance

The investigated macOS app declares bundle identifier `com.openai.codex`, app version `26.1103.60933`, build `25894`, and CLI version `0.167.0-alpha.3.2`. The filename of the installed app is not its security identity.

The matching public CLI tag is `rust-v0.167.0-alpha.3.2`, resolving to commit [`c40729ea5cf8e947481b130c59807273eda2f8e9`](https://github.com/openai/codex/tree/c40729ea5cf8e947481b130c59807273eda2f8e9). A matching version string does not prove byte-for-byte build equivalence. Public CLI source and proprietary desktop JavaScript are separate evidence sources.

See [provenance conventions](docs/PROVENANCE.md) for recording observations and limitations. Source changes, runtime traces, and test failures should remain tied to the particular version they establish.

## License

Original code and original documentation in this repository are MIT licensed. The license grants no rights to third-party applications, logos, binaries, or extracted code. Upstream Codex source remains upstream under its own license. See [NOTICE](NOTICE).

This is an independent research project and is not affiliated with or endorsed by OpenAI.
