# Browser proof component integration

Seven cases passed using selected installed production components, a synthetic policy authority, real local framed sockets, real Ed25519 signatures, real `AsyncLocalStorage`, and a disposable Chromium canary page. This is **production-component integration**, not a full Codex desktop end-to-end test.

## Observed results

| Transition | Observed behavior |
| --- | --- |
| Mutate the caller's original metadata object | The worker's cloned metadata retained task A and was deeply frozen. |
| Warm proof, then revoke the synthetic authority within the same turn | A second command with a new execution ID reused the cached proof and clicked the canary. |
| Start the next turn after that revocation | A fresh proof was requested and denied; no additional canary click. |
| Revoke before a pending authority decision completes | The producer returned denial and no canary click occurred. |
| Abort the executor lifetime during that pending decision | The selected producer method returned denial and no click occurred. |
| Revoke after an allow response was signed but before delivery | That already-signed response was accepted and the canary clicked. |
| Force active context B while A's allow proof is held | A retained its originating async-local store, saw no current metadata, and the native current-context check rejected A. It never inherited B's metadata. The command wrapper could still continue to our deliberately unguarded canary adapter. |
| Start a fresh proof from a retired context | The proof helper rejected missing current-turn metadata. |

The first revocation and next-turn observations are one combined case, giving seven cases total. Concrete counters and ordered events are in [the results](../results/browser-component-integration.json).

## Correction to the earlier model

The earlier isolated helper fixture mutated one shared metadata object. Inspection of JavaScript embedded in the native `node_repl` executable revealed a stronger mechanism: state creation clones and deeply freezes request metadata; execution state is async-local; the metadata getter returns null for an execution that is no longer active; privileged current-context access rejects retired work. The follow-up executes these selected definitions with the real Node `AsyncLocalStorage` implementation.

The previous fixture remains a counterfactual helper sensitivity test, not evidence that task A can start reading task B's metadata. Normal execution messages are also serialized by the inspected worker source. The forced-switch test deliberately activates B while A is pending to exercise retirement; it does not establish that normal commands can reach that concurrency pattern.

## Components and substitutions

The selected installed code is the browser metadata reader, proof-cache factory, signature verifier, command guard wrapper, executor browser-access method, and worker context/state/metadata definitions. Every definition is matched to a reviewed source and snippet hash before execution. Source extracts stay outside the repository.

The lab supplies policy storage, signing authority, socket adapters, and a canary command adapter. Real cryptography and length-prefixed socket requests carry the proof to the selected verifier. The selected command wrapper awaits that proof before our adapter operates an anonymous browser context. HTTP request counts and DOM state confirm the canary clicks.

The canary adapter deliberately does not add a native privileged-operation guard. For late A, the actual `getCurrent` decision is recorded separately and rejects the retired context. A click in this adapter proves wrapper continuation only. It does not prove that Codex's real downstream browser path would perform that action.

Synthetic revocation changes the lab authority's decision. It does not reproduce the desktop settings UI, remote policy propagation, executor restart, child-process termination, native peer authorization, or all downstream checks. A previously signed response has no synthetic revocation channel in this lab. No real account, live desktop broker, existing browser profile, or cloud service was used.

## Why no second GUI profile

The inspected app supports separate user-data paths, but some fallback paths still reference the current OS user's cross-instance locks, notification group-container resources, workspace defaults, and skill directories. The same signed app identity also retains OS-level identity and consent context. A second UI profile is therefore not verified no-touch isolation. A full settings-revocation test should use a disposable OS account or VM with its own browser and test account.

## Reproduce

Install the pinned dependencies from the repository root, then choose scratch storage outside the repository:

```sh
npm ci --ignore-scripts
audit_scratch="$(mktemp -d)"
export PLAYWRIGHT_BROWSERS_PATH="$audit_scratch/browsers"
node node_modules/playwright-core/cli.js install chromium-headless-shell

node tools/extract-audit-target.mjs \
  --asar /Applications/ChatGPT.app/Contents/Resources/app.asar \
  --out "$audit_scratch/host-methods.json"
node tools/extract-local-functions.mjs \
  --file /Applications/ChatGPT.app/Contents/Resources/plugins/openai-bundled/plugins/browser/scripts/browser-service.mjs \
  --function Y6 --function wce --function Ne --method executeAgentCommand \
  --out "$audit_scratch/browser.json"
node tools/extract-worker-context.mjs \
  --binary /Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl \
  --out "$audit_scratch/context.json"
node tools/test-browser-components.mjs \
  --input "$audit_scratch/browser.json" \
  --input "$audit_scratch/context.json" \
  --input "$audit_scratch/host-methods.json" \
  --out "$audit_scratch/results.json"
```

The adapter is specific to app `26.1103.60933`, build `25894`. The observed browser version was `145.0.7632.6`. Chromium sandboxing remains enabled. Browser contexts, listeners, sockets, and lab scratch directories are closed or removed after the run. The browser download remains in the caller-selected scratch location until the caller removes it.

The full GUI lifecycle and native binary bootstrap were not executed. No exploitable task/account crossing or full-product permission-revocation bypass is established by these results.
