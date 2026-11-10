# Codex broker task and permission boundaries

The inspected build contains explicit checks for account lifetime, executor identity, interactive manager ownership, request correlation, cancellation, and turn state. The local scenarios exercise those checks with synthetic dependencies. No live cross-account access, unauthorized task action, or expired-permission bypass was demonstrated.

Target: macOS app `26.1103.60933`, build `25894`, bundled CLI `0.167.0-alpha.3.2`. The ASAR SHA-256 is `a77588b2dcfa9b394d722dd8c2c8b13d3a09bacd49c839cc715245742dba6048`. Public source comparison uses commit [`c40729ea5cf8e947481b130c59807273eda2f8e9`](https://github.com/openai/codex/tree/c40729ea5cf8e947481b130c59807273eda2f8e9). Version matching does not establish exact binary/source equivalence.

## Account and task transitions

The shipped native-thread read method captures authentication and catalog generations. It checks the selected executor before work, carries a lifetime assertion into asynchronous operations, and compares account/user identity and executor again before returning. The isolated scenarios reject synthetic account, user, executor, auth-generation, catalog-generation, and disposal changes while an awaited response is pending.

The interactive host-manager path requires an existing conversation owned by the attached manager, rejects follower execution and duplicate request IDs, and cancels pending work when its signal aborts or the manager retires. The response router separates numeric and string IDs, rejects duplicate pending IDs, and does not resolve unknown or repeated responses. The schema-rejection scenario uses a mocked validator and tests rejection propagation only.

The renderer dispatcher checks message-client identity and realtime-delegation host/thread identity. It records a deduplication claim containing call, host, thread, and turn IDs. After loading the implementation, it re-reads the turn and rejects a completed turn for dynamic transport. Deduplication is not itself authorization.

Reading another native thread in the same synthetic account/executor is accepted by the isolated read method. A target thread ID is a selector here; the method does not establish caller-thread ancestry. Cross-chat reading can be an intended capability. Establishing a security failure requires showing a lower-trust caller can perform an operation outside its entitlement.

In the public app-server source, workspace/account switching pauses admission and waits for old thread runtimes to stop before replacing credentials. That lifecycle was inspected in source, not reproduced by switching a real account. [Account switching](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/app-server/src/request_processors/account_processor/workspace_switching.rs#L182), [runtime shutdown](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/app-server/src/request_processors/thread_processor/workspace_switching.rs#L7).

## Permission lifetime

Permission requests retain their originating turn and executor environment. Responses are intersected with the requested permissions; an unknown pending call does not receive a grant. New turns receive new turn-grant stores, while explicitly session-scoped grants live in a separate environment-keyed store. Pending callbacks are canceled on turn transitions. This is source evidence; the upstream Rust tests were inspected but not run. [Grant handling](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/core/src/session/mod.rs#L3535), [turn and environment stores](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/core/src/session/turn_context.rs#L450), [callback cancellation](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/app-server/src/bespoke_event_handling.rs#L165).

An already-running OS process retains its launch sandbox when permissions change. A separate fresh-input review compares the process's retained authority with current policy and grants. It can require approval again or reject reuse when new denied reads cannot be enforced. The installed CLI lists `write_stdin_approval` as stable and enabled. We did not execute a real terminal across a permission-expiry transition. [Terminal policy](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/core/src/unified_exec/stdin_approval.rs#L120), [current grants](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/core/src/unified_exec/stdin_approval.rs#L191).

Executor browser access checks its lifetime signal and environment before and after access/session preparation. A post-await denial does not establish rollback: preparation may already have begun. The scenarios do not prove termination of already-running browser work or responsiveness to every remote settings change.

## Request correlation and client authority

The native pipe prefixes request IDs with a socket-client identity before dispatch. The interactive manager additionally tracks method, request identity, and thread. The fallback result router relies on unique typed call IDs plus surrounding IPC and manager controls; it does not independently compare every host/task field.

Ordinary permission callbacks in the public outgoing-message helper do not receive the additional connection-owner checks used for some verification ceremonies. They retain original conversation routing and lifecycle cancellation. The examined transport client has not been established as a principal confined to a single task, so this observation is not evidence of a task-isolation bypass. [Outgoing callbacks](https://github.com/openai/codex/blob/c40729ea5cf8e947481b130c59807273eda2f8e9/codex-rs/app-server/src/outgoing_message.rs#L662).

## Signed browser responses

The shipped browser plugin contains a receiver-side verifier. It verifies the Ed25519 signature and compares the complete response payload against the expected domain, original request, and allowed decision. The request includes executor, session, turn, and a fresh 32-byte nonce. Isolated tests with real cryptography reject a wrong key/signature, substituted request fields, a denial, and an additional payload field. The transport and keys are synthetic; no live browser was contacted.

The surrounding helper caches one proof promise per session/turn. A new session or turn generates a new nonce. Same-turn calls reuse the proof, so this helper does not poll settings on every action or apply a wall-clock TTL. It also has no post-await metadata recheck: under a mutable metadata mock, a proof initiated for turn A can finish after that mock changes to turn B. The next call requests a fresh proof for B. Actual request-metadata lifetime and host revocation are separate controls; this is not a demonstrated cross-task operation or expiry bypass.

**Follow-up correction:** the shipped native worker clones and deeply freezes metadata, stores it in `AsyncLocalStorage`, and hides it from retired executions. The shared mutable metadata fixture is therefore counterfactual. A component integration test using that actual context mechanism found no adoption of task B's metadata by a pending task A callback. See [browser component results](BROWSER_COMPONENTS.md).

Browser command dispatch awaits this assertion in the inspected plugin. Account identity is not a field in this particular signed request; the host's executor/session mapping and lifecycle are therefore part of the remaining trust path. Native task/workspace receipt verification remains separate and untraced.

## Remaining review leads

- The renderer wrapper can proceed when both initial and later turn lookups are absent, given permissive context and downstream-executor mocks. Its claim service deduplicates rather than checking turn existence. Downstream tool checks vary; this isolated observation does not demonstrate an unauthorized operation.
- Receiver-side verification of signed native task/workspace responses remains untraced. Four identifiers were absent from all 9,815 regular members of the pinned public archive; that bounded search does not establish absence from shipped native code.
- Same-turn browser proof caching persists under synthetic authority revocation in the component lab. The full desktop settings/executor lifecycle still needs an isolated OS-level end-to-end test. Frozen async-local metadata weakens the earlier task-switch race hypothesis.
- Tool implementations have distinct authorization paths. Results for dynamic transport, local MCP, interactive manager requests, and browser access must retain their individual scope.
- A real account switch, native peer allowlist, remote service grant expiry, and live broker connection were not exercised.

## Reproduction and evidence

See the repository README for local extraction and execution commands. Source snippets remain outside the repository. `results/isolated-scenarios.json` records scenario outcomes and fingerprints, `results/shipped-static-findings.json` records exact member locations, and `results/public-source-provenance.json` pins reviewed upstream files.

The harness uses real selected functions with mocked services and one controlled guard-removal mutation. The mutation confirms that the account-change scenario detects removal of the final account comparison. It does not establish a reachable product exploit. All test data are synthetic; the audit did not read credentials, real conversation records, or other accounts.

The published run has 65 passing scenarios. Five are labeled scope observations and one is a mutation-sensitivity control. These categories must not be counted as 65 successful authorization-denial tests.
