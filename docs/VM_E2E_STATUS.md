# Disposable VM end-to-end test

The disposable macOS guest is booted and the matching app opens at its signed-out screen. **No desktop revocation or task-switch case has run.** The current scope is signed-out preparation. Seven browser component cases passed with a synthetic policy authority; their scope and limits remain in [BROWSER_COMPONENTS.md](BROWSER_COMPONENTS.md). No live permission bypass or task/account crossing has been demonstrated.

## Completed preflight

Read-only inspection found UTM 5.0.8 on a macOS 26.2 host. Its CLI supports lifecycle control but has no create/install command. Its AppleScript API exposes Apple-backend VM creation and macOS installation. The installed scripting dictionary exposes keyboard/mouse input for QEMU guests, not Apple-backend macOS guests. Documented automatic first-user provisioning requires macOS 27 or later on both host and guest. These facts identify a bootstrap gap for a fully automated fresh macOS guest through this installed UTM interface; they are not a failed guest test.

The selected CLI route is [Tart](https://github.com/openai/tart), a preprovisioned vanilla macOS guest, SSH, and VNC. The official 2.41.1 release archive was downloaded and its SHA-256 matched `e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2`, as supplied by the [official formula](https://raw.githubusercontent.com/openai/homebrew-tools/main/Formula/tart.rb). Invoking the complete app bundle reported version 2.41.1; strict deep code-signature verification succeeded outside the command sandbox.

Separate workspace-local `TART_HOME` storage and `TART_NO_AUTO_PRUNE=1` were set. Cloning the digest-pinned vanilla macOS 26.2 image completed. The new guest booted macOS 26.2, build 25C56, arm64, with four CPUs, 8192 MiB memory, and a 50 GB disk. Host directory sharing, clipboard integration, audio, and USB accessories are disabled. No host authentication state was copied. The public image password was replaced and verified; SSH uses a fresh lab key and a dedicated host-key file pinned during first-use bootstrap. The template SSH host keys were then regenerated inside the guest, repinned through that connection, and verified with a fresh key-authenticated connection. Guest SIP reports enabled, and Gatekeeper was re-enabled and reports assessments enabled.

The guest app reports version 26.1103.60933, build 25894. Its ASAR, native worker, and browser-service hashes match the recorded target, and standalone strict deep code-signature verification returned exit status zero. The app launched to its Sign in screen; no account was authenticated. These are preparation checks, not evidence of the Work policy route or a successful product browser operation.

Tart's experimental VNC initially opened a wildcard host listener despite printing a loopback URL. The new guest was stopped before app authentication and restarted without experimental VNC. The restarted VM process has no TCP listener. Guest Screen Sharing is reached through an SSH tunnel whose host listener binds only to loopback. ARD authentication type 30 and screenshot capture work. This is a setup observation about listener binding, not a product vulnerability finding.

Automated input calibration remains incomplete: three pointer attempts and one keyboard shortcut attempt produced no observed intended Safari interaction, and the canary counter remained zero. Those attempts do not establish either working input or permission enforcement. The [Node 24.11.0 arm64 archive](https://nodejs.org/dist/v24.11.0/node-v24.11.0-darwin-arm64.tar.xz) matched its [official checksum](https://nodejs.org/dist/v24.11.0/SHASUMS256.txt) and was installed inside the guest's lab directory. The guest loopback canary server started and Safari loaded fixture A with counter zero; the preflight server was stopped afterward. The [fixture's HTTP and disposable Chromium checks](CANARY_FIXTURE.md) validate the fixture separately; they are not an app GUI pass.

[Apple documents](https://support.apple.com/en-bw/guide/remote-desktop/apd8b1c65bd/mac) view-only access when Remote Management is enabled through its command-line tool. That is a possible explanation for the observed input limit; its cause has not been established in this guest. Any required control grant should use the normal guest Sharing settings.

Keep guest disks, authentication state, SSH keys, VNC credentials, raw recordings, and diagnostic captures outside the publication tree. Continuing beyond signed-out preparation requires a fresh dedicated app sign-in, completed input calibration, and supported observation of the actual pending request stage. [The machine-readable result](../results/vm-e2e-status.json) records preparation separately from the unrun matrix.

UTM references: [scripting overview](https://docs.getutm.app/scripting/scripting/), [commands](https://docs.getutm.app/scripting/cheat-sheet/), [macOS guest support](https://docs.getutm.app/guest-support/macos/). Tart references: [quick start](https://tart.run/quick-start/), [configuration source](https://github.com/openai/tart/blob/2.41.1/Sources/tart/Config.swift), [run command source](https://github.com/openai/tart/blob/2.41.1/Sources/tart/Commands/Run.swift).

## What the guest test must establish

The target is **Work preferences → Local browser use**, whose inspected path reads `localBrowserUse` from the authenticated Work-settings service. Origin-specific Browse permission, OS consent, and shell permissions are different controls. First establish that the guest account exposes the target setting and that the actual Work route uses it. Feature absence is a setup blocker, not a denial result.

A canary click is a harmless test-page button that increments a fixture-specific counter. The counter proves a page event. Pair it with the actual product browser command and recording to establish who caused it. The operator must not click it during a measured case.

| Case | Transition | Required evidence |
| --- | --- | --- |
| G0 | On; click fixture A once | Actual Work route, task/turn identity, product command and counter 0→1. |
| G1 | Off saved before a new turn | Actual request plus denial/cancellation or a separately classified timeout. |
| G2 | First action succeeds; save Off; issue a distinct second action in the same predeclared turn | Off save completes before the new command starts; unchanged turn identity; executor lifecycle; canary outcome. |
| G3 | New turn after G2, with Off still saved | New turn identity and fresh request/denial. |
| G4 | Hold an identified real Work-settings GET before upstream send; save Off; release | Gate chronology, unchanged request, result and cancellation state. |
| G5 | Hold a genuine On response after upstream receipt; save Off; release unchanged response | Upstream On predates Off save; release follows save; resulting action/lifetime. |
| G6 | While an identified access request from A is pending, select B; release A | A/B identities, actual pending interval, UI transition, A's target and outcome. |
| G7 | If normal scheduling permits, run B while A is pending; then release A | Separate identities and fixtures, actual concurrency, proof binding and effects. |
| G8 | Stop A through the app while its identified request is pending; release | Stop/cancellation chronology and any later operation. |

A spinner does not establish a pending proof. Holding a remote settings response tests stale policy delivery; it does not hold an already signed local proof. Do not replace the native socket authority or bypass peer authentication to make that interval observable. Mark an unavailable interval as unavailable.

Selecting B does not demonstrate retirement of A. A continuing on A's own fixture can be expected background work. A task-boundary finding requires evidence of the wrong task identity or resource authority. The component test's forced retirement bypasses normal worker serialization and is not evidence that the GUI can reach that schedule. Cross-account testing additionally requires independently supplied dedicated accounts and resources; it is outside this same-account task-switch matrix.

## Publication rule

For each case, preserve privately the guest/app identity, setting-save evidence, originating task/turn, real command timeline, executor lifecycle, and canary ledger. Publish reviewed aliases and the narrow observed outcome. Use `not_run`, `setup_blocked`, `passed_control`, `observed_behavior`, or `inconclusive`; distinguish denial, cancellation, worker termination, timeout, and success. A no-click timeout alone does not prove permission enforcement.

Repeat timing-dependent observations before claiming reliability, and include counterexamples. Full-product results must cite their own guest evidence; the existing component results cannot supply missing GUI, policy, or lifecycle observations. [Machine-readable status](../results/vm-e2e-status.json) keeps those evidence levels separate. This is a publication snapshot; subsequent guest runtime work needs its own update.
