#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Selected production components, synthetic policy authority, real local wire/crypto/browser.
// This is not a full Codex desktop lifecycle test. vm is not a security sandbox.
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createNetServer, createConnection } from 'node:net';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import vm from 'node:vm';

const options = { inputs: [] };
for (let i = 2; i < process.argv.length; i++) {
  const key = process.argv[i];
  if (key === '--input') options.inputs.push(process.argv[++i]);
  else if (key === '--browser') options.browser = process.argv[++i];
  else if (key === '--out') options.out = process.argv[++i];
  else if (key === '--help') {
    console.log('Usage: node tools/test-browser-components.mjs --input /scratch/browser.json --input /scratch/context.json --input /scratch/host-methods.json [--browser /disposable/chrome-headless-shell] --out /scratch/results.json');
    process.exit(0);
  } else throw new Error(`Unknown argument: ${key}`);
}
if (options.inputs.length !== 3 || !options.out) throw new Error('Three local extraction inputs and an output path are required.');
const adapter = JSON.parse(await readFile(new URL('../adapters/codex-browser-component-integration.json', import.meta.url), 'utf8'));
const docs = await Promise.all(options.inputs.map(async p => JSON.parse(await readFile(p, 'utf8'))));
for (const doc of docs) assert.ok(adapter.sources.some(s => s.sha256 === doc.source.sha256), 'Unsupported extraction fingerprint');
const methods = docs.flatMap(d => d.sources.flatMap(s => s.methods.map(m => ({ ...m, member: s.member, source_sha256: s.sha256 }))));
const provenance = new Map();
function selected(name) {
  const found = methods.filter(m => m.name === name);
  assert.equal(found.length, 1, `Expected one reviewed ${name}`);
  const m = found[0], pin = adapter.methods.find(p => p.name === name && p.member === m.member && p.start_utf16 === m.start_utf16);
  assert.ok(pin, `Missing reviewed pin for ${name}`);
  assert.equal(m.source_sha256, pin.source_sha256);
  assert.equal(createHash('sha256').update(m.code).digest('hex'), pin.snippet_sha256);
  provenance.set(name, pin);
  return m;
}
const globals = { Error, DOMException, Buffer, setTimeout, clearTimeout, structuredClone, AsyncLocalStorage };
function fn(name, bindings = {}) {
  return vm.runInNewContext(`(${selected(name).code})`, { ...globals, ...bindings }, { timeout: 1000, contextCodeGeneration: { strings: false, wasm: false } });
}
function method(name, bindings = {}) {
  return vm.runInNewContext(`({${selected(name).code}})[${JSON.stringify(name)}]`, { ...globals, ...bindings }, { timeout: 1000, contextCodeGeneration: { strings: false, wasm: false } });
}
function latch() {
  const arrived = Promise.withResolvers(), released = Promise.withResolvers();
  return { arrived: arrived.promise, notify: arrived.resolve, wait: () => released.promise, release: released.resolve };
}
function frame(message) {
  const body = Buffer.from(JSON.stringify(message)), prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length);
  return Buffer.concat([prefix, body]);
}
function receive(socket, onMessage) {
  let pending = Buffer.alloc(0);
  socket.on('data', chunk => {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 4) {
      const size = pending.readUInt32LE(0);
      if (size > 65536) { socket.destroy(new Error('Lab frame exceeds limit')); return; }
      if (pending.length < size + 4) return;
      let message;
      try { message = JSON.parse(pending.subarray(4, size + 4).toString('utf8')); }
      catch { socket.destroy(new Error('Lab received malformed JSON')); return; }
      pending = pending.subarray(size + 4);
      Promise.resolve(onMessage(message)).catch(error => socket.destroy(error));
    }
  });
}
async function connectProof(pipe) {
  const socket = createConnection({ path: pipe });
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  let pending;
  receive(socket, message => { if (message.id === 1 && pending) { const p = pending; pending = null; message.error ? p.reject(new Error(message.error.message)) : p.resolve(message.result); } });
  socket.on('error', error => pending?.reject(error));
  socket.on('close', () => pending?.reject(new Error('Lab proof connection closed')));
  return {
    read(params) { assert.equal(pending, undefined); const p = Promise.withResolvers(); pending = p; socket.write(frame({ jsonrpc: '2.0', id: 1, method: 'browser/access', params })); return p.promise; },
    async close() { socket.destroy(); },
  };
}

const require = process.env.BROKER_LAB_PLAYWRIGHT_ROOT
  ? createRequire(path.join(path.resolve(process.env.BROKER_LAB_PLAYWRIGHT_ROOT), 'package.json'))
  : createRequire(import.meta.url);
const { chromium } = require('playwright-core');
const results = [], counters = new Map();
const canaryServer = createHttpServer((req, res) => {
  const match = /^\/([a-z0-9-]+)(\/hit)?$/.exec(req.url ?? '');
  if (!match) { res.writeHead(404); res.end(); return; }
  const key = match[1];
  if (match[2] && req.method === 'POST') {
    counters.set(key, (counters.get(key) ?? 0) + 1);
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ count: counters.get(key) })); return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
  res.end(`<title>Disposable proof canary</title><button id="canary">Increment canary</button><output id="count">0</output><script>document.querySelector('#canary').onclick=async()=>{const r=await fetch('/${key}/hit',{method:'POST'});document.querySelector('#count').textContent=(await r.json()).count;};</script>`);
});
let origin, browser, scratch;
const deepFreeze = fn('deepFreeze'), isPlainObject = fn('isPlainObject');
const createState = fn('createExecState', { deepFreeze, isPlainObject });
const createContext = fn('createExecContext');
const metadata = fn('Ne');

async function lab(name, operation) {
  const trace = [], key = name.replaceAll(/[^a-z0-9-]/g, '-');
  const directory = await mkdtemp(path.join(scratch, 'case-')), pipe = path.join(directory, 'p.sock');
  await chmod(directory, 0o700);
  const keyPair = generateKeyPairSync('ed25519'), ctx = createContext();
  const policy = { allowed: true, holdDecision: null, holdReply: null };
  const activeHolds = new Set();
  const executor = { state: { environmentId: 'executor-A' }, browserAccessAuth: { token: 'synthetic-only' }, lifetime: new AbortController(), options: {} };
  const producerAccess = method('readBrowserAccess', { i3: { Sl: () => {} }, i7: async () => {
    if (policy.holdDecision) { const hold = policy.holdDecision; policy.holdDecision = null; activeHolds.add(hold); hold.notify(); try { await hold.wait(); } finally { activeHolds.delete(hold); } }
    return policy.allowed;
  } });
  const connections = new Set();
  const authority = createNetServer(socket => {
    connections.add(socket); socket.once('close', () => connections.delete(socket));
    receive(socket, async rpc => {
      assert.equal(rpc.method, 'browser/access');
      const allowed = await producerAccess.call(executor, rpc.params.executorId, async () => {});
      const payload = JSON.stringify({ domain: 'codex.browserAccess.v1', request: rpc.params, allowed });
      const response = { payload, signature: sign(null, Buffer.from(payload), keyPair.privateKey).toString('base64') };
      trace.push({ event: 'proof-decision', session: rpc.params.sessionId, turn: rpc.params.turnId, allowed });
      if (policy.holdReply) { const hold = policy.holdReply; policy.holdReply = null; activeHolds.add(hold); hold.notify(); try { await hold.wait(); } finally { activeHolds.delete(hold); } }
      socket.write(frame({ jsonrpc: '2.0', id: rpc.id, result: response }));
    });
    socket.on('error', () => {});
  });
  let browserContext, caseTimeout;
  try {
  await new Promise((resolve, reject) => { authority.once('error', reject); authority.listen(pipe, resolve); });
  await chmod(pipe, 0o600);
  const runtime = { env: { BROWSER_USE_ACCESS_EXECUTOR_ID: 'executor-A', BROWSER_USE_ACCESS_PIPE_PATH: pipe, BROWSER_USE_ACCESS_VERIFYING_IDENTITY: keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') } };
  const accessor = vm.runInNewContext(`Object.getOwnPropertyDescriptor({${selected('requestMeta').code}}, 'requestMeta').get`, { execContext: ctx }, { timeout: 1000 });
  Object.defineProperty(runtime, 'requestMeta', { get: accessor });
  const verifier = fn('wce', {
    zR: 'BROWSER_USE_ACCESS_PIPE_PATH', KR: 'BROWSER_USE_ACCESS_VERIFYING_IDENTITY', YR: 'codex.browserAccess.v1', gce: createPublicKey, yce: verify,
    Wo: { create: connectProof }, Yx: class { constructor(connection) { this.connection = connection; } read(request) { return this.connection.read(request); } },
  });
  runtime.assertBrowserAccess = fn('Y6', { VR: 'BROWSER_USE_ACCESS_EXECUTOR_ID', Ne: metadata, bce: randomBytes, wce: verifier })(runtime);
  browserContext = await browser.newContext();
  await browserContext.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const page = await browserContext.newPage();
  await page.goto(`${origin}/${key}`, { timeout: 10000 });
  const dispatch = async command => {
    const visible = metadata(runtime) ?? null;
    let current = true; try { ctx.getCurrent(); } catch { current = false; }
    trace.push({ event: 'canary-dispatch', label: command.label, originatingExec: ctx.getOptional()?.id ?? null, activeExec: ctx.activeId, visibleSession: visible?.session_id ?? null, currentContext: current, policyAllowed: policy.allowed });
    // Deliberately do not invent a downstream native guard here. Record its
    // actual decision separately; this adapter only reaches the disposable page.
    const before = counters.get(key) ?? 0;
    await page.locator('#canary').click();
    await page.waitForFunction(expected => document.querySelector('#count').textContent === String(expected), before + 1);
    return counters.get(key);
  };
  const command = method('executeAgentCommand', { o: runtime, Aa: () => { throw new Error('Dot is not part of this lab'); }, Y: dispatch });
  const state = (id, session, turn) => createState({ id, request_meta: { 'x-codex-turn-metadata': { session_id: session, turn_id: turn, nested: { canary: true } } } });
  const execute = (s, label) => { ctx.activate(s.id); return ctx.run(s, () => command({ type: 'lab_canary_click', label })).finally(() => ctx.clear(s.id)); };
    const observations = await Promise.race([
      operation({ ctx, runtime, policy, executor, trace, state, execute, count: () => counters.get(key) ?? 0 }),
      new Promise((_, reject) => { caseTimeout = setTimeout(() => reject(new Error('Lab case exceeded 20 second deadline')), 20000); }),
    ]);
    results.push({ name, passed: true, observations, trace });
  } catch (error) { results.push({ name, passed: false, error: error.message, trace }); }
  finally {
    clearTimeout(caseTimeout);
    for (const hold of [...activeHolds, policy.holdDecision, policy.holdReply]) hold?.release();
    for (const socket of connections) socket.destroy();
    if (authority.listening) await new Promise(resolve => authority.close(resolve));
    await browserContext?.close();
    await rm(directory, { recursive: true, force: true });
  }
}

try {
  scratch = await mkdtemp('/private/tmp/broker-lab-');
  await new Promise((resolve, reject) => { canaryServer.once('error', reject); canaryServer.listen(0, '127.0.0.1', resolve); });
  origin = `http://127.0.0.1:${canaryServer.address().port}`;
  browser = await chromium.launch({ executablePath: options.browser, headless: true, chromiumSandbox: true, timeout: 20000 });
  await lab('metadata-is-frozen-and-cloned', async ({ ctx, runtime }) => {
    const input = { id: 'call-A', request_meta: { 'x-codex-turn-metadata': { session_id: 'task-A', turn_id: 'turn-A' } } };
    const s = createState(input); input.request_meta['x-codex-turn-metadata'].session_id = 'task-B';
    ctx.activate(s.id);
    await ctx.run(s, async () => {
      assert.equal(metadata(runtime).session_id, 'task-A');
      assert.equal(Object.isFrozen(runtime.requestMeta), true);
      assert.equal(Object.isFrozen(runtime.requestMeta['x-codex-turn-metadata']), true);
    });
    return { originalInputMutationDoesNotChangeTask: true, metadataDeeplyFrozen: true };
  });
  await lab('same-turn-revocation-then-new-turn', async ({ ctx, policy, state, execute, count, trace }) => {
    const first = state('call-A', 'task-A', 'turn-A');
    await execute(first, 'warm-proof');
    policy.allowed = false;
    const second = state('call-A2', 'task-A', 'turn-A');
    await execute(second, 'same-turn-after-synthetic-revocation');
    assert.equal(count(), 2);
    assert.equal(trace.filter(e => e.event === 'proof-decision').length, 1);
    await assert.rejects(execute(state('call-B', 'task-A', 'turn-B'), 'new-turn-after-revocation'), /disabled/);
    assert.equal(count(), 2);
    return { canaryClicksBeforeAndAfterRevocation: 2, sameTurnUsedCachedProof: true, nextTurnFreshProofDenied: true };
  });
  await lab('revocation-before-pending-decision', async ({ policy, state, execute, count }) => {
    const hold = latch(); policy.holdDecision = hold;
    const pending = execute(state('call-A', 'task-A', 'turn-A'), 'pending-check');
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    await hold.arrived; policy.allowed = false; hold.release();
    assert.match((await outcome).error?.message ?? '', /disabled/);
    assert.equal(count(), 0);
    return { policyRevokedBeforeAuthorityDecision: true, canaryClicks: 0 };
  });
  await lab('executor-stops-before-pending-decision', async ({ policy, executor, state, execute, count }) => {
    const hold = latch(); policy.holdDecision = hold;
    const pending = execute(state('call-A', 'task-A', 'turn-A'), 'pending-executor');
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    await hold.arrived; executor.lifetime.abort(); hold.release();
    assert.match((await outcome).error?.message ?? '', /disabled/);
    assert.equal(count(), 0);
    return { actualProducerMethodHonoredLifetimeAbort: true, canaryClicks: 0 };
  });
  await lab('revocation-after-proof-signed-before-delivery', async ({ policy, state, execute, count }) => {
    const hold = latch(); policy.holdReply = hold;
    const pending = execute(state('call-A', 'task-A', 'turn-A'), 'signed-before-revocation');
    await hold.arrived; policy.allowed = false; hold.release();
    await pending; assert.equal(count(), 1);
    return { alreadySignedAllowResponseAccepted: true, canaryClicks: 1, authorityDoesNotModelDesktopRevocationLifecycle: true };
  });
  await lab('task-switch-while-task-a-proof-pending', async ({ ctx, policy, runtime, state, execute, count, trace }) => {
    const hold = latch(); policy.holdReply = hold;
    const a = state('call-A', 'task-A', 'turn-A'), b = state('call-B', 'task-B', 'turn-B');
    const pendingA = execute(a, 'pending-A');
    await hold.arrived;
    await execute(b, 'active-B');
    ctx.clear(b.id);
    hold.release(); await pendingA;
    const late = trace.find(e => e.event === 'canary-dispatch' && e.label === 'pending-A');
    assert.equal(late.originatingExec, 'call-A');
    assert.equal(late.visibleSession, null);
    assert.equal(late.currentContext, false);
    assert.equal(count(), 2);
    await ctx.run(a, async () => { assert.equal(metadata(runtime), undefined); assert.throws(() => ctx.getCurrent(), /context not found/); });
    return { taskADidNotInheritTaskBMetadata: true, nativeCurrentContextGuardRejectedRetiredA: true, wrapperContinuedIntoUnguardedCanaryAdapter: true, canaryClicks: 2, normalWorkerQueueBypassedByForcedRetirementDriver: true };
  });
  await lab('retired-task-new-request-needs-current-metadata', async ({ ctx, runtime, state, execute, count }) => {
    const a = state('call-A', 'task-A', 'turn-A');
    ctx.activate(a.id); ctx.clear(a.id);
    await ctx.run(a, async () => {
      const gate = fn('Y6', { VR: 'BROWSER_USE_ACCESS_EXECUTOR_ID', Ne: metadata, bce: randomBytes, wce: async () => { throw new Error('must not request proof'); } })(runtime);
      await assert.rejects(gate(), /current turn/);
    });
    assert.equal(count(), 0);
    return { retiredContextCannotStartFreshBrowserProof: true, canaryClicks: 0 };
  });
} finally {
  await browser?.close();
  if (canaryServer.listening) await new Promise(resolve => canaryServer.close(resolve));
  if (scratch) await rm(scratch, { recursive: true, force: true });
}

const report = {
  format: 'browser-proof-component-integration', format_version: 1,
  scope: 'Selected production components with synthetic policy authority, real local framed sockets, real Ed25519, real AsyncLocalStorage, and disposable Chromium canary actions.',
  full_product_end_to_end: false,
  selected_components: [...provenance.values()],
  browser_version: browser?.version(),
  cases_passed: results.filter(r => r.passed).length, cases_failed: results.filter(r => !r.passed).length,
  results,
  corrections: ['The previous mutable shared-metadata fixture does not reflect the worker. Actual request metadata is cloned, deeply frozen, async-local, and hidden from retired calls.'],
  limitations: [
    'Synthetic revocation changes only the lab policy decision; it does not reproduce the desktop settings UI or executor restart/cancellation lifecycle.',
    'The canary adapter deliberately has no additional native I/O guard. Its late action proves wrapper continuation only; getCurrent rejection is observed separately.',
    'The forced task-switch driver directly changes active execution. Normal worker execution is serialized in inspected source; this test does not establish that concurrent task replacement is reachable through normal commands.',
    'The full app was not launched in a second profile because inspected user-data overrides leave shared user-level paths and OS identity.',
    'No real account, live desktop broker, existing browser profile, cloud service, or native peer allowlist was used.',
  ],
  cleanup: { browser_closed: true, canary_server_closed: true, synthetic_broker_sockets_closed: true, scratch_removed: true },
};
await writeFile(options.out, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ passed: report.cases_passed, failed: report.cases_failed, scope: report.scope }));
if (report.cases_failed) process.exitCode = 1;
