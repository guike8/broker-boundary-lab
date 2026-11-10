#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Execute selected, locally extracted guard methods against synthetic dependencies.
// node:vm is a dependency-isolation aid here, not a security sandbox.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import vm from 'node:vm';

const SUPPORTED_ARCHIVE = 'a77588b2dcfa9b394d722dd8c2c8b13d3a09bacd49c839cc715245742dba6048';
const options = { inputs: [] };
for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === '--input') options.inputs.push(process.argv[++i]);
  else if (arg === '--out') options.out = process.argv[++i];
  else if (arg === '--help') {
    console.log('Usage: node tools/audit-local-methods.mjs --input /scratch/host-methods.json --input /scratch/renderer-methods.json [--out /scratch/results.json]');
    process.exit(0);
  } else throw new Error(`Unknown argument: ${arg}`);
}
if (!options.inputs.length) throw new Error('Supply local extraction files with --input; application code is never bundled with this tool.');
const documents = await Promise.all(options.inputs.map(async p => JSON.parse(await readFile(p, 'utf8'))));
const adapter = JSON.parse(await readFile(new URL('../adapters/codex-macos-26.1103.60933-25894.json', import.meta.url), 'utf8'));
for (const doc of documents) {
  if (doc.format === 'local-broker-method-extraction') {
    assert.equal(doc.source.sha256, SUPPORTED_ARCHIVE, 'Unsupported build: review aliases and fixture adapters before adding a new artifact hash.');
  } else {
    assert.equal(doc.format, 'local-broker-function-extraction');
    assert.equal(doc.source.sha256, adapter.javascript_file_sha256, 'Unsupported plugin file');
  }
}
const records = documents.flatMap(d => d.sources.flatMap(s => s.methods.map(m => ({ ...m, member: s.member, source_sha256: s.sha256 }))));
const methods = [...new Map(records.map(m => [`${m.member}:${m.start_utf16}`, m])).values()];
const used = new Map();
function select(name, owner) {
  const found = methods.filter(m => m.name === name && (!owner || m.class?.name === owner));
  assert.equal(found.length, 1, `Expected one extracted ${owner ? owner + '.' : ''}${name}; found ${found.length}`);
  const m = found[0];
  const pin = adapter.methods.find(p => p.name === m.name && p.member === m.member && p.start_utf16 === m.start_utf16);
  assert.ok(pin, `No reviewed adapter pin for ${name}`);
  assert.equal(m.source_sha256, pin.source_sha256, 'Extraction source digest differs from reviewed adapter');
  assert.equal(createHash('sha256').update(m.code).digest('hex'), pin.snippet_sha256, 'Extracted method differs from reviewed snippet digest');
  used.set(`${m.member}:${m.start_utf16}`, m);
  return m;
}
function compile(name, bindings = {}, owner) {
  const method = select(name, owner);
  return vm.runInNewContext(`({${method.code}})[${JSON.stringify(name)}]`, {
    Error, DOMException, AbortController, AbortSignal, performance, ...bindings,
  }, { timeout: 1000, contextCodeGeneration: { strings: false, wasm: false } });
}
function declaration(name, bindings = {}) {
  return vm.runInNewContext(`(${select(name).code})`, { Error, DOMException, Buffer, setTimeout, clearTimeout, ...bindings }, { timeout: 1000, contextCodeGeneration: { strings: false, wasm: false } });
}

const results = [];
async function check(name, fn, kind = 'guard-scenario') {
  try { await fn(); results.push({ name, kind, passed: true }); }
  catch (error) { results.push({ name, kind, passed: false, error: error.message }); }
}
const lifetimeMethod = compile('captureRequestLifetime');
for (const change of ['unchanged', 'auth-generation', 'catalog-generation', 'disposed']) {
  await check(`request lifetime: ${change}`, () => {
    const state = { authTokenGeneration: 3, catalogRequestGeneration: 8, disposed: false };
    const guard = lifetimeMethod.call(state);
    if (change === 'auth-generation') state.authTokenGeneration++;
    if (change === 'catalog-generation') state.catalogRequestGeneration++;
    if (change === 'disposed') state.disposed = true;
    if (change === 'unchanged') guard();
    else assert.throws(guard, error => error.name === 'AbortError');
  });
}

function threadFixture(change = 'none') {
  const state = {
    environment: 'env-A', principal: { accountId: 'account-A', userId: 'user-A' }, requests: 0,
    authTokenGeneration: 1, catalogRequestGeneration: 1, disposed: false,
  };
  let selectedThread;
  const connection = {
    appServerVersion: 'fixture-supported-version',
    captureRequestLifetime: () => lifetimeMethod.call(state),
    getAuthenticatedPrincipal: async () => ({ ...state.principal }),
    getCachedAuthenticatedPrincipal: () => state.principal,
    sendAppServerRequest: async (method, params) => {
      state.requests++;
      if (method === 'thread/read') {
        selectedThread = { id: params.threadId, historyMode: 'paginated', source: null };
        return { thread: selectedThread };
      }
      assert.equal(method, 'thread/items/list');
      if (change === 'account') state.principal = { accountId: 'account-B', userId: 'user-A' };
      if (change === 'user') state.principal = { accountId: 'account-A', userId: 'user-B' };
      if (change === 'environment') state.environment = 'env-B';
      if (change === 'auth-generation') state.authTokenGeneration++;
      if (change === 'catalog-generation') state.catalogRequestGeneration++;
      if (change === 'disposed') state.disposed = true;
      return { data: [{ turnId: 'turn-A', item: { id: 'message-A', type: 'agentMessage', text: 'synthetic fixture' } }], nextCursor: null };
    },
  };
  const bindings = {
    t4: { qh: () => true }, lw: {}, lm: { E: () => null },
    lS: async () => ({ thread: selectedThread, turns: [] }),
  };
  const context = {
    conversationExecutor: { getState: async () => ({ ready: true, environmentId: state.environment }) },
    getLocalAppServerClient: () => connection,
  };
  return { state, bindings, context };
}
for (const change of ['none', 'account', 'user', 'environment', 'auth-generation', 'catalog-generation', 'disposed']) {
  await check(`native thread read after awaited response: ${change}`, async () => {
    const f = threadFixture(change), method = compile('readLocalTaskThread', f.bindings);
    const promise = method.call(f.context, { environmentId: 'env-A', threadId: 'thread-A', limit: 20 });
    if (change === 'none') {
      const result = await promise;
      assert.equal(result.threadId, 'thread-A');
      assert.equal(result.items[0].text, 'synthetic fixture');
    } else await assert.rejects(promise, /changed|retired|not ready/);
  });
}
await check('native thread read: wrong executor rejected before requests', async () => {
  const f = threadFixture(), method = compile('readLocalTaskThread', f.bindings);
  await assert.rejects(method.call(f.context, { environmentId: 'env-B', threadId: 'thread-A' }), /not ready/);
  assert.equal(f.state.requests, 0);
});
await check('native thread read: same-account target selection is supported', async () => {
  const f = threadFixture(), method = compile('readLocalTaskThread', f.bindings);
  const value = await method.call(f.context, { environmentId: 'env-A', threadId: 'thread-B', limit: 20 });
  assert.equal(value.threadId, 'thread-B');
}, 'scope-observation');

for (const change of ['none', 'missing-auth', 'wrong-environment', 'denied', 'abort-during-check', 'environment-during-check', 'abort-during-prepare', 'environment-during-prepare']) {
  await check(`executor browser access: ${change}`, async () => {
    const controller = new AbortController();
    const state = { environmentId: change === 'wrong-environment' ? 'env-B' : 'env-A' };
    let prepared = 0;
    const method = compile('readBrowserAccess', {
      i3: { Sl: () => {} },
      i7: async () => {
        if (change === 'abort-during-check') controller.abort();
        if (change === 'environment-during-check') state.environmentId = 'env-B';
        return change !== 'denied';
      },
    });
    const value = await method.call({ browserAccessAuth: change === 'missing-auth' ? null : { token: 'synthetic-fixture' }, state, lifetime: controller, options: {} }, 'env-A', async () => {
      prepared++;
      if (change === 'abort-during-prepare') controller.abort();
      if (change === 'environment-during-prepare') state.environmentId = 'env-B';
    });
    assert.equal(value, change === 'none');
    const expectedPrepare = ['none', 'abort-during-prepare', 'environment-during-prepare'].includes(change) ? 1 : 0;
    assert.equal(prepared, expectedPrepare);
  });
}

for (const change of ['none', 'thread-environment-mismatch', 'executor-changes-before-membership']) {
  await check(`project assignment: ${change}`, async () => {
    let environment = 'env-A', writes = 0;
    const method = compile('assignChildTaskProject', { ei: { JXB: x => x, iwv: 'local' } });
    const context = {
      conversationExecutor: { getState: async () => ({ ready: true, environmentId: environment }) },
      appServerConnectionRegistry: { getConnection: () => ({ readThread: async () => ({ environments: [{ environmentId: change === 'thread-environment-mismatch' ? 'env-B' : 'env-A' }] }) }) },
      projectsManager: { withLocalProject: async (_id, fn) => {
        if (change === 'executor-changes-before-membership') environment = 'env-B';
        return fn();
      } },
      threadProjectAssignments: { setMembership: async () => { writes++; } },
      scopedState: { flushOrThrow: async () => {} },
    };
    const promise = method.call(context, { environmentId: 'env-A', projectId: 'project-A', threadId: 'thread-A' });
    if (change === 'none') { await promise; assert.equal(writes, 1); }
    else { await assert.rejects(promise, /executor|not ready/); assert.equal(writes, 0); }
  });
}

function rendererFixture(change = 'none') {
  const controller = new AbortController();
  let executed = 0, claimed = 0, turnReads = 0, claimedKey;
  const turn = { status: 'inProgress', items: [{ type: 'userMessage', clientId: 'client-A' }], params: { clientUserMessageId: 'client-A' } };
  if (change === 'wrong-message-client') turn.params.clientUserMessageId = 'client-B';
  if (change === 'realtime-wrong-host' || change === 'realtime-wrong-thread') {
    turn.items = [{ type: 'userMessage', content: [{ type: 'text', text: '<realtime_delegation>synthetic' }] }];
  }
  const manager = {
    getFollowUpContext: async () => ({}),
    getTurnById: async () => { turnReads++; return change === 'missing-turn-metadata' ? null : turn; },
    getStreamRole: async () => 'leader',
  };
  const noop = () => {};
  const modules = {
    SRbQ: { mS: (_stack, value) => value, hk: noop },
    DBCl: { JXB: x => x, DDP: x => x }, JGl5: { PD: 'codex_app' },
    PFjh: { dj: () => ({ count: noop, hist: noop }) }, Dgwo: { V: () => manager },
    u3wd: { Z: noop }, OOaz: { YA: () => false }, TL6G: { O1: { dispatchMessage: noop } },
    XLpU: { _A: 'synthetic-locator' }, kfGJ: { fI: 'local' },
    WFY2: { v: { info: noop, error: noop, warning: noop } }, Um05: { Z: x => x },
    GaA7: { appServices: { dynamicToolCalls: { tryClaimExecution: async key => {
      claimed++; claimedKey = key;
      if (change === 'abort-during-claim') controller.abort();
      return change !== 'claim-refused';
    } } } },
    rUmy: { executeDynamicToolCallRequest: async () => { executed++; return true; } },
  };
  const req = name => { assert.ok(name in modules, `Unexpected import: ${name}`); return modules[name]; };
  req.d = (exports, getters) => { for (const [key, getter] of Object.entries(getters)) Object.defineProperty(exports, key, { get: getter }); };
  req.e = async () => {
    if (change === 'completed-during-load') turn.status = 'completed';
    if (change === 'abort-during-load') controller.abort();
  };
  const exports = {};
  compile('ysE7')({}, exports, req);
  const request = {
    scope: { get: () => ({ locator: { hostId: change === 'realtime-wrong-host' ? 'remote' : 'local', conversationId: change === 'realtime-wrong-thread' ? 'thread-B' : 'thread-A' } }) },
    serverRequest: { id: 'request-A', method: 'item/tool/call', params: { callId: 'call-A', threadId: 'thread-A', turnId: 'turn-A', tool: 'synthetic_tool' } },
    hostId: 'local', signal: controller.signal, transport: 'dynamic', callerSource: 'codex',
  };
  if (change === 'missing-thread') delete request.serverRequest.params.threadId;
  if (change === 'abort-before-dispatch') controller.abort();
  return { execute: () => exports.t(request), counters: () => ({ executed, claimed, turnReads, claimedKey }) };
}
for (const change of ['none', 'missing-thread', 'wrong-message-client', 'realtime-wrong-host', 'realtime-wrong-thread', 'abort-before-dispatch', 'abort-during-claim', 'claim-refused', 'completed-during-load', 'abort-during-load']) {
  await check(`renderer dispatch: ${change}`, async () => {
    const f = rendererFixture(change), value = await f.execute(), c = f.counters();
    assert.equal(value, change === 'none');
    assert.equal(c.executed, change === 'none' ? 1 : 0);
    if (change === 'none') {
      assert.equal(c.claimedKey.callId, 'call-A');
      assert.equal(c.claimedKey.hostId, 'local');
      assert.equal(c.claimedKey.threadId, 'thread-A');
      assert.equal(c.claimedKey.turnId, 'turn-A');
      assert.ok(c.turnReads >= 2, 'Turn must be read again after lazy loading');
    }
  });
}
await check('renderer dispatch: absent turn metadata proceeds under permissive service mocks', async () => {
  const f = rendererFixture('missing-turn-metadata');
  assert.equal(await f.execute(), true);
  assert.equal(f.counters().executed, 1);
}, 'scope-observation');

const eb = select('EB');
const typedId = vm.runInNewContext(`(${eb.code})`, {}, { timeout: 1000 });
function responseRouter() {
  const bindings = { EB: typedId, ei: { udX: () => Promise.withResolvers(), K20: { safeParse: value => ({ success: typeof value?.success === 'boolean', data: value }) } } };
  const router = { pending: new Map() };
  router.wait = compile('wait', bindings, 'EW');
  router.route = compile('route', bindings, 'EW');
  router.cancelled = 0;
  router.cancel = id => {
    router.cancelled++;
    const key = typedId(id), request = router.pending.get(key);
    if (request) { router.pending.delete(key); request.reject(new Error('synthetic cancellation')); }
  };
  return router;
}
await check('response router: duplicate pending ID rejected', async () => {
  const r = responseRouter(), first = r.wait('call-A');
  assert.throws(() => r.wait('call-A'), /pending/);
  assert.equal(r.route({ id: 'call-A', result: { success: true } }), true);
  assert.equal((await first).success, true);
});
await check('response router: number and string IDs remain separate', async () => {
  const r = responseRouter(), numeric = r.wait(1), text = r.wait('1');
  r.route({ id: '1', result: { success: true } });
  assert.equal(r.pending.size, 1);
  r.route({ id: 1, result: { success: false } });
  assert.equal((await numeric).success, false);
  assert.equal((await text).success, true);
});
await check('response router: unknown and repeated replies rejected', async () => {
  const r = responseRouter();
  assert.equal(r.route({ id: 'unrelated', result: { success: true } }), false);
  const pending = r.wait('call-A');
  r.route({ id: 'call-A', result: { success: true } });
  await pending;
  assert.equal(r.route({ id: 'call-A', result: { success: true } }), false);
});
await check('response router: mocked schema rejection propagates', async () => {
  const r = responseRouter(), pending = r.wait('call-A');
  r.route({ id: 'call-A', result: {} });
  await assert.rejects(pending, /invalid response/);
});

for (const change of ['none', 'missing-conversation', 'follower', 'retired-before-call', 'retired-before-response', 'abort-before-call', 'abort-pending', 'duplicate-request']) {
  await check(`interactive manager: ${change}`, async () => {
    const signal = new AbortController(), router = responseRouter();
    let current = change !== 'retired-before-call', dispatched = 0, removed = 0;
    const bindings = { ei: { JXB: x => x, DDP: x => x } };
    const context = {
      disposed: false, requests: new Map(), nativeResponses: router,
      assertCurrent: () => { if (!current) throw new Error('synthetic manager retired'); },
      manager: {
        getConversation: () => change === 'missing-conversation' ? null : {},
        getStreamRole: () => ({ role: change === 'follower' ? 'follower' : 'leader' }),
        removePendingDynamicToolRequest: () => { removed++; },
        onRequest: request => {
          dispatched++;
          if (change === 'abort-pending') signal.abort();
          else {
            if (change === 'retired-before-response') current = false;
            void context.sendResponse(request.method, { id: request.id, result: { success: true } });
          }
        },
      },
    };
    context.isCurrent = compile('isCurrent', bindings, 'EV');
    context.cancelRequest = compile('cancelRequest', bindings, 'EV');
    context.sendResponse = compile('sendResponse', bindings, 'EV');
    if (change === 'abort-before-call') signal.abort();
    if (change === 'duplicate-request') context.requests.set('request-A', {});
    const method = compile('callInteractiveDynamicAppTool', bindings, 'EV');
    const promise = method.call(context, { id: 'request-A', method: 'item/tool/call', params: { threadId: 'thread-A' } }, signal.signal);
    if (change === 'none') {
      assert.equal((await promise).success, true);
      assert.equal(dispatched, 1);
      assert.equal(await context.sendResponse('item/tool/call', { id: 'request-A', result: { success: true } }), false);
    } else {
      await assert.rejects(promise, /own|retired|abort|already in use|cancellation/i);
      if (change === 'abort-pending' || change === 'retired-before-response') {
        assert.equal(router.cancelled, 1);
        assert.equal(removed, 1);
      } else assert.equal(dispatched, 0);
    }
  });
}

await check('mutation control: account-switch test detects removed account comparison', async () => {
  const fixture = threadFixture('account');
  const source = select('readLocalTaskThread').code;
  const pattern = /if\([^)]*accountId[^)]*userId[^)]*\)throw Error\([^)]*\);/g;
  const matches = source.match(pattern);
  assert.equal(matches?.length, 1, 'Build adapter must identify exactly one account guard');
  const changed = source.replace(pattern, '');
  const mutant = vm.runInNewContext(`({${changed}}).readLocalTaskThread`, { Error, DOMException, ...fixture.bindings }, { timeout: 1000 });
  const result = await mutant.call(fixture.context, { environmentId: 'env-A', threadId: 'thread-A', limit: 20 });
  assert.equal(result.threadId, 'thread-A', 'The removed-guard mutant should survive the account switch, demonstrating test sensitivity');
}, 'mutation-sensitivity');

const browserFunctionsPresent = methods.some(m => m.name === 'wce') && methods.some(m => m.name === 'Y6');
if (browserFunctionsPresent) {
  const trusted = generateKeyPairSync('ed25519'), other = generateKeyPairSync('ed25519');
  const encodedPublicKey = trusted.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  for (const change of ['none', 'wrong-signature', 'wrong-signing-key', 'wrong-domain', 'wrong-session', 'wrong-turn', 'wrong-executor', 'wrong-nonce', 'denied', 'extra-field', 'payload-not-string', 'missing-host-key']) {
    await check(`browser signed response: ${change}`, async () => {
      const request = { executorId: 'executor-A', sessionId: 'session-A', turnId: 'turn-A', nonce: 'synthetic-nonce-A' };
      let closed = 0;
      const method = declaration('wce', {
        zR: 'pipe', KR: 'key', YR: 'codex.browserAccess.v1', gce: createPublicKey, yce: verify,
        Wo: { create: async () => ({ close: async () => { closed++; } }) },
        Yx: class { async read() {
          const echoed = { ...request };
          if (change === 'wrong-session') echoed.sessionId = 'session-B';
          if (change === 'wrong-turn') echoed.turnId = 'turn-B';
          if (change === 'wrong-executor') echoed.executorId = 'executor-B';
          if (change === 'wrong-nonce') echoed.nonce = 'synthetic-nonce-B';
          const payloadObject = { domain: change === 'wrong-domain' ? 'other-domain' : 'codex.browserAccess.v1', request: echoed, allowed: change !== 'denied' };
          if (change === 'extra-field') payloadObject.extra = true;
          const payload = JSON.stringify(payloadObject);
          const signature = change === 'wrong-signature' ? Buffer.alloc(64).toString('base64') : sign(null, Buffer.from(payload), change === 'wrong-signing-key' ? other.privateKey : trusted.privateKey).toString('base64');
          return { payload: change === 'payload-not-string' ? payloadObject : payload, signature };
        } },
      });
      const promise = method({ env: { pipe: 'synthetic-pipe', key: change === 'missing-host-key' ? undefined : encodedPublicKey } }, request);
      if (change === 'none') await promise;
      else await assert.rejects(promise, /authenticate|disabled|unavailable/);
      assert.equal(closed, change === 'missing-host-key' ? 0 : 1);
    });
  }
  await check('browser access cache: new session or turn creates a fresh nonce-bound request', async () => {
    const requests = [], runtime = { env: { executor: 'executor-A' }, meta: { session_id: 'session-A', turn_id: 'turn-A' } };
    const factory = declaration('Y6', { VR: 'executor', Ne: x => x.meta, bce: randomBytes, wce: async (_runtime, request) => { requests.push(request); } });
    const gate = factory(runtime);
    await gate(); await gate();
    assert.equal(requests.length, 1);
    runtime.meta.turn_id = 'turn-B'; await gate();
    runtime.meta.session_id = 'session-B'; await gate();
    assert.equal(requests.length, 3);
    assert.equal(new Set(requests.map(r => r.nonce)).size, 3);
    assert.ok(requests.every(r => /^[a-f0-9]{64}$/.test(r.nonce)));
  });
  await check('browser access cache: missing current turn rejected', async () => {
    const factory = declaration('Y6', { VR: 'executor', Ne: x => x.meta, bce: randomBytes, wce: async () => { throw new Error('should not send'); } });
    const gate = factory({ env: { executor: 'executor-A' }, meta: { session_id: 'session-A' } });
    await assert.rejects(gate(), /current turn/);
  });
  await check('browser access cache: same-turn grant is cached', async () => {
    let checks = 0, allowed = true;
    const runtime = { env: { executor: 'executor-A' }, meta: { session_id: 'session-A', turn_id: 'turn-A' } };
    const factory = declaration('Y6', { VR: 'executor', Ne: x => x.meta, bce: randomBytes, wce: async () => { checks++; if (!allowed) throw new Error('synthetic access revoked'); } });
    const gate = factory(runtime);
    await gate(); allowed = false; await gate();
    assert.equal(checks, 1);
    runtime.meta.turn_id = 'turn-B';
    await assert.rejects(gate(), /revoked/);
    assert.equal(checks, 2);
  }, 'scope-observation');
  await check('browser access cache: missing executor context skips this local gate', async () => {
    let checks = 0;
    const factory = declaration('Y6', { VR: 'executor', Ne: x => x.meta, bce: randomBytes, wce: async () => { checks++; } });
    await factory({ env: {}, meta: {} })();
    assert.equal(checks, 0);
  }, 'scope-observation');
  await check('browser access gate: mutable metadata can change while proof is pending', async () => {
    const waiting = Promise.withResolvers(), requests = [];
    const runtime = { env: { executor: 'executor-A' }, meta: { session_id: 'session-A', turn_id: 'turn-A' } };
    const factory = declaration('Y6', { VR: 'executor', Ne: x => x.meta, bce: randomBytes, wce: async (_runtime, request) => { requests.push(request); if (requests.length === 1) await waiting.promise; } });
    const gate = factory(runtime), pending = gate();
    runtime.meta.turn_id = 'turn-B';
    waiting.resolve(); await pending;
    assert.equal(requests[0].turnId, 'turn-A');
    await gate();
    assert.equal(requests[1].turnId, 'turn-B');
  }, 'scope-observation');
}

const report = {
  format: 'local-broker-boundary-scenarios', format_version: 1,
  artifact_sha256: SUPPORTED_ARCHIVE,
  browser_plugin_sha256: browserFunctionsPresent ? adapter.javascript_file_sha256 : null,
  harness_version: '0.1.0',
  execution: 'Selected shipped JavaScript functions with synthetic dependency adapters; application bootstrap, live broker, filesystem operations, browser, user state and network were not invoked by the tested functions.',
  dependencies: 'Version-specific module aliases and surrounding services are mocked. This tests local control flow, not end-to-end product security.',
  methods: [...used.values()].map(m => ({ name: m.name, owner_class: m.class?.name ?? null, member: m.member, source_sha256: m.source_sha256, start_utf16: m.start_utf16, end_utf16: m.end_utf16, snippet_sha256: createHash('sha256').update(m.code).digest('hex') })),
  passed: results.filter(r => r.passed).length, failed: results.filter(r => !r.passed).length,
  results,
  conclusions: [
    'The tested guards reject synthetic account/auth/catalog/executor changes, cancellation, mismatched renderer identity and completed turns.',
    'Reading another synthetic native thread in the same account/executor is supported by the isolated method; caller-thread entitlement is not established here.',
    'No live cross-account or expired-permission bypass has been demonstrated.',
  ],
  not_tested: ['Native task/workspace signed payload verification', 'Real account switch teardown', 'Remote service grants and clock expiry', 'All dynamic tool implementations', 'Already-running process permission revocation'],
  qualifications: [
    'Browser-session preparation may already have begun before a post-await revocation check returns false. The test does not demonstrate rollback or process termination.',
    'The response schema validator is mocked; the router test checks rejection propagation, not the actual product schema.',
    'The missing-turn case holds context lookup and downstream executor mocks permissive. It establishes wrapper behavior only.',
    'The mutable-metadata case is counterfactual. Follow-up worker inspection and integration show cloned, deeply frozen, async-local metadata hidden from retired calls; it does not establish a reachable task-switch race.',
    'Method hashes are pinned to the reviewed local extraction. These are consistency checks, not independent vendor-authenticity verification.',
    'Browser receipt tests use real Ed25519 cryptography and the selected verifier with synthetic transport. Live browser authorization and same-turn settings-revocation propagation were not tested.',
  ],
};
const content = JSON.stringify(report, null, 2) + '\n';
if (options.out) await writeFile(options.out, content, { flag: 'wx' });
else process.stdout.write(content);
console.error(JSON.stringify({ passed: report.passed, failed: report.failed }));
if (report.failed) process.exitCode = 1;
