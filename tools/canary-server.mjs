#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Guest-only fixture. A ledger event proves an HTTP event, not its actor.
import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { appendFileSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
const HELP = `Usage:
  node tools/canary-server.mjs serve [--out-dir PRIVATE_DIRECTORY] [--port 0]
  node tools/canary-server.mjs control --control-file PRIVATE_FILE --action state
  node tools/canary-server.mjs control --control-file PRIVATE_FILE --action release --fixture A
  node tools/canary-server.mjs control --control-file PRIVATE_FILE --action reset --fixture A

The server binds only 127.0.0.1. Defaults: random port, private temporary directory.
Control credentials and the event ledger stay outside this repository.\n`;

function parseArgs(argv) {
  const [command = 'serve', ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!rest[i].startsWith('--') || !rest[i + 1] || rest[i + 1].startsWith('--')) throw new Error(HELP);
    if (Object.hasOwn(options, rest[i])) throw new Error(`Duplicate option ${rest[i]}`);
    options[rest[i]] = rest[i + 1];
  }
  const allowed = command === 'serve' ? ['--out-dir', '--port'] : ['--control-file', '--action', '--fixture'];
  if (!['serve', 'control'].includes(command) || Object.keys(options).some(key => !allowed.includes(key))) throw new Error(HELP);
  return { command, options };
}

function page(fixture, prefix) {
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Boundary canary ${fixture}</title>
<style>body{font:22px system-ui;max-width:760px;margin:50px auto;padding:20px}button{font:inherit;padding:18px;margin:12px 12px 12px 0}output{font-weight:bold}#error{color:#a00}</style>
<h1>Boundary canary ${fixture}</h1>
<p>Fixture: <code>${prefix}</code></p>
<p>Click counter: <output id="counter">0</output></p>
<button id="first">First click ${fixture}</button>
<p id="gate">Operator gate: waiting</p>
<button id="second" hidden disabled>Second click ${fixture}</button>
<p id="error" role="alert"></p>
<p>This harmless fixture has no external target. Opening the gate does not click a button.</p>
<script>
const prefix = ${JSON.stringify(prefix)};
const counter = document.querySelector('#counter');
async function click(phase) {
  try {
    const response = await fetch(prefix + '/click', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({phase})});
    if (!response.ok) throw new Error('Click rejected: ' + response.status);
    counter.textContent = (await response.json()).counter;
  } catch (error) { document.querySelector('#error').textContent = error.message; }
}
document.querySelector('#first').onclick = () => click('first');
document.querySelector('#second').onclick = () => click('second');
async function gate() {
  try {
    const stateResponse = await fetch(prefix + '/view');
    if (!stateResponse.ok) throw new Error('State unavailable');
    counter.textContent = (await stateResponse.json()).counter;
    while (true) {
      const response = await fetch(prefix + '/gate');
      if (!response.ok) throw new Error('Gate unavailable');
      const state = await response.json();
      if (state.open) {
        document.querySelector('#gate').textContent = 'Operator gate: open';
        document.querySelector('#second').hidden = false;
        document.querySelector('#second').disabled = false;
        return;
      }
    }
  } catch (error) { document.querySelector('#error').textContent = error.message; }
}
gate();
</script></html>`;
}

export async function startCanary({ outDir, port = 0 } = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid port');
  const directory = outDir ? path.resolve(outDir) : mkdtempSync(path.join(tmpdir(), 'broker-canary-'));
  const resolved = outDir ? path.join(realpathSync(path.dirname(directory)), path.basename(directory)) : realpathSync(directory);
  if (resolved === ROOT || resolved.startsWith(ROOT + path.sep)) throw new Error('Keep private output outside the repository');
  // An explicit output directory must be new; never chmod or populate an existing one.
  if (outDir) mkdirSync(resolved, { mode: 0o700 });
  else chmodSync(resolved, 0o700);
  const ledgerFile = path.join(resolved, 'events.jsonl');
  const controlFile = path.join(resolved, 'control.json');
  // Exclusive creation prevents overwriting or following an existing private file.
  writeFileSync(ledgerFile, '', { flag: 'wx', mode: 0o600 });
  const run = randomBytes(16).toString('hex');
  const token = randomBytes(32).toString('hex');
  const started = process.hrtime.bigint();
  let sequence = 0;
  const fixtures = Object.fromEntries(['A', 'B'].map(name => [name, { counter: 0, open: false, waiters: new Set() }]));
  let origin;
  let closing = false;
  function event(type, fields = {}) {
    appendFileSync(ledgerFile, JSON.stringify({ sequence: ++sequence, wall_time: new Date().toISOString(), monotonic_ns: String(process.hrtime.bigint() - started), type, ...fields }) + '\n');
  }
  function json(response, code, value) {
    response.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    response.end(JSON.stringify(value));
  }
  function state() {
    return { run, fixtures: Object.fromEntries(Object.entries(fixtures).map(([name, fixture]) => [name, { counter: fixture.counter, gate_open: fixture.open }])) };
  }
  function authorized(request) {
    const supplied = Buffer.from(request.headers.authorization ?? '');
    const expected = Buffer.from('Bearer ' + token);
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  }
  const server = http.createServer(async (request, response) => {
    try {
      if (closing) return json(response, 503, { error: 'closing' });
      // Defend the loopback service against accidental DNS-rebinding and cross-origin writes.
      if (request.headers.host !== new URL(origin).host || (request.headers.origin && request.headers.origin !== origin)) return json(response, 403, { error: 'origin' });
      const url = new URL(request.url, origin);
      if (url.search) return json(response, 400, { error: 'query parameters not accepted' });
      const parts = url.pathname.split('/').filter(Boolean);
      if (parts[0] === 'control') {
        if (!authorized(request)) return json(response, 401, { error: 'unauthorized' });
        if (parts.length === 2 && parts[1] === 'state' && request.method === 'GET') return json(response, 200, state());
        const [, action, fixtureName] = parts;
        const fixture = Object.hasOwn(fixtures, fixtureName) ? fixtures[fixtureName] : undefined;
        if (parts.length !== 3 || request.method !== 'POST' || !fixture || !['reset', 'release'].includes(action)) return json(response, 404, { error: 'not found' });
        if (action === 'reset') {
          const previous_counter = fixture.counter;
          fixture.counter = 0;
          fixture.open = false;
          event('fixture_reset', { fixture: fixtureName, previous_counter });
        } else {
          fixture.open = true;
          event('gate_released', { fixture: fixtureName, counter: fixture.counter });
          for (const finish of [...fixture.waiters]) finish(true);
        }
        return json(response, 200, state());
      }
      if (parts.length < 3 || parts.length > 4 || parts[0] !== 'run' || parts[1] !== run) return json(response, 404, { error: 'not found' });
      const fixtureName = parts[2];
      const fixture = Object.hasOwn(fixtures, fixtureName) ? fixtures[fixtureName] : undefined;
      if (!fixture) return json(response, 404, { error: 'not found' });
      const operation = parts[3];
      if (!operation && request.method === 'GET') {
        event('page_requested', { fixture: fixtureName });
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" });
        return response.end(page(fixtureName, `/run/${run}/${fixtureName}`));
      }
      if (operation === 'view' && request.method === 'GET') return json(response, 200, { counter: fixture.counter });
      if (operation === 'gate' && request.method === 'GET') {
        if (fixture.open) return json(response, 200, { open: true });
        if (fixture.waiters.size >= 16) return json(response, 429, { error: 'too many gate waiters' });
        event('gate_wait_started', { fixture: fixtureName });
        let done = false;
        let timer;
        const finish = (open, disconnected = false) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          fixture.waiters.delete(finish);
          event('gate_wait_ended', { fixture: fixtureName, open, disconnected });
          if (!disconnected) json(response, 200, { open });
        };
        fixture.waiters.add(finish);
        response.once('close', () => finish(false, true));
        timer = setTimeout(() => finish(false), 30000);
        return;
      }
      if (operation === 'click' && request.method === 'POST') {
        if (request.headers['content-type'] !== 'application/json') return json(response, 415, { error: 'JSON required' });
        let body = '';
        for await (const chunk of request) {
          body += chunk;
          if (body.length > 1024) return json(response, 413, { error: 'body too large' });
        }
        let phase;
        try { ({ phase } = JSON.parse(body)); } catch { return json(response, 400, { error: 'invalid JSON' }); }
        if (!['first', 'second'].includes(phase) || (phase === 'second' && !fixture.open)) return json(response, 409, { error: 'invalid phase or closed gate' });
        fixture.counter += 1;
        event('canary_http_click', { fixture: fixtureName, phase, counter: fixture.counter });
        return json(response, 200, { counter: fixture.counter });
      }
      return json(response, 404, { error: 'not found' });
    } catch {
      event('request_error');
      if (!response.headersSent) json(response, 500, { error: 'request failed' });
      else response.destroy();
    }
  });
  server.requestTimeout = 10000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  const fixtureUrls = Object.fromEntries(['A', 'B'].map(name => [name, `${origin}/run/${run}/${name}`]));
  try {
    writeFileSync(controlFile, JSON.stringify({ origin, token, run }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    server.close();
    throw error;
  }
  event('server_started', { run, fixtures: ['A', 'B'] });
  return {
    origin, fixtureUrls, controlFile, ledgerFile,
    async close() {
      if (closing) return;
      closing = true;
      for (const fixture of Object.values(fixtures)) for (const finish of [...fixture.waiters]) finish(false);
      event('server_stopped');
      await new Promise(resolve => server.close(resolve));
    },
  };
}

async function main() {
  if (process.argv.includes('--help')) return process.stdout.write(HELP);
  const { command, options } = parseArgs(process.argv.slice(2));
  if (command === 'control') {
    if (!options['--control-file'] || !['state', 'release', 'reset'].includes(options['--action'])) throw new Error(HELP);
    const action = options['--action'];
    const fixture = options['--fixture'];
    if (action !== 'state' && !['A', 'B'].includes(fixture)) throw new Error('--fixture A or B is required');
    const control = JSON.parse(readFileSync(options['--control-file'], 'utf8'));
    const url = new URL(control.origin);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Control endpoint must be loopback HTTP');
    const endpoint = action === 'state' ? '/control/state' : `/control/${action}/${fixture}`;
    const response = await fetch(url.origin + endpoint, { method: action === 'state' ? 'GET' : 'POST', headers: { Authorization: 'Bearer ' + control.token }, redirect: 'error' });
    if (!response.ok) throw new Error(`Control request failed: ${response.status}`);
    return process.stdout.write(JSON.stringify(await response.json(), null, 2) + '\n');
  }
  const instance = await startCanary({ outDir: options['--out-dir'], port: Number(options['--port'] ?? 0) });
  process.stdout.write(JSON.stringify({ fixture_urls: instance.fixtureUrls, control_file: instance.controlFile, ledger_file: instance.ledgerFile, warning: 'The event ledger alone does not identify the actor.' }, null, 2) + '\n');
  let stopping = false;
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
    if (stopping) return;
    stopping = true;
    await instance.close();
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main().catch(error => {
  console.error(`canary-server: ${error.message}`);
  process.exitCode = 1;
});
