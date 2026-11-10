#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Extract selected inert JavaScript definitions embedded in a reviewed local binary.
// No native executable, embedded module, bootstrap, or selected function is run.
import { createHash } from 'node:crypto';
import { mkdir, open, realpath, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const PROFILE = Object.freeze({
  binarySha256: 'ea870d110c925156840f5d2c68bdcda81df3fb6d61c5b9879b3c78d9cd130bc5',
  embeddedStart: 11478022,
  embeddedEnd: 11492953,
  embeddedSha256: 'f1d24878a59743329e01ce8467d37eca1ed3cd62525fad3493525633d72e48b0',
});
const FUNCTION_NAMES = new Set(['createExecContext', 'createExecState', 'deepFreeze', 'isPlainObject']);

function usage() {
  return 'Usage: node tools/extract-worker-context.mjs --binary /local/node_repl --out /scratch/context.json\n' +
    'Supports the reviewed native executable fingerprint only. Output contains locally extracted source and must remain outside this repository.\n' +
    'Install @babel/parser here, or set BROKER_LAB_PARSER_ROOT to an existing parser package root.\n';
}

function argumentsOf(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--help' || key === '-h') return { help: true };
    if (!['--binary', '--out'].includes(key) || !argv[i + 1]) throw new Error(`Invalid argument: ${key}`);
    options[key.slice(2)] = argv[++i];
  }
  if (!options.binary || !options.out) throw new Error(usage());
  return options;
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

async function scratchDestination(output) {
  const repository = await realpath(path.resolve(import.meta.dirname, '..'));
  const requested = path.resolve(output);
  if (inside(repository, requested)) throw new Error('Choose scratch output outside this repository; embedded source must not be committed.');
  await mkdir(path.dirname(requested), { recursive: true });
  const canonicalParent = await realpath(path.dirname(requested));
  if (inside(repository, canonicalParent)) throw new Error('Scratch parent resolves inside this repository.');
  return path.join(canonicalParent, path.basename(requested));
}

function parserModule() {
  const root = process.env.BROKER_LAB_PARSER_ROOT;
  return root ? createRequire(path.join(path.resolve(root), 'package.json'))('@babel/parser') : require('@babel/parser');
}

function extract(ast, text) {
  const methods = [];
  const stack = [ast];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    const isFunction = node.type === 'FunctionDeclaration' && FUNCTION_NAMES.has(node.id?.name);
    const isMetadataGetter = node.type === 'ObjectMethod' && node.kind === 'get' && !node.computed && node.key?.name === 'requestMeta';
    if (isFunction || isMetadataGetter) {
      const name = isFunction ? node.id.name : 'requestMeta';
      const code = text.slice(node.start, node.end);
      methods.push({
        name,
        kind: node.type,
        accessor: isMetadataGetter ? 'get' : null,
        class: null,
        start_utf16: node.start,
        end_utf16: node.end,
        offset_unit: 'zero-based UTF-16 code units within embedded source, end exclusive',
        binary_start: PROFILE.embeddedStart + Buffer.byteLength(text.slice(0, node.start), 'utf8'),
        binary_end: PROFILE.embeddedStart + Buffer.byteLength(text.slice(0, node.end), 'utf8'),
        snippet_sha256: createHash('sha256').update(code).digest('hex'),
        code,
      });
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child && typeof child === 'object' && child.type) stack.push(child);
      } else if (value && typeof value === 'object' && value.type) stack.push(value);
    }
  }
  const expected = [...FUNCTION_NAMES, 'requestMeta'];
  for (const name of expected) {
    if (methods.filter(method => method.name === name).length !== 1) throw new Error(`Expected exactly one ${name} definition in reviewed embedded runtime.`);
  }
  return methods.sort((a, b) => a.start_utf16 - b.start_utf16);
}

async function main() {
  const options = argumentsOf(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage()); return; }
  const destination = await scratchDestination(options.out);
  const binary = await realpath(path.resolve(options.binary));
  const handle = await open(binary, 'r');
  let before, after, bytes;
  try {
    before = await handle.stat();
    if (!before.isFile() || before.size > 64 * 1024 * 1024) throw new Error('Expected a regular native executable of at most 64 MiB.');
    bytes = await handle.readFile();
    after = await handle.stat();
  } finally { await handle.close(); }
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== before.size) throw new Error('Binary changed during inspection; output not published.');
  const binarySha256 = createHash('sha256').update(bytes).digest('hex');
  if (binarySha256 !== PROFILE.binarySha256) throw new Error('Unsupported binary fingerprint; review a new extraction profile before proceeding.');
  const embedded = bytes.subarray(PROFILE.embeddedStart, PROFILE.embeddedEnd);
  const embeddedSha256 = createHash('sha256').update(embedded).digest('hex');
  if (embeddedSha256 !== PROFILE.embeddedSha256) throw new Error('Embedded runtime range differs from reviewed fingerprint.');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(embedded);
  const methods = extract(parserModule().parse(text, { sourceType: 'script' }), text);
  const output = {
    format: 'local-node-repl-context-extraction', format_version: 1,
    captured_at_utc: new Date().toISOString(),
    source: { kind: 'native-embedded-javascript', path: binary, sha256: binarySha256, hash_scope: 'full-file' },
    isolation: 'Inert AST extraction; native executable, module/bootstrap and selected definitions were not executed.',
    redistribution: 'Contains local application source. Keep this scratch output outside the publication repository.',
    sources: [{
      member: 'worker-runtime.js', sha256: embeddedSha256,
      binary_start: PROFILE.embeddedStart, binary_end: PROFILE.embeddedEnd,
      size_bytes: embedded.length, methods,
    }],
  };
  await writeFile(destination, JSON.stringify(output, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ output: destination, definitions: methods.length, binary_sha256: binarySha256, embedded_sha256: embeddedSha256 }) + '\n');
}

main().catch(error => { process.stderr.write(`extract-worker-context: ${error.message}\n`); process.exitCode = 1; });
