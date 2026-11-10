#!/usr/bin/env node
/* SPDX-License-Identifier: MIT
 * Parse caller-selected local JavaScript and extract named inert functions.
 * No import, application module, bootstrap, or extracted function is executed.
 */
import { createHash } from 'node:crypto';
import { mkdir, open, realpath, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const MAX_BYTES = 16 * 1024 * 1024;

function usage() {
  return 'Usage: node tools/extract-local-functions.mjs --file /local/script.mjs [--function name] [--method name] --out /scratch/functions.json\n' +
    'The output contains local source snippets and must remain outside this repository.\n' +
    'Install @babel/parser here, or set BROKER_LAB_PARSER_ROOT to a directory from which it can be required.\n';
}

function argumentsOf(argv) {
  const result = { functions: new Set(), methods: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--help' || key === '-h') return { help: true };
    if (!['--file', '--function', '--method', '--out'].includes(key) || !argv[i + 1]) throw new Error(`Invalid argument: ${key}`);
    const value = argv[++i];
    if (key === '--function') result.functions.add(value);
    else if (key === '--method') result.methods.add(value);
    else result[key.slice(2)] = value;
  }
  if (!result.file || !result.out || result.functions.size + result.methods.size === 0) throw new Error(usage());
  return result;
}

function inside(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

async function scratchDestination(output) {
  const repository = await realpath(path.resolve(import.meta.dirname, '..'));
  const requested = path.resolve(output);
  if (inside(repository, requested)) throw new Error('Choose a scratch output outside this repository; local source snippets must not be committed.');
  await mkdir(path.dirname(requested), { recursive: true });
  const parent = await realpath(path.dirname(requested));
  if (inside(repository, parent)) throw new Error('The scratch parent resolves inside this repository; choose an external directory.');
  return path.join(parent, path.basename(requested));
}

function parserModule() {
  const root = process.env.BROKER_LAB_PARSER_ROOT;
  return root ? createRequire(path.join(path.resolve(root), 'package.json'))('@babel/parser') : require('@babel/parser');
}

function extract(ast, source, names, methodNames) {
  const methods = [];
  const stack = [ast];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    const functionMatch = node.type === 'FunctionDeclaration' && names.has(node.id?.name);
    const methodMatch = ['ObjectMethod','ClassMethod'].includes(node.type) && methodNames.has(node.key?.name);
    if (functionMatch || methodMatch) {
      methods.push({
        name: functionMatch ? node.id.name : node.key.name, kind: node.type, class: null,
        start_utf16: node.start, end_utf16: node.end,
        offset_unit: 'zero-based UTF-16 code units, end exclusive',
        code: source.slice(node.start, node.end),
      });
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child && typeof child === 'object' && child.type) stack.push(child);
      } else if (value && typeof value === 'object' && value.type) stack.push(value);
    }
  }
  methods.sort((a, b) => a.start_utf16 - b.start_utf16);
  const found = new Set(methods.map(method => method.name));
  const missing = [...names, ...methodNames].filter(name => !found.has(name));
  if (missing.length) throw new Error(`Requested function declarations not found: ${missing.join(', ')}`);
  return methods;
}

async function main() {
  const options = argumentsOf(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage()); return; }
  const destination = await scratchDestination(options.out);
  const file = await realpath(path.resolve(options.file));
  const handle = await open(file, 'r');
  let before, after, bytes;
  try {
    before = await handle.stat();
    if (!before.isFile() || before.size > MAX_BYTES) throw new Error('Choose a regular JavaScript file of at most 16 MiB.');
    bytes = await handle.readFile();
    after = await handle.stat();
  } finally { await handle.close(); }
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== before.size) throw new Error('Source changed during inspection; output not published.');
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const parser = parserModule();
  const ast = parser.parse(source, { sourceType: 'unambiguous' });
  const methods = extract(ast, source, options.functions, options.methods);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const output = {
    format: 'local-broker-function-extraction', format_version: 1,
    captured_at_utc: new Date().toISOString(),
    source: { kind: 'javascript-file', path: file, sha256, hash_scope: 'full-file' },
    isolation: 'Inert syntax only; modules, bootstrap, and functions were not executed.',
    redistribution: 'This scratch output contains locally extracted code. Do not commit or redistribute it with the original audit tools.',
    sources: [{ member: path.basename(file), size_bytes: bytes.length, sha256, methods }],
  };
  await writeFile(destination, JSON.stringify(output, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ output: destination, functions: methods.length, file_sha256: sha256 }) + '\n');
}

main().catch(error => { process.stderr.write(`extract-local-functions: ${error.message}\n`); process.exitCode = 1; });
