#!/usr/bin/env node
/* SPDX-License-Identifier: MIT
 * Extract inert methods from a caller-selected local ASAR for isolated tests.
 * This tool never loads an application module or invokes its bootstrap.
 */
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, mkdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const DEFAULT_METHODS = [
  'captureRequestLifetime', 'isRequestLifetimeCurrent', 'assertCurrent',
  'readLocalTaskThread', 'prepareChildTaskWorkspace', 'readLocalWorkBrowserAccess',
  'callDynamicAppTool', 'listChildTaskProjects', 'assignChildTaskProject',
  'readBrowserAccess', 'canCallTool', 'dispatchToolCall', 'cancelToolCall',
];

function usage() {
  return 'Usage: node tools/extract-local-methods.mjs --asar /path/app.asar --out /scratch/methods.json [--member archive/path.js] [--method name] [--function name] [--module name]\n' +
    'The output contains local proprietary snippets. Keep it outside the repository.\n' +
    'Install @babel/parser in this project, or set BROKER_LAB_PARSER_ROOT to a directory from which it can be required.\n';
}

function argsOf(argv) {
  const options = { members: [], methods: [], functions: [], modules: [] };
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (key === '--help' || key === '-h') return { help: true };
    if (!['--asar','--out','--member','--method','--function','--module'].includes(key) || !argv[i + 1]) throw new Error(`Invalid argument: ${key}`);
    const value = argv[++i];
    if (key === '--member') options.members.push(value);
    else if (key === '--method') options.methods.push(value);
    else if (key === '--function') options.functions.push(value);
    else if (key === '--module') options.modules.push(value);
    else options[key.slice(2)] = value;
  }
  if (!options.asar || !options.out) throw new Error(usage());
  options.methods = new Set(options.methods.length ? options.methods : DEFAULT_METHODS);
  options.functions = new Set(options.functions);
  options.modules = new Set(options.modules);
  return options;
}

function parserModule() {
  const root = process.env.BROKER_LAB_PARSER_ROOT;
  if (root) return createRequire(path.join(path.resolve(root), 'package.json'))('@babel/parser');
  return require('@babel/parser');
}

async function readExactly(handle, length, position) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const read = await handle.read(buffer, offset, length - offset, position + offset);
    if (!read.bytesRead) throw new Error('Truncated ASAR input');
    offset += read.bytesRead;
  }
  return buffer;
}

function inventory(header) {
  const result = [];
  const visit = (directory, prefix = '') => {
    for (const [name, entry] of Object.entries(directory.files ?? {})) {
      const logical = prefix + name;
      if (entry.files) visit(entry, logical + '/');
      else result.push({ logical, entry });
    }
  };
  visit(header);
  return result;
}

async function hashFile(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

function inside(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel));
}

async function scratchDestination(output) {
  const repository = await realpath(path.resolve(import.meta.dirname, '..'));
  const requested = path.resolve(output);
  if (inside(repository, requested)) throw new Error('Choose a scratch output outside this repository; extracted application snippets must not be committed.');
  await mkdir(path.dirname(requested), { recursive: true });
  // A lexical outside path can resolve through an ancestor symlink into this
  // repository. Check the existing canonical parent and use that canonical
  // path for publication, rather than following the requested spelling again.
  const parent = await realpath(path.dirname(requested));
  if (inside(repository, parent)) throw new Error('The scratch output parent resolves inside this repository; choose an external directory.');
  return path.join(parent, path.basename(requested));
}

function extractMethods(ast, source, wantedMethods, wantedFunctions, wantedModules) {
  const result = [];
  const stack = [{ node: ast, owner: null }];
  while (stack.length) {
    const { node, owner } = stack.pop();
    if (!node || typeof node !== 'object') continue;
    const currentOwner = ['ClassDeclaration', 'ClassExpression'].includes(node.type)
      ? { name: node.id?.name ?? null, start_utf16: node.start }
      : owner;
    const method = node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod';
    const fn = node.type === 'FunctionDeclaration';
    const module = node.type === 'ObjectMethod';
    const name = method || module ? node.key?.name ?? node.key?.value : fn ? node.id?.name : null;
    if (typeof name === 'string' && ((method && wantedMethods.has(name)) || (fn && wantedFunctions.has(name)) || (module && wantedModules.has(name)))) {
      result.push({
        name, kind: node.type, class: currentOwner,
        start_utf16: node.start, end_utf16: node.end,
        offset_unit: 'zero-based UTF-16 code units, end exclusive',
        code: source.slice(node.start, node.end),
      });
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (child && typeof child === 'object' && child.type) stack.push({ node: child, owner: currentOwner });
      } else if (value && typeof value === 'object' && value.type) stack.push({ node: value, owner: currentOwner });
    }
  }
  return result.sort((a,b) => a.start_utf16 - b.start_utf16);
}

async function main() {
  const options = argsOf(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage()); return; }
  const archive = path.resolve(options.asar);
  const destination = await scratchDestination(options.out);
  const parser = parserModule();
  const handle = await open(archive, 'r');
  const before = await handle.stat();
  let sources;
  try {
    const prefix = await readExactly(handle, 16, 0);
    const headerSize = prefix.readUInt32LE(4), jsonSize = prefix.readUInt32LE(12);
    if (prefix.readUInt32LE(0) !== 4 || headerSize < 8 || headerSize > 16 * 1024 * 1024 || jsonSize > headerSize - 8 || 8 + headerSize > before.size) throw new Error('Unsupported ASAR header');
    const header = JSON.parse((await readExactly(handle, jsonSize, 16)).toString('utf8'));
    const files = inventory(header);
    const selected = options.members.length
      ? options.members.map(logical => { const found = files.find(x => x.logical === logical); if (!found) throw new Error(`Missing archive member: ${logical}`); return found; })
      : files.filter(x => x.logical.startsWith('.vite/build/') && x.logical.endsWith('.js'));
    sources = [];
    for (const {logical, entry} of selected) {
      if (entry.unpacked || entry.link || entry.offset == null) throw new Error(`Selected member is not a packed ordinary file: ${logical}`);
      const size = entry.size, offset = Number(entry.offset), dataOffset = 8 + headerSize + offset;
      if (!Number.isSafeInteger(size) || size < 0 || size > 16 * 1024 * 1024 || !Number.isSafeInteger(offset) || offset < 0 || dataOffset + size > before.size) throw new Error(`Invalid or oversized selected member: ${logical}`);
      const bytes = await readExactly(handle, size, dataOffset);
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const digest = createHash('sha256').update(bytes).digest('hex');
      const ast = parser.parse(text, { sourceType: 'unambiguous' });
      sources.push({
        member: logical, size_bytes: size, archive_data_offset: dataOffset,
        sha256: digest,
        declared_integrity: entry.integrity ?? null,
        declared_sha256_matches: entry.integrity?.algorithm === 'SHA256' ? entry.integrity.hash === digest : null,
        methods: extractMethods(ast, text, options.methods, options.functions, options.modules),
      });
    }
  } finally { await handle.close(); }
  const archiveHash = await hashFile(archive);
  const check = await open(archive, 'r');
  let after;
  try { after = await check.stat(); } finally { await check.close(); }
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error('Archive changed during inspection; output not published');
  const output = {
    format: 'local-broker-method-extraction', format_version: 1,
    captured_at_utc: new Date().toISOString(),
    source: { archive_path: archive, sha256: archiveHash, hash_scope: 'full-file' },
    isolation: 'Inert syntax only; application bootstrap and modules were not executed.',
    redistribution: 'This scratch output contains locally extracted application code. Do not commit or redistribute it with the original audit tools.',
    sources,
  };
  await writeFile(destination, JSON.stringify(output, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ output: destination, members: sources.length, methods: sources.reduce((n,s) => n+s.methods.length,0), archive_sha256: archiveHash })+'\n');
}

main().catch(error => { process.stderr.write(`extract-local-methods: ${error.message}\n`); process.exitCode = 1; });
