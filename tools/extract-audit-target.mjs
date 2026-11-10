#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Select reviewed archive members/methods for the included build adapter.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node tools/extract-audit-target.mjs --asar /path/app.asar --out /scratch/methods.json');
  process.exit(0);
}
for (let i = 0; i < args.length; i += 2) {
  if (!['--asar', '--out'].includes(args[i]) || !args[i+1]) throw new Error('Expected --asar and --out arguments');
}
if (!args.includes('--asar') || !args.includes('--out')) throw new Error('Both --asar and --out are required');
const adapter = JSON.parse(readFileSync(new URL('../adapters/codex-macos-26.1103.60933-25894.json', import.meta.url), 'utf8'));
const members = [...new Set(adapter.methods.map(m => m.member))];
const methods = [...new Set(adapter.methods.map(m => m.name).filter(n => n !== 'EB' && n !== 'ysE7'))];
const selection = [...members.flatMap(m => ['--member', m]), ...methods.flatMap(m => ['--method', m]), '--function', 'EB', '--module', 'ysE7'];
const result = spawnSync(process.execPath, [fileURLToPath(new URL('./extract-local-methods.mjs', import.meta.url)), ...args, ...selection], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
