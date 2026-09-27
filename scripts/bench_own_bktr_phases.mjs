// Phase-level baseline of the own-BKTR two-pass path (fs/bktr-pack.js) on the
// real Stardew NSZ files with a seekable-no-read output (browser FSA shape).
//
// The bench runs whichever layout the seekable branch currently emits:
//   - Tier-1 single-pass (this commit): Pass 1 = resolve/tables/build (no
//     contentId hash walk); Pass 2 = hdr-write / walk-write-hash / tl-write —
//     the merged write+hash walk (sha inline per adapter.write).
//   - two-pass (pre-Tier-1): Pass 1 adds sha-head / walk-hash / sha-tail;
//     Pass 2 reports walk-write.
// The summary block auto-detects the mode (no walk-hash phases ⇒ single-pass).
//
// Unlike test_twopass_fsa_sim.mjs this does NOT byte-compare (no merge
// reference) and uses a PREALLOCATED-doubling seekable writable: that test's
// FsaSim regrows the whole buffer on every write (O(n²) copies), which inflates
// the Pass-2 walk. Doubling makes adapter.write ≈ memcpy — the real-browser
// case. Output is an in-memory throwaway, never written to disk (AGENTS.md
// benchmark rules).
//
// Uses the phase hook (setBktrPhaseHook) in fs/bktr-pack.js: each phase reports
// { name, bytes, ms } plus cpuMs = wall time of the phase's inner hot op
// (sha.update / adapter.write). From that we split the data-region walk(s) into
// decompress+AES vs hash/write and measure the single-pass win over the old
// two-walk layout.
//
// Run: node scripts/bench_own_bktr_phases.mjs [runs=2]

import fs from 'fs';
import { performance } from 'perf_hooks';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';
import { openContainer } from '../fs/container.js';
import { NczStreamSource } from '../fs/range-source.js';
import { AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { setBktrPhaseHook } from '../fs/bktr-pack.js';

class FileReader {
  constructor(path) {
    this.path = path;
    this.fd = fs.openSync(path, 'r');
    this.size = fs.statSync(path).size;
  }
  async read(offset, size) {
    const buf = Buffer.alloc(size);
    fs.readSync(this.fd, buf, 0, size, offset);
    return buf;
  }
  close() { fs.closeSync(this.fd); }
}

// Seekable-no-read writable (FSA shape) with amortized-O(1) writes: the buffer
// cap doubles instead of growing by exactly `end` (FsaSim's O(n²) pathology).
class Writable {
  constructor() { this.pos = 0; this.data = null; this.cap = 0; this.ops = 0; this.written = 0; }
  async seek(pos) { this.pos = pos; }
  async write(entry) {
    const pos = entry.position;
    const view = entry.data;
    const end = pos + view.byteLength;
    if (!this.data || this.cap < end) {
      const cap2 = Math.max(this.cap * 2, end, 1 << 20);
      const nd = new Uint8Array(cap2);
      if (this.data) nd.set(this.data);
      this.data = nd;
      this.cap = cap2;
    }
    this.data.set(view, pos);
    this.pos = end;
    this.written += view.byteLength;
    this.ops += 1;
  }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const RUNS = process.argv.length > 2 ? parseInt(process.argv[2], 10) : 2;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const log = (level, msg) => { if (!process.env.QUIET) console.log(`[${level.toUpperCase()}] ${msg}`); };
const progress = () => {};

const baseReader = new FileReader(basePath);
const updateReader = new FileReader(updatePath);
const baseC = await openContainer({ reader: baseReader, name: 'base' });
const updC = await openContainer({ reader: updateReader, name: 'update' });
const pickProg = (c) => c.entries.filter(e => /\.ncz$/i.test(e.name) && !/\.cnmt\.ncz$/i.test(e.name)).sort((a, b) => b.size - a.size)[0];
const pickTik = async (c, r) => { const t = c.entries.find(e => e.name.toLowerCase().endsWith('.tik')); return t ? await r.read(t.offset, t.size) : null; };
const baseProg = pickProg(baseC);
const updProg = pickProg(updC);
const baseTik = await pickTik(baseC, baseReader);
const updateTik = await pickTik(updC, updateReader);
const params = { keys, baseTik, updateTik };
// Member-window readers (same discipline as test_twopass_fsa_sim.mjs).
const baseNcz = new AdapterNCZReader(baseReader, baseProg.offset, baseProg.size);
const updateNcz = new AdapterNCZReader(updateReader, updProg.offset, updProg.size);
const baseParsed = await parseNczSections(baseNcz);
const updateParsed = await parseNczSections(updateNcz);

const phases = [];
setBktrPhaseHook((p) => phases.push(p));

const readers = [
  { name: 'base.nsz', reader: baseReader },
  { name: 'update.nsz', reader: updateReader },
];

function fmtMB(ms, bytes) {
  if (!(ms > 0) || !(bytes > 0)) return '—';
  return `${(bytes / 1e6 / (ms / 1000)).toFixed(1)} MB/s`;
}

console.log(`\n=== own-BKTR two-pass phase baseline (${basePath.split('/').pop()} + ${updatePath.split('/').pop()}) ===\n`);

let best = null;
for (let run = 1; run <= RUNS; run++) {
  phases.length = 0;
  const w = new Writable();
  const t0 = performance.now();
  const result = await update(readers, { writable: w }, { keys, log, progress });
  const e2eMs = performance.now() - t0;

  const sum = (name) => phases.filter(p => p.name === name).reduce((s, p) => s + p.ms, 0);
  const cpu = (name) => phases.filter(p => p.name === name).reduce((s, p) => s + p.cpuMs, 0);
  // Phase sets cover BOTH layouts: the two-pass layout emitted sha-head /
  // walk-hash / sha-tail (Pass 1) and walk-write (Pass 2); the Tier-1
  // single-pass layout emits no sha phases and reports the merged write+hash
  // walk as 'walk-write-hash'.
  const pass1 = ['resolve', 'tables', 'build', 'sha-head', 'walk-hash', 'sha-tail'].map(n => [n, sum(n)]);
  const pass2 = ['hdr-write', 'walk-write', 'walk-write-hash', 'tl-write'].map(n => [n, sum(n)]);
  const p1Total = pass1.reduce((s, [, m]) => s + m, 0);
  const p2Total = pass2.reduce((s, [, m]) => s + m, 0);

  const info = { e2eMs, result, p1Total, p2Total,
    walkHash: sum('walk-hash'), walkHashCpu: cpu('walk-hash'),
    walkWrite: sum('walk-write') + sum('walk-write-hash'),
    walkWriteCpu: cpu('walk-write') + cpu('walk-write-hash'),
    shaHead: sum('sha-head'), shaHeadCpu: cpu('sha-head'),
  };

  console.log(`run ${run} — Product: ${result.size.toLocaleString()} bytes; e2e ${(e2eMs / 1000).toFixed(1)}s`);
  console.log(`  Pass 1 phases (sum ${(p1Total / 1000).toFixed(1)}s):`);
  for (const [n, m] of pass1) {
    const bytes = phases.find(p => p.name === n)?.bytes ?? 0;
    const c = cpu(n);
    if (m < 1) continue;
    console.log(`    ${n.padEnd(11)} ${(m / 1000).toFixed(2).padStart(6)}s  ${fmtMB(m, bytes).padStart(11)}  (cpu ${(c / 1000).toFixed(2)}s)`);
  }
  console.log(`  Pass 2 phases (sum ${(p2Total / 1000).toFixed(1)}s):`);
  for (const [n, m] of pass2) {
    const bytes = phases.find(p => p.name === n)?.bytes ?? 0;
    if (m < 1) continue;
    const c = cpu(n);
    console.log(`    ${n.padEnd(11)} ${(m / 1000).toFixed(2).padStart(6)}s  ${fmtMB(m, bytes).padStart(11)}  (cpu ${(c / 1000).toFixed(2)}s)`);
  }
  console.log(`  phases/Pass1+Pass2 = ${(((p1Total + p2Total) / 1000).toFixed(1))}s of e2e ${(e2eMs / 1000).toFixed(1)}s`);

  if (!best || e2eMs < best.e2eMs) best = info;
}

const b = best;
// No Pass-1 sha phases emitted ⇒ the Tier-1 single-pass layout ran.
const singlePass = b.walkHash === 0;
// Two-pass baseline (Stardew, best-of-3, pre-Tier-1 — CHANGELOG #137).
const BASELINE_P1 = 14.2; // s (tables 1.6 + build 2.0 + walk-hash 10.5 + misc)
const BASELINE_E2E = 24.8; // s
const wName = `walk-hash ${(b.walkHash / 1000).toFixed(1)}s (sha wall ${(b.walkHashCpu / 1000).toFixed(1)}s)   walk-write+hash ${(b.walkWrite / 1000).toFixed(1)}s (write wall ${(b.walkWriteCpu / 1000).toFixed(1)}s)`;
const decompressAES = b.walkWrite - b.walkWriteCpu;
console.log(`\n=== best-of-${RUNS} (lowest e2e ${(b.e2eMs / 1000).toFixed(1)}s) ===`);
console.log(`  Pass 1 phases sum: ${(b.p1Total / 1000).toFixed(1)}s   Pass 2 phases sum: ${(b.p2Total / 1000).toFixed(1)}s`);
if (singlePass) {
  console.log(`  MODE: Tier-1 single-pass (seekable) — Pass 1 = layout/tables/header only (no contentId hash walk)`);
  console.log(`  ${wName}`);
  console.log(`  merged walk: write+sha wall ${(b.walkWriteCpu / 1000).toFixed(1)}s, decompress+AES ≈ ${(decompressAES / 1000).toFixed(1)}s`);
  console.log(`  Pass 1 ${(b.p1Total / 1000).toFixed(1)}s (two-pass baseline ${BASELINE_P1}s — the hash walk is gone)`);
  console.log(`  e2e ${(b.e2eMs / 1000).toFixed(1)}s (two-pass baseline ${BASELINE_E2E}s) → ${(100 * (1 - b.e2eMs / 1000 / BASELINE_E2E)).toFixed(0)}% faster`);
} else {
  console.log(`  MODE: two-pass (pre-Tier-1) — separate Pass-1 contentId hash walk`);
  console.log(`  ${wName}`);
  console.log(`  walk-write decompress+AES ${(decompressAES / 1000).toFixed(1)}s`);
  console.log(`  sha-head ${(b.shaHead / 1000).toFixed(1)}s (exefs contentId hash wall ${(b.shaHeadCpu / 1000).toFixed(1)}s)`);
  const saved = Math.min(b.walkHash - b.walkHashCpu, decompressAES);
  const projected = b.e2eMs - saved;
  console.log(`  Tier-1 (single-pass write+hash, seekable) removes one walk's decompress+AES:`);
  console.log(`    saved ≈ ${(saved / 1000).toFixed(1)}s (${(100 * saved / b.e2eMs).toFixed(1)}% of e2e ${(b.e2eMs / 1000).toFixed(1)}s)`);
  console.log(`    projected e2e ≈ ${(projected / 1000).toFixed(1)}s (${(100 * (1 - projected / b.e2eMs)).toFixed(1)}% faster)`);
}
const nativeShaWall = (b.shaHeadCpu + b.walkHashCpu) / 1000; // wall SECONDS (Node native backend)
const shaScaleToJs = 1921 / 201; // measured on this machine: native vs pure-JS SHA256
console.log(`  [browser note] pure-JS SHA wall ≈ ${(nativeShaWall * shaScaleToJs).toFixed(1)}s vs ${nativeShaWall.toFixed(2)}s native${singlePass ? ' (contentId sha now inline in the merged walk)' : ''}.`);

for (const r of readers) r.reader.close();