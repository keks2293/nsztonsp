#!/usr/bin/env node
// Progress protocol test for the update pipeline (real Stardew base + update NSZ):
// each path reports per-phase fractions (p in [0,1], stable phase label, phase byte
// total), monotonic within a phase, each phase ends at exactly 1.0 — so the bar can
// never regress across phases. Phases: two-pass (own-BKTR) = 'Reading BKTR tables... (1/3)'
// (own denominator: the prefix decompression to the tables) + 'Computing contentId
// (2/3)' (2×exefs + data region) + 'Writing output (3/3)',
// auto/scatter (the default on a readable output) = 'Writing output (1/1)' only —
// no prep phase, the update streams via NczStreamSource inside the write, buffered =
// 'Computing contentId (1/2)' + 'Writing output (2/2)'). The whole-section prep pass
// ('Reading update sections...') exists only on the explicit two-pass/'seekback'
// route (extractNcaSections) — no longer the default, so not exercised here. Also
// re-verifies auto/scatter ≡ buffered byte-identity (the two-pass writes the
// self-contained own-BKTR NCA — a different format by design, #135; verified at
// merge level by test_twopass_sw_sim). Runs 5-7 force big allocations to fail
// (simulated ArrayBuffer ceiling) and check the buffer-feasibility preflight
// falls back to the default no-buffer route byte-identically. In-memory outputs
// only (no disk writes).
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { update } from '../fs/update.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

// Sequential writer with gap-fill, mirrors SWDownloader (adapter API: write(position, data)).
class SequentialWriter {
  #pos = 0;
  chunks = [];
  write(position, data) {
    const gap = position - this.#pos;
    if (gap > 0) this.chunks.push(new Uint8Array(gap));
    this.chunks.push(new Uint8Array(data));
    this.#pos = position + data.byteLength;
  }
  build() {
    const buf = new Uint8Array(this.#pos);
    let off = 0;
    for (const c of this.chunks) { buf.set(c, off); off += c.byteLength; }
    return buf;
  }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = () => {};

let failures = 0;
function assert(cond, msg) {
  if (cond) console.log(`  ok - ${msg}`);
  else { failures++; console.log(`  FAIL - ${msg}`); }
}

function checkProtocol(name, events, expectedLabels, buf) {
  console.log(`\n== ${name} (${events.length} progress events) ==`);
  const segments = [];
  for (const e of events) {
    const last = segments[segments.length - 1];
    if (last && last.label === e.label) last.events.push(e);
    else segments.push({ label: e.label, events: [e] });
  }
  const labels = segments.map(s => s.label);
  assert(labels.join(' | ') === expectedLabels.join(' | '), `phase order: ${labels.join(' -> ')}`);

  // Tail phase byte total must equal the sum of the non-Program, non-CNMT output members.
  const files = new PFS0(buf).getFiles();
  const cnmt = files.find(f => f.name.endsWith('.cnmt.nca'));
  const program = files.find(f => f.name.toLowerCase().endsWith('.nca') && f !== cnmt);
  const tailExpected = files.filter(f => f !== cnmt && f !== program).reduce((s, f) => s + f.size, 0);

  for (const s of segments) {
    const evs = s.events;
    assert(evs.length > 0, `${s.label}: events reported`);
    assert(evs.every(e => e.p >= 0 && e.p <= 1 + 1e-9), `${s.label}: p within [0,1]`);
    if (s.label.startsWith('Writing output')) {
      // The Program NCA (~699 MB) crosses ~10 stride boundaries on its way; a
      // pass that reports only the final _prog(1) (e.g. a progress gate that
      // never fires) would leave the UI frozen for the whole write.
      assert(evs.length >= 5, `${s.label}: multiple events across the phase (got ${evs.length})`);
    }
    assert(evs.every((e, i) => i === 0 || evs[i - 1].p <= e.p + 1e-12), `${s.label}: monotonic within phase (program→tail continuity)`);
    assert(evs[evs.length - 1].p === 1, `${s.label}: phase ends at exactly 1.0 (got ${evs[evs.length - 1].p})`);
    assert(evs.every(e => typeof e.phaseBytes === 'number' && e.phaseBytes > 0), `${s.label}: phaseBytes reported`);
    assert(new Set(evs.map(e => e.phaseBytes)).size === 1, `${s.label}: phaseBytes constant within phase`);
    const bytes = evs[0].phaseBytes;
    if (s.label === 'Writing output (2/2)' || s.label === 'Writing output (3/3)') {
      assert(bytes === program.size + tailExpected, `${s.label}: phaseBytes (${bytes}) == Program NCA (${program.size}) + tail (${tailExpected})`);
    } else if (s.label === 'Writing output (1/1)') {
      // streaming phase = exefs + romfs writes + full-NCA re-read + tail
      assert(bytes > program.size + tailExpected, `${s.label}: phaseBytes (${bytes}) > Program NCA + tail (${program.size + tailExpected}) (re-read included)`);
    }
  }
  // The read-only pass-1 phase (two-pass only) does more work than the write phase.
  const p1 = segments.find(s => s.label.startsWith('Computing contentId'));
  const p2 = segments.find(s => s.label.startsWith('Writing output'));
  if (p1 && p2) {
    assert(p1.events[0].phaseBytes > p2.events[0].phaseBytes,
      `pass-1 phaseBytes (${p1.events[0].phaseBytes}) > write phase (${p2.events[0].phaseBytes})`);
  }
}

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

// Run 1: default auto route (memory output has read-back → scatter, 1 phase)
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const res = await update([base, upd], { memory: true }, {
    keys, log, bktrMerge: true,
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = new Uint8Array(await res.blob.arrayBuffer());
  // Auto → scatter on a readable output: no extract-sections prep phase, the
  // whole run is one 'Writing output (1/1)' phase (tables/patch reads inside it).
  checkProtocol('auto/scatter (memory, default)', events, ['Writing output (1/1)'], buf);
  globalThis.__refSha = sha(buf);
  globalThis.__refLen = buf.length;
}

// Run 2: two-pass (sequential writer, no read-back → appendOnly, 3 phases)
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const sw = new SequentialWriter();
  await update([base, upd], { writable: sw }, {
    keys, log, bktrMerge: true,
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = sw.build();
  // The own-BKTR two-pass (post-#135) has NO 'Reading update sections...' prep
  // (update.js:621 streams ExeFS one-shot instead of extractNcaSections); its
  // Pass 1 opens with the tables phase — own denominator (tableReadEnd), ends
  // at exactly 1.0 — then the compute phase starts at 0 on its own scale.
  checkProtocol('two-pass (sw-sim, appendOnly)', events, ['Reading BKTR tables... (1/3)', 'Computing contentId (2/3)', 'Writing output (3/3)'], buf);

  console.log(`\nauto/scatter sha256=${globalThis.__refSha} (${globalThis.__refLen})`);
  console.log(`two-pass     sha256=${sha(buf)} (${buf.length})`);
  globalThis.__twoPassSha = sha(buf);
  // NOTE: scatter ≡ two-pass byte-compare dropped — post-#135 the two-pass
  // emits a SELF-CONTAINED own-BKTR Program NCA (701,833,488 B) while the
  // scatter/buffered paths write the plaintext-merged NCA (701,770,512 B);
  // the formats differ by design. Two-pass bytes are verified at merge level
  // by test_twopass_sw_sim.mjs; scatter ≡ buffered is checked in run 3.
}

// Run 3: buffered (sequential writer + updateMode 'buffered' → 1 merge into
// memory, 2 phases) — verifies the buffered path's phase protocol AND that
// buffered output is byte-identical to the streaming reference (this is the
// append-only combination the browser SW download uses with the Buffered pill).
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const sw = new SequentialWriter();
  await update([base, upd], { writable: sw }, {
    keys, log, bktrMerge: true, updateMode: 'buffered',
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = sw.build();
  checkProtocol('buffered (sw-sim, appendOnly)', events, ['Computing contentId (1/2)', 'Writing output (2/2)'], buf);
  console.log(`buffered  sha256=${sha(buf)} (${buf.length})`);
  assert(globalThis.__refSha === sha(buf) && globalThis.__refLen === buf.length, 'buffered ≡ auto/scatter byte-identical');
}

// Run 4: 'buffer-update' (BufferUpdate pill on SW/FSA) — extract the update
// sections into RAM (preflight-allocated) + base streamed, plain two-pass merge
// (NOT own-BKTR): a plaintext-merged NCA, so it must match runs 1/3 byte-for-byte.
{
  const events = [];
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
  const sw = new SequentialWriter();
  await update([base, upd], { writable: sw }, {
    keys, log, bktrMerge: true, updateMode: 'buffer-update',
    progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
  });
  base.reader.close(); upd.reader.close();
  const buf = sw.build();
  checkProtocol('buffer-update (sw-sim, extract + plain two-pass)', events,
    ['Reading update sections...', 'Computing contentId (1/2)', 'Writing output (2/2)'], buf);
  console.log(`buffer-update sha256=${sha(buf)} (${buf.length})`);
  assert(sha(buf) === globalThis.__refSha && buf.length === globalThis.__refLen,
    'buffer-update ≡ auto/scatter plaintext-merged byte-identical (run 1)');
}

// Runs 5-7: buffer-feasibility preflight fallback — force every allocation over
// 300 MB to fail (simulating the browser's ArrayBuffer ceiling) and verify that
// every buffered route disables the buffer, logs a warning, and completes on the
// default no-buffer route with the bytes of the corresponding reference run:
//   'buffered' (BufferNCA) on SW        → own-BKTR two-pass ≡ run 2
//   'two-pass' (BufferUpdate) on memory → scatter          ≡ run 1
//   'buffer-update' on SW               → own-BKTR two-pass ≡ run 2
// The patched constructor keeps Uint8Array.prototype (and inherits the statics),
// so `instanceof` and all typed-array behavior stay intact — only allocations
// over LIMIT throw, exactly like a real RangeError from the ceiling.
{
  const LIMIT = 300 * 1024 * 1024;
  const Orig = globalThis.Uint8Array;
  function PatchedCtor(...args) {
    if (typeof args[0] === 'number' && args[0] > LIMIT) {
      throw new RangeError('Array buffer allocation failed');
    }
    return new Orig(...args);
  }
  PatchedCtor.prototype = Orig.prototype;
  Object.setPrototypeOf(PatchedCtor, Orig);
  globalThis.Uint8Array = PatchedCtor;

  const out = {};
  try {
    // Run 5: SW + 'buffered' — the whole-NCA probe fails → warn → 'auto' → own-BKTR.
    {
      const logs = [], events = [];
      const base = { name: 'base.nsp', reader: new FileReader(basePath) };
      const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
      const sw = new SequentialWriter();
      await update([base, upd], { writable: sw }, {
        keys, bktrMerge: true, updateMode: 'buffered',
        log: (level, msg) => logs.push({ level, msg }),
        progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
      });
      base.reader.close(); upd.reader.close();
      Object.assign(out, { sw5: sw, logs5: logs, events5: events });
    }
    // Run 6: memory + 'two-pass' — the section probe fails → warn → 'auto' → scatter.
    {
      const logs = [], events = [];
      const base = { name: 'base.nsp', reader: new FileReader(basePath) };
      const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
      const res = await update([base, upd], { memory: true }, {
        keys, bktrMerge: true, updateMode: 'two-pass',
        log: (level, msg) => logs.push({ level, msg }),
        progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
      });
      base.reader.close(); upd.reader.close();
      Object.assign(out, { res6: res, logs6: logs, events6: events });
    }
    // Run 7: SW + 'buffer-update' — the section probe fails → warn → 'auto' → own-BKTR.
    {
      const logs = [], events = [];
      const base = { name: 'base.nsp', reader: new FileReader(basePath) };
      const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
      const sw = new SequentialWriter();
      await update([base, upd], { writable: sw }, {
        keys, bktrMerge: true, updateMode: 'buffer-update',
        log: (level, msg) => logs.push({ level, msg }),
        progress: (p, label, phaseBytes) => events.push({ p, label, phaseBytes }),
      });
      base.reader.close(); upd.reader.close();
      Object.assign(out, { sw7: sw, logs7: logs, events7: events });
    }
  } finally {
    globalThis.Uint8Array = Orig;
  }

  const buf5 = out.sw5.build();
  checkProtocol('buffer-fallback: buffered → own-BKTR (sw-sim, appendOnly)', out.events5,
    ['Reading BKTR tables... (1/3)', 'Computing contentId (2/3)', 'Writing output (3/3)'], buf5);
  assert(out.logs5.some(l => l.level === 'warn' && l.msg.includes('Buffer not possible')),
    'run5: "Buffer not possible" warning logged');
  assert(out.logs5.some(l => l.level === 'info' && l.msg.includes('own-BKTR')),
    'run5: auto route info (own-BKTR) logged');
  console.log(`fallback/buffered sha256=${sha(buf5)} (${buf5.length})`);
  assert(sha(buf5) === globalThis.__twoPassSha, 'run5: fallback ≡ own-BKTR two-pass (run 2) byte-identical');

  const buf6 = new Uint8Array(await out.res6.blob.arrayBuffer());
  checkProtocol('buffer-fallback: two-pass → scatter (memory)', out.events6,
    ['Writing output (1/1)'], buf6);
  assert(out.logs6.some(l => l.level === 'warn' && l.msg.includes('Buffer not possible')),
    'run6: "Buffer not possible" warning logged');
  console.log(`fallback/two-pass sha256=${sha(buf6)} (${buf6.length})`);
  assert(sha(buf6) === globalThis.__refSha && buf6.length === globalThis.__refLen,
    'run6: fallback ≡ auto/scatter (run 1) byte-identical');

  const buf7 = out.sw7.build();
  checkProtocol('buffer-fallback: buffer-update → own-BKTR (sw-sim, appendOnly)', out.events7,
    ['Reading BKTR tables... (1/3)', 'Computing contentId (2/3)', 'Writing output (3/3)'], buf7);
  assert(out.logs7.some(l => l.level === 'warn' && l.msg.includes('Buffer not possible')),
    'run7: "Buffer not possible" warning logged');
  console.log(`fallback/buffer-update sha256=${sha(buf7)} (${buf7.length})`);
  assert(sha(buf7) === globalThis.__twoPassSha, 'run7: fallback ≡ own-BKTR two-pass (run 2) byte-identical');
}

console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
