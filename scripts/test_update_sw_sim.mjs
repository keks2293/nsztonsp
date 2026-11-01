// Simulates the browser SW download path (sequential-only stream + gap-fill)
// and verifies the produced NSP is correct.
//
// There are TWO physically different Program NCA layouts, so byte-identity is
// only expected WITHIN a layout, not across layouts:
//
//   Layout A — plain (scatter): the merged RomFS is written in virtual order
//     as a plain IVFC section (CRYPT.NONE). Routes: fd 'auto' (scatter),
//     'buffered', memory output, explicit 'scatter' (fd + memory). All five
//     are byte-identical — same NCA bytes, same contentId.
//
//   Layout B — own-BKTR (SW two-pass, fs/bktr-pack.js): the Program NCA is
//     self-contained — its RomFS data region is re-laid out physically (patch
//     union intervals, then base union intervals) and carries its OWN reloc/sub
//     BKTR tables inside the RomFS section (fs-header crypt_type = BKTR).
//     Same data in a different byte order → different sha256 → different
//     contentId (the id IS the hash). Layout B can therefore NEVER be
//     byte-compared to Layout A; it is verified at the MERGE level (the same
//     pattern as test_twopass_fsa_sim.mjs): mergeRomFS(trivialBase,
//     producedNCA).mergedData == Layout A's RomFS data level, plus ExeFS
//     section equality and CNMT consistency.
//
// The original version of this test asserted byte-identity of ALL six outputs.
// That held until the own-BKTR writer landed (9a13281), when the SW route
// legitimately diverged; the fix for that commit was missed and landed here.
//
// Run: node scripts/test_update_sw_sim.mjs
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';
import { PFS0 } from '../fs/pfs0.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader, parseCnmtFromRawNca } from '../fs/nca.js';
import { BufferRangeSource } from '../fs/range-source.js';
import {
    decryptNcaHeaderBytes, fsHeaderAt, SECTION_FS_TYPE,
    FS_HDR, IVFC_LEVELS_OFFSET, IVFC_MAX_LEVEL, IVFC_LEVEL_HDR,
} from '../fs/nca-utils.js';
import { mergeRomFS } from '../fs/bktr-merge.js';
import { CNMT_ENTRY_TYPE } from '../fs/cnmt.js';
import { readLeU64 } from '../fs/bytes.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

// Mirrors SWDownloader: sequential, fills gaps with zeros, tracks position.
class SequentialWriter {
  #pos = 0;
  chunks = [];
  // Mirrors SWDownloader.write exactly (adapter API: write(position, data)).
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
const progress = () => {};
const logs = [];
const log = (level, msg) => { logs.push(msg); };
// Prove the lockstep base path is ACTUALLY taken per mode (not silently falling
// back to registerRange + read). markMode(label) opens a fresh log window;
// modeLogs records the per-mode window content for the route-specific checks.
let windowStart = 0;
const modeWindows = {};
const markMode = (label) => { windowStart = logs.length; };
const markWindow = (label) => { modeWindows[label] = logs.slice(windowStart); windowStart = logs.length; };

// FORCE_JS=1 runs the exact browser SHA-256 path (pure-JS streaming class);
// default runs the native node:crypto streaming backend. Both must MATCH.
if (process.env.FORCE_JS) {
  const { setForceJsSha256 } = await import('../crypto/sha256.js');
  setForceJsSha256(true);
  console.log('forcing pure-JS streaming SHA256 (browser path)');
}

const sha256 = (u8) => crypto.createHash('sha256').update(u8).digest('hex');
const check = (ok, what, detail = '') => {
  if (!ok) { console.log(`  FAIL ${what}${detail ? ' — ' + detail : ''}`); process.exitCode = 1; }
  else console.log(`  ok   ${what}`);
};

// Base Program NCA header (for the merge-level check of the SW route).
const baseHdrReader = new FileReader(basePath);
const baseC = await openContainer({ reader: baseHdrReader, name: 'base' });
const baseProgEntry = baseC.entries
  .filter(e => /\.ncz$/i.test(e.name) && !/\.cnmt\.ncz$/i.test(e.name))
  .sort((a, b) => b.size - a.size)[0];
const baseHeaderRaw = await baseHdrReader.read(baseProgEntry.offset, Math.min(baseProgEntry.size, 0xC00));
baseHdrReader.close();

// Reference: seekable fd output, 'auto' → scatter route (Layout A).
const refPath = '/tmp/update_sw_sim_ref.nsp';
const refFd = fs.openSync(refPath, 'w+');
markMode('ref');
await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  { fd: refFd }, { keys, log, progress, bktrMerge: true });
markWindow('ref');
fs.closeSync(refFd);
const ref = new Uint8Array(fs.readFileSync(refPath));

// SW-simulated: sequential writer with gap-fill (append-only → two-pass
// own-BKTR route, Layout B).
const sw = new SequentialWriter();
markMode('sim');
const result = await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  { writable: sw }, { keys, log, progress, bktrMerge: true });
markWindow('sim');
const sim = sw.build();

// Buffered mode (the browser "Buffer" pill): merged RomFS fully in memory.
const bufPath = '/tmp/update_sw_sim_buffered.nsp';
const bufFd = fs.openSync(bufPath, 'w+');
markMode('buffered');
await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  { fd: bufFd }, { keys, log, progress, bktrMerge: true, updateMode: 'buffered' });
markWindow('buffered');
fs.closeSync(bufFd);
const buf = new Uint8Array(fs.readFileSync(bufPath));

// In-memory output with read-back: the streaming scatter route (Layout A).
const memOut = { memory: true };
markMode('memory');
const mem = await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  memOut, { keys, log, progress, bktrMerge: true });
markWindow('memory');
const memBuf = new Uint8Array(await mem.blob.arrayBuffer());

// Scatter mode: fd output (seekable), updateMode='scatter' (Layout A).
const scatterPath = '/tmp/update_sw_sim_scatter.nsp';
const scatterFd = fs.openSync(scatterPath, 'w+');
markMode('scatter');
await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  { fd: scatterFd }, { keys, log, progress, bktrMerge: true, updateMode: 'scatter' });
markWindow('scatter');
fs.closeSync(scatterFd);
const scatter = new Uint8Array(fs.readFileSync(scatterPath));

// Scatter on a memory (blob) output (Layout A).
markMode('scatter-memory');
const memScatter = await update(
  [{ name: 'base.nsp', reader: new FileReader(basePath) }, { name: 'update.nsz', reader: new FileReader(updatePath) }],
  { memory: true }, { keys, log, progress, bktrMerge: true, updateMode: 'scatter' });
markWindow('scatter-memory');
const memScatterBuf = new Uint8Array(await memScatter.blob.arrayBuffer());

console.log(`\n=== RESULT (SW sim) ===`);
console.log('ref (fd, scatter)    :', ref.length, 'sha256=' + sha256(ref));
console.log('sim (sw, own-BKTR)   :', sim.length, 'sha256=' + sha256(sim));
console.log('buffered (fd)        :', buf.length, 'sha256=' + sha256(buf));
console.log('memory (streaming)   :', memBuf.length, 'sha256=' + sha256(memBuf));
console.log('scatter (fd)         :', scatter.length, 'sha256=' + sha256(scatter));
console.log('scatter (memory)     :', memScatterBuf.length, 'sha256=' + sha256(memScatterBuf));
console.log('result.size          :', result.size);

// ── Group A: same-layout (plain scatter) routes — byte-identical ────────────
{
  const groupA = [
    ['ref (fd auto)', 'ref', ref], ['buffered (fd)', 'buffered', buf],
    ['memory (streaming)', 'memory', memBuf], ['scatter (fd)', 'scatter', scatter],
    ['scatter (memory)', 'scatter-memory', memScatterBuf],
  ];
  const refSha = sha256(ref);
  for (const [label, , out] of groupA) {
    check(out.length === ref.length && sha256(out) === refSha,
      `${label}: byte-identical to ref`, `${out.length} vs ${ref.length}`);
  }
  for (const [label, key] of groupA) {
    check(modeWindows[key].some(m => /Base lockstep/.test(m)),
      `${label}: Base lockstep path taken`,
      modeWindows[key].filter(m => /lockstep/i.test(m)).join(' | ').slice(0, 200));
  }
}

// ── Group B: sim (SW two-pass own-BKTR) — merge-level equivalence ───────────
{
  console.log('\n=== SW own-BKTR route (Layout B) — merge-level checks ===');

  // Route sanity: the append-only output took the own-BKTR two-pass writer.
  check(modeWindows['sim'].some(m => /Two-pass own-BKTR/.test(m)),
    'sim: own-BKTR two-pass route taken');

  // PFS0.getFiles() returns ABSOLUTE offsets (relative + headerSize); the PFS0
  // header sits at file offset 0 in both files, so tails are 0.
  const refPfs = new PFS0(ref), simPfs = new PFS0(sim);
  const refEntries = refPfs.getFiles();
  const simEntries = simPfs.getFiles();
  check(simPfs.headerSize === refPfs.headerSize,
    `sim: PFS0 header size matches ref — ${simPfs.headerSize} vs ${refPfs.headerSize}`);
  check(simEntries.length === refEntries.length && simEntries.length === 4,
    `sim: PFS0 member count — ${simEntries.length} vs ${refEntries.length}`);

  const pickProg = (es) => es.filter(e => /\.nca$/i.test(e.name) && !/\.cnmt\.nca$/i.test(e.name))
    .sort((a, b) => b.size - a.size)[0];
  const pickCnmt = (es) => es.find(e => /\.cnmt\.nca$/i.test(e.name));
  const refProg = pickProg(refEntries), simProg = pickProg(simEntries);
  const refCnmtE = pickCnmt(refEntries), simCnmtE = pickCnmt(simEntries);
  const refOthers = refEntries.filter(e => e !== refProg && e !== refCnmtE);
  const simOthers = simEntries.filter(e => e !== simProg && e !== simCnmtE);

  // contentId self-consistency: the PFS0 name IS the sha256 prefix of the
  // written NCA (Pass-1 contentId == Pass-2 bytes).
  const simProgNca = sim.subarray(simProg.offset, simProg.offset + simProg.size);
  const simSha = sha256(simProgNca);
  check(simProg.name.toLowerCase().startsWith(simSha.slice(0, 32)),
    'sim: program name embeds sha256(written NCA)', `${simProg.name.slice(0, 32)} vs ${simSha.slice(0, 32)}`);
  check(result.size === sim.length, `sim: result.size ${result.size} === file ${sim.length}`);

  // PFS0 layout: same members as ref (same names/sizes, program excluded),
  // contiguous from offset 0, file ends at the last member.
  check(simOthers.length === refOthers.length &&
        simOthers.every((e, i) => e.name === refOthers[i].name && e.size === refOthers[i].size),
    'sim: non-program members match ref (names + sizes)',
    simOthers.map(e => e.name).join(', '));
  check(simCnmtE.size === refCnmtE.size,
    `sim: CNMT size matches ref — ${simCnmtE.size} vs ${refCnmtE.size}`);
  // PFS0 layout: the program is `delta` bytes larger (its own BKTR tables in
  // the RomFS section), so every later member is shifted by delta; the
  // container's inherited gaps (dropped delta fragments leave holes) are
  // preserved from the input layout, so contiguity is NOT expected.
  const delta = simProg.size - refProg.size;
  check(delta > 0, `sim: program NCA larger than ref (own BKTR tables) — +${delta}`,
    `${simProg.size} vs ${refProg.size}`);
  let layoutOk = simProg.offset === refProg.offset; // both right after the header
  for (let i = 1; i < simEntries.length; i++)
    layoutOk = layoutOk && simEntries[i].offset - delta === refEntries[i].offset;
  const endOf = (es) => { const l = es[es.length - 1]; return l.offset + l.size; };
  check(layoutOk, 'sim: PFS0 layout = ref layout shifted by the program delta (gaps preserved)',
    simEntries.map((e, i) => `${e.name.slice(0, 8)}@${(e.offset - (i ? delta : 0)).toString(16)}`).join(' '));
  check(endOf(refEntries) === ref.length && endOf(simEntries) === sim.length,
    'sim: file ends right after the last member (header at offset 0)',
    `sim end ${endOf(simEntries)} vs ${sim.length}; ref end ${endOf(refEntries)} vs ${ref.length}`);

  // Non-program NCAs are copied verbatim — byte-identical to ref's.
  for (const re of refOthers) {
    const se = simEntries.find(e => e.name === re.name);
    if (!se) { check(false, `sim: missing member ${re.name}`); continue; }
    check(sha256(sim.subarray(se.offset, se.offset + se.size)) === sha256(ref.subarray(re.offset, re.offset + re.size)),
      `sim: ${re.name} byte-identical to ref`);
  }

  // Program NCA sections: ExeFS is plaintext in both layouts (CRYPT.NONE) and
  // is the same update ExeFS — the whole section must be byte-identical.
  const refProgNca = ref.subarray(refProg.offset, refProg.offset + refProg.size);
  const refHdr = decryptNcaHeader(refProgNca.subarray(0, 0xC00), keys);
  const simHdr = decryptNcaHeader(simProgNca.subarray(0, 0xC00), keys);
  const refExe = refHdr.sections.find(s => s.fsType === SECTION_FS_TYPE.PFS0);
  const simExe = simHdr.sections.find(s => s.fsType === SECTION_FS_TYPE.PFS0);
  check(refExe && simExe && refExe.size === simExe.size &&
        sha256(refProgNca.subarray(refExe.offset, refExe.offset + refExe.size)) ===
        sha256(simProgNca.subarray(simExe.offset, simExe.offset + simExe.size)),
    'sim: ExeFS section byte-identical to ref',
    refExe && simExe ? `${refExe.size} vs ${simExe.size}` : 'missing section');

  // RomFS: ref's is the plain (virtual-order) merged data; sim's is own-BKTR
  // (physical order + own tables). Resolve sim's via mergeRomFS with a trivial
  // base (all its reloc entries are isPatch=1, so the base is never read) and
  // compare against ref's IVFC data level.
  const refRomSec = refHdr.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS);
  const refFh = fsHeaderAt(decryptNcaHeaderBytes(refProgNca.subarray(0, 0xC00), keys), refHdr.sections.indexOf(refRomSec));
  const lvlBase = IVFC_LEVELS_OFFSET + FS_HDR.HASH_DATA;
  const lvl = (IVFC_MAX_LEVEL - 1) * IVFC_LEVEL_HDR.SIZE;
  const dataLevelOffset = Number(readLeU64(refFh, lvlBase + lvl + IVFC_LEVEL_HDR.LOGICAL_OFFSET));
  const dataLevelSize = Number(readLeU64(refFh, lvlBase + lvl + IVFC_LEVEL_HDR.HASH_DATA_SIZE));
  const refRomfs = refProgNca.subarray(refRomSec.offset + dataLevelOffset, refRomSec.offset + dataLevelOffset + dataLevelSize);

  const simMerged = await mergeRomFS(
    { headerRaw: baseHeaderRaw, source: { read: async () => new Uint8Array(0) } },
    { headerRaw: simProgNca.subarray(0, 0xC00), source: BufferRangeSource(simProgNca) },
    { keys, log },
  );
  check(simMerged.dataLevelSize === dataLevelSize,
    `sim: merged RomFS size — ${simMerged.dataLevelSize} vs ${dataLevelSize}`);
  check(sha256(simMerged.mergedData) === sha256(refRomfs),
    `sim: merged RomFS byte-identical to ref's (same data, different order)`,
    sha256(simMerged.mergedData).slice(0, 16) + ' vs ' + sha256(refRomfs).slice(0, 16));

  // CNMT: same structure; the only differences may be the program entry's
  // hash (= contentId) and size.
  const refCnmt = (await parseCnmtFromRawNca(ref.subarray(refCnmtE.offset, refCnmtE.offset + refCnmtE.size), keys)).cnmt;
  const simCnmt = (await parseCnmtFromRawNca(sim.subarray(simCnmtE.offset, simCnmtE.offset + simCnmtE.size), keys)).cnmt;
  check(refCnmt.titleId === simCnmt.titleId && refCnmt.contentEntryCount === simCnmt.contentEntryCount &&
        refCnmt.metaEntryCount === simCnmt.metaEntryCount,
    'sim: CNMT titleId + entry counts match ref');
  // CNMT_ENTRY_TYPE.PROGRAM = 1 (switchbrew PackagedContentInfo; verified
  // against hacPack cnmt.c) — not 0.
  const refP = refCnmt.contentEntries.find(e => e.type === CNMT_ENTRY_TYPE.PROGRAM);
  const simP = simCnmt.contentEntries.find(e => e.type === CNMT_ENTRY_TYPE.PROGRAM);
  const otherRef = refCnmt.contentEntries.filter(e => e.type !== CNMT_ENTRY_TYPE.PROGRAM);
  const otherSim = simCnmt.contentEntries.filter(e => e.type !== CNMT_ENTRY_TYPE.PROGRAM);
  check(otherRef.length === otherSim.length &&
        otherRef.every((e, i) => e.hash === otherSim[i].hash && e.size === otherSim[i].size),
    'sim: CNMT non-program entries identical to ref');
  check(!!refP && !!simP &&
        simP.hash === simSha && simP.size === simProg.size &&
        refP.hash === sha256(refProgNca) && refP.size === refProg.size,
    'sim: CNMT program entry = (sha256(program NCA), program size) in each layout');
  check(refCnmt.metaEntries.length === simCnmt.metaEntries.length &&
        refCnmt.metaEntries.every((e, i) =>
          e.titleId === simCnmt.metaEntries[i].titleId && e.version === simCnmt.metaEntries[i].version &&
          e.type === simCnmt.metaEntries[i].type && e.install === simCnmt.metaEntries[i].install),
    'sim: CNMT meta entries identical to ref');
}

if (process.exitCode === 1) {
  console.log('\nMISMATCH — see FAIL lines above');
  process.exit(1);
}
console.log('\nMATCH — plain-layout routes byte-identical; SW own-BKTR route: contentId self-consistent, merged RomFS ≡ ref RomFS, ExeFS ≡, CNMT consistent.');
