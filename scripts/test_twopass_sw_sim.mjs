// Simulates the browser SW download adapter (sequential append + zero gap-fill)
// and runs the full two-pass BKTR update on the real Stardew NSZ files.
//
// The sequential-output two-pass path now emits a SELF-CONTAINED own-BKTR
// Program NCA (fs/bktr-pack.js): the whole BKTR section is rewritten with our
// own data region + reloc/sub tables, so the produced NSP can no longer be
// byte-compared to the yanu plaintext-merge reference. Verification therefore
// happens at the MERGE level:
//   - the SW stream must stay append-only (no gap-fills, no backward writes);
//   - the PFS0 header must be 272 bytes (fixed name lengths);
//   - the produced Program NCA must merge byte-identically to the real update:
//     mergeRomFS(base, producedNCA) == scatter-merge of the real update;
//   - the PFS0 program name must embed sha256(produced NCA) — the Pass-1
//     contentId equals the Pass-2 written bytes exactly.
//
// Run: node scripts/test_twopass_sw_sim.mjs
import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';
import { PFS0 } from '../fs/pfs0.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { BufferRangeSource, NczStreamSource } from '../fs/range-source.js';
import { AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { decryptNcaHeaderBytes, fsHeaderAt, SECTION_FS_TYPE, SECTION_CRYPTO_TYPE } from '../fs/nca-utils.js';
import { resolveBktrMeta, readBktrTables, mergeRomFS, scatterRomFS } from '../fs/bktr-merge.js';
import { readLeU64 } from '../fs/bytes.js';

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

// Faithful SWDownloader.write simulation: data is APPENDED to a sequential
// stream; gaps (position > #pos) are filled with zeros; #pos = position + len.
// Backward writes (position < #pos) append at the current stream position while
// #pos is set backwards — corrupting everything after, exactly like the real SW.
//
// detach=true simulates the OLD SWDownloader, which transferred (detached) the
// caller's full-buffer views via postMessage — zeroing .length on the caller's
// reference after the write. The fixed SW always posts a copy (detach=false),
// but the two-pass loop also captures lengths before writing, so the pipeline
// must survive BOTH modes.
class SwSim {
  constructor(outPath, { detach = false } = {}) {
    this.outPath = outPath;
    this.detach = detach;
    this.fd = fs.openSync(outPath, 'w');
    this.pos = 0;
    this.streamLen = 0;
    this.gapFills = [];
    this.backward = [];
  }
  async write(position, data) {
    const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    const gap = position - this.pos;
    if (gap > 0) {
      if (gap >= 0x1000) this.gapFills.push({ at: position, size: gap, streamPos: this.pos });
      fs.writeSync(this.fd, Buffer.alloc(gap), 0, gap, this.streamLen);
      this.streamLen += gap;
    } else if (gap < 0) {
      this.backward.push({ at: position, len: view.byteLength, streamPos: this.streamLen, delta: gap });
    }
    const len = view.byteLength;
    if (this.detach && view.byteLength === view.buffer.byteLength) {
      // old SW: postMessage transferred the ORIGINAL buffer → bytes arrive at
      // the stream, caller's buffer is detached (length becomes 0).
      fs.writeSync(this.fd, view, 0, len, this.streamLen);
      view.buffer.transfer(0);
    } else {
      // fixed SW: always post a copy — caller's buffer survives.
      const chunk = view.slice(0);
      fs.writeSync(this.fd, chunk, 0, len, this.streamLen);
    }
    this.streamLen += len;
    this.pos = position + len;
  }
  close() { fs.closeSync(this.fd); }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const log = (level, msg) => { if (!process.env.QUIET) console.log(`[${level.toUpperCase()}] ${msg}`); };
const progress = () => {};
const sha256 = (b) => createHash('sha256').update(Buffer.from(b.buffer, b.byteOffset, b.length)).digest('hex');

const baseReader = new FileReader(basePath);
const updateReader = new FileReader(updatePath);
const baseC = await openContainer({ reader: baseReader, name: 'base' });
const updC = await openContainer({ reader: updateReader, name: 'update' });
const pickProg = (c) => c.entries.filter(e => /\.ncz$/i.test(e.name) && !/\.cnmt\.ncz$/i.test(e.name)).sort((a, b) => b.size - a.size)[0];
const pickTik = async (c, r) => { const t = c.entries.find(e => e.name.toLowerCase().endsWith('.tik')); return t ? await r.read(t.offset, t.size) : null; };
const baseProg = pickProg(baseC);
const updProg = pickProg(updC);
const baseHeaderRaw = await baseReader.read(baseProg.offset, Math.min(baseProg.size, 0xC00));
const updateHeaderRaw = await updateReader.read(updProg.offset, Math.min(updProg.size, 0xC00));
const baseTik = await pickTik(baseC, baseReader);
const updateTik = await pickTik(updC, updateReader);
// Member-window readers: parseNczSections offsets are relative to the .ncz
// MEMBER, so every NczStreamSource must read through the same window (a whole-
// file reader would decompress at wrong absolute offsets → registered ranges
// never fill → "NCA data ended before registered range").
const baseNcz = new AdapterNCZReader(baseReader, baseProg.offset, baseProg.size);
const updateNcz = new AdapterNCZReader(updateReader, updProg.offset, updProg.size);
const baseParsed = await parseNczSections(baseNcz);
const updateParsed = await parseNczSections(updateNcz);

const updateHdr = decryptNcaHeader(updateHeaderRaw, keys);
const bk = updateHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
if (bk < 0) throw new Error('update has no BKTR romfs section');
const updFh = fsHeaderAt(decryptNcaHeaderBytes(updateHeaderRaw, keys), bk);
const dataLevelSize = readLeU64(updFh, 0x18 + 5 * 0x18 + 8);

async function runSwSim(runOutPath, detach) {
  const sw = new SwSim(runOutPath, { detach });
  const readers = [
    { name: 'base.nsz', reader: baseReader },
    { name: 'update.nsz', reader: updateReader },
  ];
  await update(readers, { writable: sw }, { keys, log, progress });
  sw.close();
  return sw;
}

// Reference merged data (physical-order scatter of the real update).
const mergedRef = new Uint8Array(dataLevelSize);
await scatterRomFS({
  baseInput: { headerRaw: baseHeaderRaw, source: new NczStreamSource(baseNcz, baseParsed, log) },
  updateCtx: { headerRaw: updateHeaderRaw, source: null, reader: updateNcz, parsed: updateParsed, streamable: true },
  options: { keys, baseTik, updateTik },
  writeFn: (off, chunk) => { mergedRef.set(chunk, off); },
  log,
});
const realMeta = await resolveBktrMeta({ headerRaw: baseHeaderRaw }, { headerRaw: updateHeaderRaw }, { keys, baseTik, updateTik });
const tr = [
  { off: realMeta.relocAbsOffset, len: realMeta.relocHeader.size },
  { off: realMeta.subAbsOffset, len: realMeta.subHeader.size },
].sort((a, b) => a.off - b.off);
const { relocBlock } = await readBktrTables((() => { const s = new NczStreamSource(updateNcz, updateParsed, log); for (const r of tr) s.registerRange(r.off, r.len); return s; })(), realMeta);
log('info', `reference: reloc=${relocBlock.entries.length}, merged=${dataLevelSize} bytes`);

function hdrSizeOf(path) {
  const fd = fs.openSync(path, 'r');
  const head = Buffer.alloc(16);
  fs.readSync(fd, head, 0, 16, 0);
  fs.closeSync(fd);
  return 0x10 + head.readUInt32LE(4) * 0x18 + head.readUInt32LE(8);
}

async function mergeCompares(name, sw) {
  // Extract the produced Program NCA from the SW output file.
  const all = fs.readFileSync(sw.outPath);
  const entries = new PFS0(all).getFiles();
  const prog = entries.filter(e => /\.nca$/i.test(e.name) && !/\.cnmt\.nca$/i.test(e.name)).sort((a, b) => b.size - a.size)[0];
  if (!prog) throw new Error(`${name}: no program NCA`);
  const nca = all.subarray(prog.offset, prog.offset + prog.size);
  const psha = sha256(nca);
  // Pass-1 contentId must match Pass-2 bytes.
  if (!prog.name.toLowerCase().startsWith(psha.slice(0, 32))) {
    throw new Error(`${name}: program name ${prog.name.slice(0, 32)} != sha256-of-written ${psha.slice(0, 32)}`);
  }
  const ours = await mergeRomFS(
    { headerRaw: baseHeaderRaw, source: { read: async () => new Uint8Array(0) } },
    { headerRaw: nca.subarray(0, 0xC00), source: BufferRangeSource(nca) },
    { keys, log }
  );
  if (ours.dataLevelSize !== dataLevelSize) throw new Error(`${name}: merged size mismatch`);
  for (let i = 0; i < dataLevelSize; i++) {
    if (ours.mergedData[i] !== mergedRef[i]) throw new Error(`${name}: merged byte diff at 0x${i.toString(16)}`);
  }
  console.log(`${name}: merge byte-identical (${dataLevelSize.toLocaleString()} bytes), contentId = sha of written NCA`);
  return prog;
}

// Run 1 (detach=true): the STRICT case — mimics the OLD SWDownloader whose
// postMessage transfer detached the caller's buffers (zeroing .length after
// the write). Passes only if the pipeline never touches a buffer post-write.
// Run 2 (detach=false): the FIXED SWDownloader behavior (always posts a copy).
const runs = [];
for (const detach of [true, false]) {
  const p = `/tmp/twopass_sw_ownbktr_${detach ? 'detach' : 'copy'}.nsp`;
  console.log(`\n===== SwSim run: detach=${detach} =====`);
  runs.push({ detach, path: p, sw: await runSwSim(p, detach) });
}

let ok = true;
for (const run of runs) {
  const { detach, sw, path } = run;
  console.log(`\n=== RESULT (detach=${detach}) ===`);
  const hdr = hdrSizeOf(path);
  const size = fs.statSync(path).size;
  console.log(`header: ${hdr} (0x${hdr.toString(16)})  [expect 272 (0x110)]`);
  console.log(`size: ${size.toLocaleString()}`);
  console.log(`SW sim: gapFills(>=0x1000)=${sw.gapFills.length}  backward=${sw.backward.length}`);
  for (const g of sw.gapFills) console.log(`  gap at pos=0x${g.at.toString(16)} size=${g.size}`);
  for (const b of sw.backward.slice(0, 10)) console.log(`  backward at pos=0x${b.at.toString(16)} len=${b.len} delta=${b.delta}`);

  if (hdr !== 272) { console.log(`FAIL: PFS0 header is ${hdr}, expected 272`); ok = false; }
  if (sw.gapFills.length || sw.backward.length) { console.log('FAIL: SW sim detected non-sequential writes'); ok = false; }
  try {
    run.progName = (await mergeCompares(`run(detach=${detach})`, sw)).name;
  } catch (e) {
    console.log(`FAIL: ${e.message}`);
    ok = false;
  }
}

// Both runs must produce the same contentId (files are unlinked only after this).
if (runs[0] && runs[1]) {
  const a = runs[0].progName, b = runs[1].progName;
  if (!a || !b || a !== b) {
    console.log(`FAIL: detach and copy runs produced different contentIds (${a ? a.slice(0, 32) : '?'} vs ${b ? b.slice(0, 32) : '?'})`); ok = false;
  } else {
    console.log(`\ndetach ≡ copy run: same contentId (${a.slice(0, 32)})`);
  }
}

for (const r of runs) { try { fs.unlinkSync(r.path); } catch { /* already gone */ } }

baseReader.close();
updateReader.close();
if (ok) console.log('\nPASS: SW two-pass (own-BKTR) — sequential discipline, header, merge equality, determinism.');
else process.exit(1);