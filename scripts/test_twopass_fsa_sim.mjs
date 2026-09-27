// Simulates the browser File System Access API writable (seek + positioned
// write, NO read — MDN: FileSystemWritableFileStream only has write/seek/
// truncate) and runs the full two-pass BKTR update on the real Stardew NSZ
// files.
//
// The sequential-output two-pass path (outRead === null) now emits a
// SELF-CONTAINED own-BKTR Program NCA (fs/bktr-pack.js): the whole BKTR
// section is rewritten with our own data region + reloc/sub tables, so the
// produced NSP can no longer be byte-compared to the yanu plaintext-merge
// reference. Verification therefore happens at the MERGE level (mirroring
// test_twopass_sw_sim.mjs):
//   - the FSA stream must stay sequential apart from the ONE legal trailing
//     write-back: the real PFS0 header overwrites offset 0 at the end (seekable
//     two-pass, no placeholder — the append-only/no-seek writer instead emits
//     the 272-byte header first);
//   - the PFS0 header must be 272 bytes (fixed name lengths);
//   - the produced Program NCA must merge byte-identically to the real update:
//     mergeRomFS(base, producedNCA) == scatter-merge of the real update;
//   - the PFS0 program name must embed sha256(produced NCA) — the Pass-1
//     contentId equals the Pass-2 written bytes exactly.
//
// Run: node scripts/test_twopass_fsa_sim.mjs
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

// Faithful FSA simulation: positioned writes may arrive in ANY order
// (including backward — legal here, only tracked for reporting), no read().
// Gaps are implicitly zeros.
class FsaSim {
  constructor(outPath) {
    this.outPath = outPath;
    this.data = null;
    this.pos = 0;
    this.backward = [];
  }
  async seek(pos) { this.pos = pos; }
  async write(entry) {
    const pos = entry.position;
    const view = entry.data;
    if (pos < this.pos) this.backward.push({ at: pos, len: view.byteLength, delta: pos - this.pos });
    const end = pos + view.byteLength;
    if (!this.data || this.data.byteLength < end) {
      const nd = new Uint8Array(Math.max(this.data ? this.data.byteLength : 0, end));
      if (this.data) nd.set(this.data);
      this.data = nd;
    }
    this.data.set(view, pos);
    this.pos = end;
  }
  close() {
    fs.writeFileSync(this.outPath, this.data);
  }
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

async function mergeCompares(name, outPath) {
  // Extract the produced Program NCA from the FSA output file.
  const all = fs.readFileSync(outPath);
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

const outPath = '/tmp/twopass_fsa_sim.nsp';
const fsa = new FsaSim(outPath);
const readers = [
  { name: 'base.nsz', reader: baseReader },
  { name: 'update.nsz', reader: updateReader },
];
const result = await update(readers, { writable: fsa }, { keys, log, progress });
fsa.close();
for (const r of readers) r.reader.close();

const size = fs.statSync(outPath).size;
console.log(`\n=== RESULT (FSA sim) ===`);
console.log(`size: ${size.toLocaleString()}  result.size: ${result.size}`);
console.log(`backward writes (expected exactly one — trailing 272 B PFS0 header @0): ${fsa.backward.length}`);
for (const b of fsa.backward.slice(0, 5)) console.log(`  backward at pos=0x${b.at.toString(16)} len=${b.len}`);

let ok = true;
const hdr = hdrSizeOf(outPath);
if (hdr !== 272) { console.log(`FAIL: PFS0 header is ${hdr}, expected 272`); ok = false; }
// FSA (seekable) two-pass: NCA written as one sequential sweep, then the
// 272-byte PFS0 header written back at offset 0. Anything beyond that single
// trailing write-back is a sequencing regression.
const hdrBw = fsa.backward.filter(b => b.at === 0);
const extraBw = fsa.backward.filter(b => b.at !== 0);
if (hdrBw.length !== 1 || hdrBw[0].len !== 272) {
  console.log(`FAIL: expected exactly one trailing PFS0-header write-back at offset 0 (len 272), got ${fsa.backward.length}`); ok = false;
}
if (extraBw.length) { console.log(`FAIL: ${extraBw.length} unexpected backward write(s) beyond the PFS0 header`); ok = false; }
if (result.size !== size) { console.log(`FAIL: result.size ${result.size} != file ${size}`); ok = false; }
try {
  const prog = await mergeCompares('FSA sim', outPath);
  console.log(`program contentId: ${prog.name.slice(0, 32)} (embedded in PFS0 name)`);
} catch (e) {
  console.log(`FAIL: ${e.message}`);
  ok = false;
}
if (ok) console.log('\nPASS: FSA two-pass (own-BKTR) — PFS0-header-only write-back, header, merge equality, contentId match.');
else process.exit(1);