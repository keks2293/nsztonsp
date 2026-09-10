// Simulates the browser SW download path (sequential-only stream + gap-fill) and
// verifies the result is byte-identical to the seekable fd output. The SW cannot
// seek, so SWDownloader fills gaps between writes with zeros; this writer mirrors
// that exact logic and collects the stream in order.
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

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

// Mirrors real FSA (FileSystemWritableFileStream): write+seek, but NO read() — so
// buildRead() must return null for it and scatter can only run via mergeBuffer
// (hashes come from RAM, no output re-read).
class FsaWriter {
  chunks = [];
  write({ type, position, data }) {
    this.chunks.push({ offset: position, data: new Uint8Array(data) });
  }
  seek(position) {}
  build() {
    this.chunks.sort((a, b) => a.offset - b.offset);
    const last = this.chunks[this.chunks.length - 1];
    const buf = new Uint8Array(last.offset + last.data.length);
    for (const c of this.chunks) buf.set(c.data, c.offset);
    return buf;
  }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = () => {};
const progress = () => {};

// FORCE_JS=1 runs the exact browser SHA-256 path (pure-JS streaming class);
// default runs the native node:crypto streaming backend. Both must MATCH.
if (process.env.FORCE_JS) {
  const { setForceJsSha256 } = await import('../crypto/sha256.js');
  setForceJsSha256(true);
  console.log('forcing pure-JS streaming SHA256 (browser path)');
}

const baseReader = { name: 'base.nsp', reader: new FileReader(basePath) };
const updateReader = { name: 'update.nsz', reader: new FileReader(updatePath) };

// Reference: seekable fd output (known-good)
const refPath = '/tmp/update_sw_sim_ref.nsp';
const refFd = fs.openSync(refPath, 'w+');
await update([baseReader, updateReader], { fd: refFd }, { keys, log, progress, bktrMerge: true });
fs.closeSync(refFd);
baseReader.reader.close(); updateReader.reader.close();
const ref = new Uint8Array(fs.readFileSync(refPath));

// SW-simulated: sequential writer with gap-fill
const base2 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update2 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const sw = new SequentialWriter();
const result = await update([base2, update2], { writable: sw }, { keys, log, progress, bktrMerge: true });
base2.reader.close(); update2.reader.close();
const sim = sw.build();

// Buffered mode (the browser "Buffer" pill): merged RomFS fully in memory
const base3 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update3 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const bufPath = '/tmp/update_sw_sim_buffered.nsp';
const bufFd = fs.openSync(bufPath, 'w+');
await update([base3, update3], { fd: bufFd }, { keys, log, progress, bktrMerge: true, updateMode: 'buffered' });
fs.closeSync(bufFd);
base3.reader.close(); update3.reader.close();
const buf = new Uint8Array(fs.readFileSync(bufPath));

const refSha = crypto.createHash('sha256').update(ref).digest('hex');
const simSha = crypto.createHash('sha256').update(sim).digest('hex');
const bufSha = crypto.createHash('sha256').update(buf).digest('hex');
console.log('ref (fd, seekback) :', ref.length, 'sha256=' + refSha);
console.log('sim (sw, two-pass) :', sim.length, 'sha256=' + simSha);
console.log('buffered (fd)      :', buf.length, 'sha256=' + bufSha);
console.log('result.size        :', result.size);

// In-memory output with read-back: the new memory read() in buildRead() unlocks
// the streaming single-decompression path for memory outputs (browser) — must
// stay byte-identical to fd.
const base4 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update4 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const memOut = { memory: true };
const mem = await update([base4, update4], memOut, { keys, log, progress, bktrMerge: true });
base4.reader.close(); update4.reader.close();
const memBuf = new Uint8Array(await mem.blob.arrayBuffer());
const memSha = crypto.createHash('sha256').update(memBuf).digest('hex');
console.log('memory (streaming) :', memBuf.length, 'sha256=' + memSha);

// Scatter mode: fd output (seekable), updateMode='scatter' — wins the update
// once per use (tables U1 + patches U2), writes the merged RomFS out of virtual
// order, and re-reads the written NCA for the IVFC hash + contentId.
const base5 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update5 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const scatterPath = '/tmp/update_sw_sim_scatter.nsp';
const scatterFd = fs.openSync(scatterPath, 'w+');
await update([base5, update5], { fd: scatterFd }, { keys, log, progress, bktrMerge: true, updateMode: 'scatter' });
fs.closeSync(scatterFd);
base5.reader.close(); update5.reader.close();
const scatter = new Uint8Array(fs.readFileSync(scatterPath));
const scatterSha = crypto.createHash('sha256').update(scatter).digest('hex');
console.log('scatter (fd)       :', scatter.length, 'sha256=' + scatterSha);

// Scatter + Buffer (fd, readable output): merged RomFS + ExeFS accumulate in RAM,
// hashes come from the buffers (no output re-read). Must stay byte-identical to
// the re-read scatter path above.
const base6 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update6 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const sbcPath = '/tmp/update_sw_sim_scatterbuf.nsp';
const sbcFd = fs.openSync(sbcPath, 'w+');
await update([base6, update6], { fd: sbcFd }, { keys, log, progress, bktrMerge: true, updateMode: 'scatter', mergeBuffer: true });
fs.closeSync(sbcFd);
base6.reader.close(); update6.reader.close();
const sbc = new Uint8Array(fs.readFileSync(sbcPath));
const sbcSha = crypto.createHash('sha256').update(sbc).digest('hex');
console.log('scatter+buffer (fd) :', sbc.length, 'sha256=' + sbcSha);

// Scatter + Buffer on an FSA-style output (write+seek, NO read): buildRead() → null,
// so only mergeBuffer lets scatter run here — proves the gating and the no-re-read
// path on a realistic browser-FSA output. Must succeed and be byte-identical.
const base7 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update7 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const fsa = new FsaWriter();
await update([base7, update7], { writable: fsa }, { keys, log, progress, bktrMerge: true, updateMode: 'scatter', mergeBuffer: true });
base7.reader.close(); update7.reader.close();
const fsaBytes = fsa.build();
const fsaSha = crypto.createHash('sha256').update(fsaBytes).digest('hex');
console.log('scatter+buffer (FSA):', fsaBytes.length, 'sha256=' + fsaSha);

// Scatter on a memory (blob) output — the browser in-memory path. buildRead()
// returns a working reader for memory (adapter.js), so scatter runs WITHOUT the
// merged-buffer, hashing the merged RomFS + contentId by re-reading the written
// chunks. Must be byte-identical to the fd scatter above.
const base8 = { name: 'base.nsp', reader: new FileReader(basePath) };
const update8 = { name: 'update.nsz', reader: new FileReader(updatePath) };
const memScatterOut = { memory: true };
const memScatter = await update([base8, update8], memScatterOut, { keys, log, progress, bktrMerge: true, updateMode: 'scatter' });
base8.reader.close(); update8.reader.close();
const memScatterBuf = new Uint8Array(await memScatter.blob.arrayBuffer());
const memScatterSha = crypto.createHash('sha256').update(memScatterBuf).digest('hex');
console.log('scatter (memory)    :', memScatterBuf.length, 'sha256=' + memScatterSha);

const tally = [refSha, simSha, bufSha, memSha, scatterSha, memScatterSha, sbcSha, fsaSha];
const lens = [ref.length, sim.length, buf.length, memBuf.length, scatter.length, memScatterBuf.length, sbc.length, fsaBytes.length];
if (tally.every(s => s === refSha) && lens.every(n => n === ref.length)) {
  console.log('MATCH — seekback ≡ two-pass ≡ buffered ≡ memory ≡ memory+scatter ≡ scatter ≡ scatter+buffer(fd) ≡ scatter+buffer(FSA), all byte-identical');
} else {
  console.log('MISMATCH');
  let i = 0; const n = Math.min(...lens);
  while (i < n && ref[i] === sim[i]) i++;
  console.log('first diff ref/sim at', i, '0x' + i.toString(16), 'len ref=' + lens.join(' '));
  process.exit(1);
}
