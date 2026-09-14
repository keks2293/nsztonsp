// Probe: measure the adapter.write() call pattern of the SW two-pass update
// path (the same writable-no-read shape as FSA) on the real Stardew pair.
// Runs ONCE as appendOnly two-pass (3x romfs), memory output, no disk written.
// Prints: write() call count, size histogram, wall time inside write(), and an
// extrapolation of what a per-call FSA IPC latency would add.
import fs from 'node:fs';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
  close() { fs.closeSync(this.fd); }
}

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));
const log = () => {};
const progress = () => {};

class CountingWriter {
    constructor() { this.chunks = []; this.pos = 0; this.calls = 0; this.ms = 0; this.hist = new Map(); }
    write(position, data) {
        const t0 = performance.now();
        const n = data.byteLength; // BEFORE storing: SW transfers detach the buffer
        this.calls++;
        this.chunks.push({ offset: position, data });
        this.pos = position + n;
        const ms = performance.now() - t0;
        this.ms += ms;
        // bucket: pow2
        let b = 1;
        while (b < n) b <<= 1;
        this.hist.set(b, (this.hist.get(b) || 0) + n);
    }
    build() {
        const buf = new Uint8Array(this.pos);
        for (const c of this.chunks) { buf.set(c.data, c.offset); }
        return buf;
    }
}

const reader = { name: 'base.nsp', reader: new FileReader(basePath) };
const updateInput = { name: 'update.nsz', reader: new FileReader(updatePath) };
const w = new CountingWriter();
const t0 = performance.now();
const result = await update([reader, updateInput], { writable: w }, { keys, log, progress, bktrMerge: true });
reader.reader.close(); updateInput.reader.close();
const totalMs = performance.now() - t0;

console.log('output size:', result.size, 'bytes');
console.log(`write() calls: ${w.calls}, write() wall: ${w.ms.toFixed(1)}ms, total run: ${totalMs.toFixed(0)}ms`);
console.log('size histogram (bucket → bytes, MB):');
for (const [b, bytes] of [...w.hist.entries()].sort((a, b2) => a[0] - b2[0])) {
    console.log(`  ≤${b < 1024 ? b + ' B' : (b / 1024 / 1024).toFixed(1) + ' MB'}: ${(bytes / 1048576).toFixed(1)} MB`);
}
console.log('\nextrapolation: extra time if each write() call cost L (async IPC):');
for (const L of [0.05, 0.1, 0.25, 0.5, 1.0]) {
    console.log(`  L=${L}ms → +${(w.calls * L / 1000).toFixed(1)}s over ${totalMs.toFixed(0)}s run (+${(100 * w.calls * L / totalMs).toFixed(1)}%)`);
}