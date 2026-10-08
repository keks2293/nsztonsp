// Real LOLLIPOP CHAINSAW RePOP two-pass own-BKTR update on the .NSZ inputs —
// hash-only append-only (SW-equivalent) output, NO disk writes.
//
// Purpose: this is the pair that crashed the browser with
//   "Update failed: Array buffer allocation failed"
// because walkDataRegion eagerly registered patch+base ranges
// (patch total + base total = dataRegion = 0x19de3b3c0 ≈ 6.94 GB of
// Uint8Array held simultaneously). This harness:
//   1. measures the Node-side peak RSS of the run (eager-allocation baseline
//      before the lockstep fix vs bounded window after it), and
//   2. pins contentId + full-output sha256 so the fix can be verified
//      BYTE-IDENTICAL (lockstep serves the same ciphertext).
// The output is an append-only (no seek) writer, i.e. the exact SW two-pass
// branch (computeOwnBktrContentId + writeOwnBktrProgramNca) the browser takes.
//
// Usage:  node scripts/verify_lollipop_update_nsz.mjs
// Optional: EXPECTED_CONTENT_ID=<hex> EXPECTED_SHA=<hex> to assert.
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

class FileReader {
    constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
    async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }
    close() { fs.closeSync(this.fd); }
}

// Hash-only append-only output (sequential writes only, like the SW adapter).
class HashWriter {
    constructor() { this.h = crypto.createHash('sha256'); this.total = 0; this.last = 0; }
    write(pos, data) {
        if (pos !== this.last) throw new Error(`HashWriter: out-of-order write at ${pos} (expected ${this.last})`);
        this.h.update(data); this.last += data.byteLength; this.total += data.byteLength;
    }
    digest() { return this.h.digest('hex'); }
}

const DIR = '/Users/rmitkov/Downloads/Lollipop Chainsaw RePop [NSZ]';
const basePath = `${DIR}/LOLLIPOP CHAINSAW RePOP [0100DD301A686000][v0] (7.10 GB).nsz`;
const updatePath = `${DIR}/LOLLIPOP CHAINSAW RePOP [0100DD301A686800][v1179648] (2.29 GB).nsz`;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
let capturedContentId = null;
const log = (level, msg) => {
    if (level !== 'debug') console.log(`[${level.toUpperCase()}] ${msg}`);
    let m = /^ContentId: ([0-9a-f]{64})/.exec(msg);
    if (m) capturedContentId = m[1];
    m = /own-BKTR contentId \(Pass 1\): ([0-9a-f]{64})/.exec(msg);
    if (m && !capturedContentId) capturedContentId = m[1];
};
const progress = () => {};

// Sample RSS so the run reports its own peak even without /usr/bin/time -l.
let peakRss = 0;
const rssTimer = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peakRss) peakRss = rss;
}, 500);
rssTimer.unref();

console.log('=== LOLLIPOP CHAINSAW RePOP two-pass own-BKTR update on .NSZ — hash-only append-only output ===\n');
const base = { name: 'base.nsz', reader: new FileReader(basePath) };
const upd = { name: 'update.nsz', reader: new FileReader(updatePath) };
const out = new HashWriter();
const t0 = performance.now();
const res = await update([base, upd], { writable: out }, { keys, log, progress, bktrMerge: true });
const sec = (performance.now() - t0) / 1000;
const finalPeak = Math.max(peakRss, process.memoryUsage().rss);
const outputSha = out.digest(); // hash is single-use — finalize once
console.log(`\nOK: sec=${sec.toFixed(1)}s size=${res.size} members=${res.memberCount}`);
console.log(`full-output sha256=${outputSha} (total ${out.total} bytes)`);
console.log(`peak RSS=${(finalPeak / 1024 / 1024 / 1024).toFixed(2)} GiB`);
console.log(`declared size=${res.size} === written total=${out.total} : ${res.size === out.total ? 'MATCH ✓' : 'MISMATCH ✗'}`);

console.log(`\ncontentId (Program NCA sha256): ${capturedContentId}`);
let failed = false;
if (process.env.EXPECTED_CONTENT_ID) {
    const ok = capturedContentId === process.env.EXPECTED_CONTENT_ID;
    console.log(`  expected   ${process.env.EXPECTED_CONTENT_ID}`);
    console.log(`  contentId ${ok ? 'MATCH ✓' : 'MISMATCH ✗'}`);
    if (!ok) failed = true;
}
if (process.env.EXPECTED_SHA) {
    const ok = outputSha === process.env.EXPECTED_SHA;
    console.log(`  output sha ${ok ? 'MATCH ✓' : 'MISMATCH ✗'}`);
    if (!ok) failed = true;
}
if (res.size !== out.total) failed = true;
console.log(`\n${failed ? 'CHECKS FAILED ✗' : 'ALL CHECKS PASSED ✓'}`);
base.reader.close(); upd.reader.close();
process.exit(failed ? 1 : 0);
