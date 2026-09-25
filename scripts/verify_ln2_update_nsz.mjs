// Real LN2 two-pass update verification on the .NSZ inputs (no disk output —
// hash-only writer). The .nsp harness (verify_ln2_update.mjs) uses a FileRangeSource
// base whose registerRange() is a no-op, so it never exercises the NCZ base-range
// registration that LN2 trips over (non-monotonic + overlapping base phys offsets).
// This harness feeds the .nsz (NCZ) base through NczStreamSource, which is the path
// that used to throw "NczStreamSource: ranges must be strictly increasing".
//
// Expected (known-good, from the .nsp run / hacpack reference):
//   contentId = 067f1c504e756e438203c96b4506a6552cac808d65c3bf94cfcb4088de9c85e5
//   declared size = 5326224720
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

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const basePath = `${DIR}/Little Nightmares II [010097100EDD6000][v0] (4.99 GB).nsz`;
const updatePath = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`;
const EXPECTED_CONTENT_ID = '067f1c504e756e438203c96b4506a6552cac808d65c3bf94cfcb4088de9c85e5';
const EXPECTED_SIZE = 5326224720;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
let capturedContentId = null;
const log = (level, msg) => {
    if (level !== 'debug') console.log(`[${level.toUpperCase()}] ${msg}`);
    const m = /^ContentId: ([0-9a-f]{64})/.exec(msg);
    if (m) capturedContentId = m[1];
};
const progress = () => {};

console.log('=== LN2 two-pass update on .NSZ (NCZ base) — hash-only append-only output ===\n');
const base = { name: 'base.nsz', reader: new FileReader(basePath) };
const upd = { name: 'update.nsz', reader: new FileReader(updatePath) };
const out = new HashWriter();
const t0 = performance.now();
const res = await update([base, upd], { writable: out }, { keys, log, progress, bktrMerge: true });
const sec = (performance.now() - t0) / 1000;
console.log(`\nOK: sec=${sec.toFixed(1)}s size=${res.size} members=${res.memberCount}`);
console.log(`sha256(contentId)=${out.digest().slice(0, 32)} (total ${out.total})`);
console.log(`declared size=${res.size} === written total=${out.total} : ${res.size === out.total ? 'MATCH ✓' : 'MISMATCH ✗'}`);

console.log(`\ncontentId check (Program NCA sha256):`);
console.log(`  got      ${capturedContentId}`);
console.log(`  expected ${EXPECTED_CONTENT_ID}`);
const cidOk = capturedContentId === EXPECTED_CONTENT_ID;
console.log(cidOk ? '  contentId MATCH ✓ (byte-identical to known-good)' : '  contentId MISMATCH ✗');
const sizeOk = res.size === EXPECTED_SIZE;
console.log(`size check: ${sizeOk ? `MATCH ✓ (${res.size})` : `MISMATCH ✗ (got ${res.size}, expected ${EXPECTED_SIZE})`}`);
console.log(`\n${cidOk && sizeOk ? 'ALL CHECKS PASSED ✓' : 'CHECKS FAILED ✗'}`);
base.reader.close(); upd.reader.close();
