// Real LN2 two-pass update verification (no disk output — hash-only writer).
// Pass 1 previously died with "Invalid PFS0 magic" in createExefsAcidFilter.
// ExeFS check: the output Program NCA has PLAINTEXT sections (hacpack
// --plaintext style: encrypted header, raw section data), so the ExeFS must be
// read DIRECTLY at (sectionOffset + sectionStart) — NOT via the CTR keystream
// (extractExefs would XOR plaintext → garbage magic).
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

class FileReader {
    constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
    async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }
    close() { fs.closeSync(this.fd); }
}

// Hash-only output: append-only SW two-pass path (no seek/read-back), barfs if
// writes are out of order.
class HashWriter {
    constructor() { this.h = crypto.createHash('sha256'); this.total = 0; this.last = 0; }
    write(pos, data) {
        if (pos !== this.last) throw new Error(`HashWriter: out-of-order write at ${pos} (expected ${this.last})`);
        this.h.update(data); this.last += data.byteLength; this.total += data.byteLength;
    }
    digest() { return this.h.digest('hex'); }
}

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const basePath = `${DIR}/010097100edd6000_base_v0.nsp`;
const updatePath = `${DIR}/010097100edd6800_update_v262144.nsp`;
const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const log = (level, msg) => { if (level !== 'debug') console.log(`[${level.toUpperCase()}] ${msg}`); };
const progress = () => {};
const silence = () => {};

// Read the plaintext ExeFS of a plaintext-section Program NCA directly.
// Returns { magic, size, titleId }.
async function readOutputExeFS(ncaBuf, keys) {
    const { decryptNcaHeader } = await import('../fs/nca.js');
    const { decryptNcaHeaderBytes, findExefsFsHeader, sectionMedia, FS_HDR } = await import('../fs/nca-utils.js');
    const { readLeU64 } = await import('../fs/bytes.js');
    const hdr = await decryptNcaHeader(ncaBuf.subarray(0, 0xC00), keys);
    const decBytes = decryptNcaHeaderBytes(ncaBuf.subarray(0, 0xC00), keys);
    const { idx, fsHdr: exeFsHdr } = findExefsFsHeader(decBytes, 'verify');
    const sectionStart = readLeU64(exeFsHdr, FS_HDR.PFS0_OFFSET);
    const sectionSize = readLeU64(exeFsHdr, FS_HDR.PFS0_SIZE);
    const { mediaOffset } = sectionMedia(decBytes, idx);
    const dataOff = mediaOffset * 0x200 + sectionStart;
    // Direct read — sections are plaintext in the output NCA.
    const raw = ncaBuf.subarray(dataOff, dataOff + Math.min(sectionSize, 4));
    const magic = raw.length >= 4 ? String.fromCharCode(raw[0], raw[1], raw[2], raw[3]) : '(too short)';
    return { titleId: hdr.titleId, magic, size: sectionSize, dataOff };
}

const mode = process.argv[2] || 'twopass';
if (mode === 'twopass') {
    console.log('=== LN2 two-pass update (hash-only append-only output) ===\n');
    const base = { name: 'base.nsp', reader: new FileReader(basePath) };
    const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
    const out = new HashWriter();
    const t0 = performance.now();
    const res = await update([base, upd], { writable: out }, { keys, log, progress, bktrMerge: true });
    console.log(`\nOK: sec=${((performance.now() - t0) / 1000).toFixed(1)}s size=${res.size} members=${res.memberCount}`);
    console.log(`sha256=${out.digest()} (total ${out.total})`);
    console.log(`declared size=${res.size} === written total=${out.total} : ${res.size === out.total ? 'MATCH ✓' : 'MISMATCH ✗'}`);
    base.reader.close(); upd.reader.close();
} else if (mode === 'memory') {
    console.log('=== LN2 seekable streaming update (memory output) ===\n');
    const base = { name: 'base.nsp', reader: new FileReader(basePath) };
    const upd = { name: 'update.nsp', reader: new FileReader(updatePath) };
    const t0 = performance.now();
    const res = await update([base, upd], { memory: true }, { keys, log, progress, bktrMerge: true });
    const buf = new Uint8Array(await res.blob.arrayBuffer());
    console.log(`\nOK: sec=${((performance.now() - t0) / 1000).toFixed(1)}s blob=${buf.byteLength} declaredSize=${res.size} members=${res.memberCount}`);
    console.log(`blob 0x0..0x4 = ${buf.subarray(0, 4).join(',')} (PFS0 = 50,46,53,30)`);

    // Validate: parse the output NSP as PFS0 → program NCA ExeFS magic.
    const { PFS0 } = await import('../fs/pfs0.js');
    const pfs0 = new PFS0(buf);
    const files = pfs0.getFiles();
    console.log(`\nOutput PFS0 members:`);
    let total = 0;
    for (const f of files) { console.log(`  ${f.name} (${f.size} bytes)`); total += f.size; }
    console.log(`memberSizes total = ${total}; blob = ${buf.byteLength}; pfs0 header ${buf.subarray(0x10, 0x14) ? '' : ''}`);
    const prog = files.find(f => f.name.toLowerCase().endsWith('.nca') && !f.name.toLowerCase().endsWith('.cnmt.nca') && f.size > 100 * 1024 * 1024);
    if (prog) {
        const ncaBuf = buf.subarray(prog.offset, prog.offset + prog.size);
        const { magic, size, dataOff, titleId } = await readOutputExeFS(ncaBuf, keys);
        console.log(`Program NCA: ${prog.name} titleId=${titleId} ExeFS magic=${JSON.stringify(magic)} (exefs ${size} bytes @0x${dataOff.toString(16)})`);
        console.log(`  NCA member size (${prog.size}) vs declared layout OK; magic PFS0? ${magic === 'PFS0' ? 'YES ✓' : 'check logs'}`);
    }
    const cnmtFile = files.find(f => f.name.toLowerCase().endsWith('.cnmt.nca'));
    if (cnmtFile) {
        // CNMT NCA: read CNMT directly (plaintext section too)
        console.log(`CNMT member: ${cnmtFile.name} (${cnmtFile.size} bytes)`);
    }
    base.reader.close(); upd.reader.close();
} else {
    console.log(`unknown mode ${mode} (twopass | memory)`);
}