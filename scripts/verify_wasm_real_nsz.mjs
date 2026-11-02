#!/usr/bin/env node
// verify_wasm_real_nsz.mjs — decompress a real .nsz through the FORCED-WASM
// path (the exact browser code path: true streaming push through the
// tootallnate wasm decoder — ZSTD_decompressStream fed chunk by chunk, output
// yielded as produced) and prove it byte-identical:
//   - with [expected-payload-sha256]: compare the WASM payload hash against it
//     (payload = NCA bytes 0x4000..ncaSize, sections decrypted per NCZSECTN)
//   - without: A/B the forced-WASM path against the native Node (node:zlib)
//     path and require byte-identical hashes.
// Usage: node scripts/verify_wasm_real_nsz.mjs path/to/file.nsz [expected-payload-sha256]

import { openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PFS0 } from '../fs/pfs0.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { setZstdStreamForcedWasm } from '../crypto/zstd.js';

const path = process.argv[2];
const expected = process.argv[3] || null;
if (!path) {
    console.error('usage: node scripts/verify_wasm_real_nsz.mjs file.nsz [expected-payload-sha256]');
    process.exit(1);
}

const fd = openSync(path, 'r');
const stat = { read };
async function read(offset, size) {
    const buf = Buffer.alloc(size);
    readSync(fd, buf, 0, size, offset);
    return new Uint8Array(buf);
}

// Hash the decompressed payload region (0x4000..ncaSize) as it flows through
// writeChunk (sections already decrypted per the NCZSECTN table).
async function hashPayload(f) {
    const reader = new AdapterNCZReader(stat, f.offset, f.size);
    const parsed = await parseNczSections(reader);
    const nczd = new NCZDecompressor(reader);
    const h = createHash('sha256');
    let payloadBytes = 0;
    const t0 = Date.now();
    await nczd.decompress(null, async (chunk, pos) => {
        if (pos >= 0x4000) { h.update(chunk); payloadBytes += chunk.length; }
    }, parsed);
    const ms = Date.now() - t0;
    return { hex: h.digest('hex'), payloadBytes, expectedPayload: parsed.ncaSize - 0x4000, ms, ncaSize: parsed.ncaSize };
}

const pfs0 = await PFS0.open(stat);
const files = pfs0.getFiles();
const nczs = files.filter(f => f.name.toLowerCase().endsWith('.ncz'));
if (!nczs.length) { console.error('no NCZ members found'); process.exit(1); }

let failed = false;
for (const ncz of nczs) {
    // Forced-WASM run (browser code path).
    setZstdStreamForcedWasm(true);
    const wasm = await hashPayload(ncz);
    setZstdStreamForcedWasm(false);
    const ref = expected ? { hex: expected, payloadBytes: wasm.payloadBytes } : await hashPayload(ncz); // native node:zlib path
    const okSize = wasm.payloadBytes === wasm.expectedPayload;
    const okHash = okSize && wasm.hex === ref.hex;
    const mode = expected ? 'expected hash' : 'A/B vs node:zlib';
    console.log(`${ncz.name}: ncaSize=${wasm.ncaSize} payload=${wasm.payloadBytes}/${wasm.expectedPayload}`);
    console.log(`  wasm sha256=${wasm.hex} (${(wasm.ms / 1000).toFixed(1)}s, ${(wasm.payloadBytes / 1048576 / (wasm.ms / 1000)).toFixed(1)} MB/s)`);
    if (!expected) console.log(`  node sha256=${ref.hex} (${(ref.ms / 1000).toFixed(1)}s)`);
    if (okHash) console.log(`PASS  ${ncz.name} (${mode})`);
    else {
        console.error(`FAIL  ${ncz.name} (${mode})` + (!okSize ? ' — payload size mismatch' : ` — hash mismatch (expected ${ref.hex})`));
        failed = true;
    }
}
closeSync(fd);
process.exit(failed ? 1 : 0);
