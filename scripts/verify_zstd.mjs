#!/usr/bin/env node
// verify_zstd.mjs — cross-validates crypto/zstd.js frame inspection against
// the reference decoder (the @tootallnate/zstd-wasm streaming decoder — raw
// ZSTD_decompressStream via decompress_stream) for every frame header encoding
// the zstd 1.5.7 spec defines (FCS field sizes 0/1/2/4, single/multi segment,
// RLE and compressed blocks, empty content, checksum flag, strict
// trailing-garbage rejection). Run: node scripts/verify_zstd.mjs

import { zstdCompressSync, zstdDecompressSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { inspectFrame, compressBlock, decompressBlock, decompressStream, setZstdStreamForcedWasm } from '../crypto/zstd.js';

let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
    if (cond) { pass++; console.log('PASS  ' + name + (extra ? '  (' + extra + ')' : '')); }
    else { fail++; console.log('FAIL  ' + name + (extra ? '  (' + extra + ')' : '')); }
}
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// ---------- tootallnate wasm reference decoder (raw driver) ----------
const bytes = new Uint8Array(readFileSync(new URL('../static/zstd.wasm', import.meta.url)));
const { instance } = await WebAssembly.instantiate(bytes, {});
const $ = instance.exports;
const BUF = { SRC: 0, SRC_SIZE: 4, SRC_POS: 8, DST: 12, DST_SIZE: 16, DST_POS: 20, SIZE: 24 };
const dInCap = $.dstream_in_size(), dOutCap = $.dstream_out_size();
const dinP = $.zstd_malloc(dInCap), doutP = $.zstd_malloc(dOutCap), dbufP = $.zstd_malloc(BUF.SIZE);

// Reference decode: feed `frame` in dInCap slices through a FRESH dctx and
// return { out } or { err }. Mirrors the facade's runDecompress logic.
function refDecompress(frame) {
    const dctx = $.dctx_new();
    const parts = [];
    try {
        for (let off = 0; off < frame.length; off += dInCap) {
            const take = Math.min(frame.length - off, dInCap);
            new Uint8Array($.memory.buffer).set(frame.subarray(off, off + take), dinP);
            let srcPos = 0;
            while (srcPos < take) {
                let view = new DataView($.memory.buffer, dbufP, BUF.SIZE);
                view.setUint32(BUF.SRC, dinP, true); view.setUint32(BUF.SRC_SIZE, take, true); view.setUint32(BUF.SRC_POS, srcPos, true);
                view.setUint32(BUF.DST, doutP, true); view.setUint32(BUF.DST_SIZE, dOutCap, true); view.setUint32(BUF.DST_POS, 0, true);
                const r = $.decompress_stream(dctx, dbufP);
                if ($.is_error(r)) return { err: 'ZSTD_decompressStream error ' + r };
                view = new DataView($.memory.buffer, dbufP, BUF.SIZE);
                const dp = view.getUint32(BUF.DST_POS, true);
                if (dp) parts.push(new Uint8Array($.memory.buffer, doutP, dp).slice());
                const ns = view.getUint32(BUF.SRC_POS, true);
                if (ns === srcPos && dp === 0) return { err: 'decoder made no progress' };
                srcPos = ns;
                if (r === 0) { if (srcPos < take) return { err: 'trailing bytes after frame end' }; break; }
            }
        }
        const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
        let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
        return { out };
    } finally {
        $.dctx_free(dctx);
    }
}

// ---------- positive matrix: sizes hitting every FCS encoding ----------
const text = (n, seed = 0) => { const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = (i * 7 + seed * 13 + 11) & 0xff; return b; };
const cases = [
    ['empty', new Uint8Array(0)],
    ['1B', new Uint8Array([0x42])],
    ['100B (1B FCS)', text(100, 1)],
    ['255B (1B FCS max)', text(255, 2)],
    ['256B (2B FCS min)', text(256, 3)],
    ['257B (2B FCS)', text(257, 4)],
    ['1KiB zeros (2B FCS)', new Uint8Array(1024)],
    ['3KiB zeros (2B FCS)', new Uint8Array(3000)],
    ['65535B (2B FCS max)', text(65535, 5)],
    ['65536B (4B FCS min)', text(65536, 6)],
    ['65537B (4B FCS)', text(65537, 7)],
    ['1MiB text (4B FCS)', text(1 << 20, 8)],
    ['1MiB random (4B FCS)', new Uint8Array(randomBytes(1 << 20))],
];

for (const [name, src] of cases) {
    const frame = new Uint8Array(zstdCompressSync(Buffer.from(src)));
    const ins = inspectFrame(frame);
    ok(`${name}: inspectFrame`, !!ins && (!ins.hasContentSize || ins.contentSize === src.length), `contentSize=${ins ? ins.contentSize : 'null'} has=${ins ? ins.hasContentSize : 'null'}`);
    const rd = refDecompress(frame);
    ok(`${name}: wasm ref roundtrip`, !rd.err && eq(rd.out, src), rd.err ?? `${rd.out.length} B`);
    // facade roundtrip via forced-WASM one-shot (decompressBlock)
    setZstdStreamForcedWasm(true);
    const back = await decompressBlock(frame, src.length);
    ok(`${name}: facade decompressBlock (forced wasm)`, eq(back, src), `${back.length} B`);
    // facade roundtrip via forced-WASM streaming (decompressStream)
    let total = 0, off = 0; const CHUNK = 65536;
    let err = null;
    try {
        for await (const c of decompressStream(async () => {
            if (off >= frame.length) return null;
            const d = frame.subarray(off, Math.min(off + CHUNK, frame.length));
            off = Math.min(off + CHUNK, frame.length);
            return d;
        }, src.length, frame.length)) total += c.length;
    } catch (e) {
        err = e.message;
    }
    setZstdStreamForcedWasm(false);
    ok(`${name}: facade decompressStream (forced wasm)`, err === null && total === src.length, err ?? `${total} B`);
}

// ---------- hand-built frames: exact encodings the matrix may not hit ----------
function u32le(b, o, v) { b[o] = v & 255; b[o + 1] = (v >> 8) & 255; b[o + 2] = (v >> 16) & 255; b[o + 3] = (v >>> 24) & 255; }

// RLE block: header size = repeat count, body = 1 byte (the value)
{
    const n = 300, val = 0x7e;
    const frame = new Uint8Array(4 + 1 + 2 + 3 + 1);
    frame.set([0x28, 0xb5, 0x2f, 0xfd, 0x60], 0); // 2-byte FCS, single segment
    frame[5] = n - 256; frame[6] = 0;             // 2-byte FCS stores size - 256
    u32le(frame, 7, ((n << 3) | (1 << 1) | 1) & 0xffffff); // last, RLE, repeat count
    frame[10] = val;
    const ins = inspectFrame(frame);
    ok('RLE frame: inspectFrame', !!ins && ins.contentSize === n, `contentSize=${ins ? ins.contentSize : 'null'}`);
    const rd = refDecompress(frame);
    ok('RLE frame: wasm roundtrip', !rd.err && rd.out.length === n && rd.out.every(v => v === val), rd.err ?? `${rd.out.length} B`);
}

// multi-block frame (two raw blocks, last flag only on the second)
{
    const a = new Uint8Array([1, 2, 3]), b = new Uint8Array([4, 5, 6, 7]);
    const frame = new Uint8Array(4 + 1 + 1 + (3 + 3) + (3 + 4));
    frame.set([0x28, 0xb5, 0x2f, 0xfd, 0x20], 0); // single segment, 1-byte FCS
    frame[5] = a.length + b.length;
    u32le(frame, 6, (a.length << 3) | (0 << 1) | 0); // raw, not last
    frame.set(a, 9);
    u32le(frame, 9 + a.length, (b.length << 3) | (0 << 1) | 1); // raw, last
    frame.set(b, 12 + a.length);
    const ins = inspectFrame(frame);
    ok('multi-block raw frame: inspectFrame', !!ins && ins.contentSize === 7, `contentSize=${ins ? ins.contentSize : 'null'}`);
    const rd = refDecompress(frame);
    ok('multi-block raw frame: wasm roundtrip', !rd.err && eq(rd.out, new Uint8Array([1, 2, 3, 4, 5, 6, 7])), rd.err ?? '');
}

// non-single-segment frame (window descriptor present), no FCS field
{
    const src = text(1000, 9);
    const f = new Uint8Array(4 + 1 + 1 + (3 + 1000));
    f.set([0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x50], 0); // desc 0, window descriptor 0x50
    u32le(f, 6, (1000 << 3) | (0 << 1) | 1); // single raw block, last
    f.set(src, 9);
    const ins = inspectFrame(f);
    ok('window-desc frame (no FCS): inspectFrame', !!ins && ins.contentSize === 0, `contentSize=${ins ? ins.contentSize : 'null'}`);
    const rd = refDecompress(f);
    ok('window-desc frame (no FCS): wasm roundtrip', !rd.err && eq(rd.out, src), rd.err ?? `${rd.out.length} B`);
}

// checksum flag (bit 2): 4-byte trailer, shape-only validation
{
    const frame = new Uint8Array(4 + 1 + 1 + 3 + 2 + 4);
    frame.set([0x28, 0xb5, 0x2f, 0xfd, 0x24], 0); // single segment, checksum bit set
    frame[5] = 2;
    u32le(frame, 6, (2 << 3) | (0 << 1) | 1); // raw, last
    frame.set([0xaa, 0xbb], 9);
    u32le(frame, 11, 0x12345678); // fake xxh32 (shape test; value is the decoder's job)
    ok('checksum frame: inspectFrame', inspectFrame(frame) !== null);
    ok('checksum frame truncated at checksum: reject', inspectFrame(frame.subarray(0, 14)) === null);
    const rd = refDecompress(frame);
    ok('checksum frame: wasm rejects wrong checksum (as expected)', !!rd.err, rd.err ?? 'accepted?!');
}

// ---------- negative cases ----------
{
    const src = text(5000, 10);
    const frame = new Uint8Array(zstdCompressSync(Buffer.from(src)));

    ok('truncated (1B off end): reject', inspectFrame(frame.subarray(0, frame.length - 1)) === null);
    ok('truncated (header only): reject', inspectFrame(frame.subarray(0, 5)) === null);

    const trailing = new Uint8Array(frame.length + 8);
    trailing.set(frame, 0); trailing.set([9, 9, 9, 9, 9, 9, 9, 9], frame.length);
    ok('trailing garbage: reject', inspectFrame(trailing) === null);

    const two = new Uint8Array(frame.length * 2);
    two.set(frame, 0); two.set(frame, frame.length);
    ok('two frames: reject', inspectFrame(two) === null);

    const skippable = new Uint8Array([0x28, 0xb5, 0x2f, 0x30, 0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4]);
    ok('skippable frame: reject', inspectFrame(skippable) === null);

    const reserved = new Uint8Array(frame);
    reserved[4] |= 0x08;
    ok('reserved bit set: reject', inspectFrame(reserved) === null);

    const zeroCompressed = new Uint8Array(4 + 1 + 1 + 3);
    zeroCompressed.set([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0], 0);
    zeroCompressed[6] = (0 << 3) | (2 << 1) | 1; // compressed, size 0, last
    ok('zero-size compressed block: reject', inspectFrame(zeroCompressed) === null);

    const noLastBlock = new Uint8Array(4 + 1 + 1 + 6 + 3);
    noLastBlock.set([0x28, 0xb5, 0x2f, 0xfd, 0x20, 0], 0);
    u32le(noLastBlock, 6, (3 << 3) | 0); // raw, NOT last
    noLastBlock.set([1, 2, 3], 9);
    ok('no last block before EOF: reject', inspectFrame(noLastBlock) === null);

    // RLE body is exactly 1 byte: a second body byte is trailing garbage
    const badRle = new Uint8Array(4 + 1 + 2 + 3 + 2);
    badRle.set([0x28, 0xb5, 0x2f, 0xfd, 0x60], 0);
    badRle[5] = 300 - 256; badRle[6] = 0;
    u32le(badRle, 7, ((300 << 3) | (1 << 1) | 1) & 0xffffff);
    badRle.set([0x11, 0x12], 10);
    ok('RLE with 2-byte body: reject', inspectFrame(badRle) === null);
}

// ---------- facade compress cross-compat (forced-wasm encoder) ----------
{
    const src = text(1 << 20, 11);
    setZstdStreamForcedWasm(true);
    const wasmFrame = await compressBlock(src, 18);
    setZstdStreamForcedWasm(false);
    // The tootallnate encoder emits multi-segment frames with NO FCS field —
    // inspectFrame must still accept the shape; the ref decoder must roundtrip.
    const ins = inspectFrame(wasmFrame);
    ok('compressBlock (wasm) frame: inspectFrame (valid, no FCS)', !!ins && !ins.hasContentSize, `has=${ins ? ins.hasContentSize : 'null'}`);
    const rd = refDecompress(wasmFrame);
    ok('compressBlock (wasm) frame: wasm ref decodes byte-identical', !rd.err && eq(rd.out, src), rd.err ?? `${rd.out.length} B`);
    const nodeBack = new Uint8Array(zstdDecompressSync(Buffer.from(wasmFrame)));
    ok('compressBlock (wasm) frame: node decodes byte-identical', eq(nodeBack, src));
}

// ---------- facade one-shot decompress of a node:zlib frame (forced-wasm) ----------
{
    const src = text(1 << 20, 12);
    const nodeFrame = new Uint8Array(zstdCompressSync(Buffer.from(src), { level: 18 }));
    setZstdStreamForcedWasm(true);
    const back = await decompressBlock(nodeFrame, src.length);
    setZstdStreamForcedWasm(false);
    ok('decompressBlock (wasm) of node frame: byte-identical', eq(back, src), `${back.length} B`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
