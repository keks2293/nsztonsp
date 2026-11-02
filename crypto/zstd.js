// zstd backend facade — single seam for compress + decompress.
//
// Node (CLI / scripts): native node:zlib (zstdCompressSync / zstdDecompressSync /
// createZstdDecompress). Browser: ONE @tootallnate/zstd-wasm build
// (static/zstd.wasm, an unmodified copy of
// node_modules/@tootallnate/zstd-wasm/dist/zstd.wasm) for BOTH compress and
// decompress, using its TRUE streaming APIs (ZSTD_compressStream2 /
// ZSTD_decompressStream via compress_stream / decompress_stream).
//
// Driver design — ONE shared WebAssembly instance, FRESH context per op:
//   * The instance's linear memory is the expensive part. It starts at 8 MiB
//     and self-grows via wasi-libc sbrk (the module has NO imports — no
//     grow-heap callback needed). It is loaded once and shared by every op.
//   * Each op allocates its OWN cctx/dctx plus its own in/out/buf I/O buffers
//     and frees them when done. This is deliberate: a dctx is PERMANENTLY
//     TAINTED after any decompress_stream error (every later call on it
//     returns a -10 generic error), so reusing a shared one-shot context across
//     ops would silently poison all later decompression after a single corrupt
//     block. A fresh context per op makes the taint impossible to leak.
//     (Reusing a context across *successful* frames works, but error-safety
//     wins; dctx_new/cctx_new are cheap small mallocs.)
//   * Views into memory.buffer MUST be re-acquired after every wasm call — a
//     heap growth detaches every existing ArrayBuffer-backed view.
//
// Strictness:
//   * One-shot path (decompressBlock): inspectFrame() — the spec-verified strict
//     single-frame gate (rejects bad header, truncation, trailing bytes,
//     multi-frame payloads) — plus a decode and an EXACT byte-count check
//     against expectedSize (or the frame's declared content size).
//   * Streaming path (decompressStream): a true streaming push (chunks fed as
//     they arrive, output yielded as it is produced — the wasm heap stays
//     bounded by the frame window, not the payload size). Gates = an EXACT
//     decompressed byte-count against expectedSize (throw on `>` mid-stream,
//     `<` at end — this catches silent mid-frame truncation) plus the decoder's
//     own trailing-garbage rejection (it refuses input after the frame ends).
//   node:zlib silently tolerates trailing garbage after a complete frame (which
//   is why the NCZ reader-length bug #43 sailed through the Node suite); the
//   browser/forced-WASM path stays strict via the gates above.

import { isNode } from './platform.js';

// ---------- @tootallnate/zstd-wasm raw driver ----------
// The module's named exports (verified on load — see verifyExports). The push/
// finish loop logic is ported from the package's dist/index.js (MIT).
const REQUIRED_EXPORTS = [
    'memory',
    'zstd_malloc', 'zstd_free',
    'cctx_new', 'cctx_free', 'cctx_set_level', 'compress_stream',
    'cstream_in_size', 'cstream_out_size',
    'dctx_new', 'dctx_free', 'decompress_stream',
    'dstream_in_size', 'dstream_out_size',
    'is_error', 'get_error_name',
];

// The shared in/out cursor struct (wrapper.c `JsBuf`): six u32 LE fields.
const BUF = { SRC: 0, SRC_SIZE: 4, SRC_POS: 8, DST: 12, DST_SIZE: 16, DST_POS: 20, SIZE: 24 };

function readCString($, ptr) {
    const bytes = new Uint8Array($.memory.buffer, ptr);
    let end = 0;
    while (bytes[end] !== 0 && end < bytes.length) end++;
    return new TextDecoder().decode(bytes.subarray(0, end));
}

function checkError($, ret) {
    if ($.is_error(ret)) {
        // This build ships with error strings stripped, so the name is a fixed
        // placeholder; include the numeric code so failures are diagnosable.
        const name = readCString($, $.get_error_name(ret));
        throw new Error(`zstd: ${name} (code ${ret})`);
    }
}

let wasmPromise = null;

async function loadWasmBytes() {
    if (isNode) {
        const { readFileSync } = await import('node:fs');
        return new Uint8Array(readFileSync(new URL('../static/zstd.wasm', import.meta.url)));
    }
    // Resolve against the page URL (works both in dev — page at repo root —
    // and in the esbuild bundle, where the page URL points at out/ and the
    // asset is copied to out/static/ by build.js).
    const base = (typeof document !== 'undefined' && document.baseURI) || new URL('./', import.meta.url).href;
    const resp = await fetch(new URL('static/zstd.wasm', base));
    if (!resp.ok) throw new Error(`Failed to load static/zstd.wasm (HTTP ${resp.status})`);
    return new Uint8Array(await resp.arrayBuffer());
}

function verifyExports($) {
    for (const name of REQUIRED_EXPORTS) {
        if (name === 'memory') {
            if (!$.memory || !$.memory.buffer) throw new Error('zstd wasm: missing/invalid export "memory" (layout mismatch — @tootallnate/zstd-wasm version?)');
        } else if (typeof $[name] !== 'function') {
            throw new Error(`zstd wasm: missing export "${name}" (layout mismatch — @tootallnate/zstd-wasm version?)`);
        }
    }
}

// Self-test: a level-3 and level-18 compress→decompress roundtrip through the
// raw driver. Runs once on load; throws loudly if the backend is broken.
function verifyBackend($) {
    const data = new Uint8Array(64);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7) & 0xff;
    for (const level of [3, 18]) {
        const frame = compressWith($, data, level);
        const back = decompressWith($, frame, data.length);
        if (back.length !== data.length) throw new Error(`zstd wasm self-test: roundtrip size mismatch (level ${level})`);
        for (let i = 0; i < data.length; i++) if (back[i] !== data[i]) throw new Error(`zstd wasm self-test: roundtrip mismatch (level ${level})`);
    }
}

async function loadWasm() {
    if (!wasmPromise) {
        wasmPromise = (async () => {
            const bytes = await loadWasmBytes();
            // No imports: wasi-libc grows the heap itself via sbrk.
            const { instance } = await WebAssembly.instantiate(bytes, {});
            const $ = instance.exports;
            verifyExports($);
            verifyBackend($);
            return $;
        })();
    }
    return wasmPromise;
}

// ---------- zstd frame inspector (strict trailing-garbage semantics) ----------
// Validates that `data` is EXACTLY one complete zstd frame (zstd 1.5.7 spec,
// magic 0xFD2FB528 LE): magic + frame header + >=1 data block + optional
// content checksum, ending exactly at data.length. Frame header layout
// (Frame_Header_Descriptor bit positions per spec, decoder-verified):
//   bits 7-6  Frame_Content_Size_flag: 0 -> 1B FCS if single-segment else none,
//             1 -> 2B (stores size-256), 2 -> 4B, 3 -> 8B (all LE, direct)
//   bit  5    Single_Segment_flag (no window descriptor when set)
//   bit  4    unused
//   bit  3    reserved — must be 0 (decoder: frameParameter_unsupported)
//   bit  2    Content_Checksum_flag (single bit; 4-byte xxh32 at frame end)
//   bits 1-0  Dictionary_ID_flag -> 0/1/2/4-byte field (before the FCS field)
// Blocks: 3-byte LE header (bit 0 last, bits 1-2 type, bits 3-23 size) + body.
//   type 0 raw / 2 compressed: body = size (size 0 compressed cannot decode);
//   type 1 RLE: body is always 1 byte (header size = repeat count / output);
//   type 3 reserved: invalid.
// Returns { contentSize, hasContentSize } (declared FCS; contentSize is 0
// both when the field is absent and when it declares an empty frame —
// hasContentSize disambiguates) or null when the input is a bad header, a
// truncated frame, has trailing bytes, or is a multi-frame payload. Used as the
// one-shot gate: it reproduces the old zstddec streaming strictness (which
// rejected trailing garbage) for the non-streaming path.
export function inspectFrame(data) {
    if (data.length < 4 || data[0] !== 0x28 || data[1] !== 0xb5 || data[2] !== 0x2f || data[3] !== 0xfd) return null;
    let pos = 4;
    const desc = data[pos++];
    const fcsFlag = (desc >> 6) & 3;
    const singleSegment = (desc >> 5) & 1;
    const hasChecksum = (desc >> 2) & 1;
    if ((desc & 0x08) !== 0) return null; // reserved bit must be zero
    if (!singleSegment) pos++; // 1-byte window descriptor (consumed, not validated)
    const dictIdFlag = desc & 3;
    pos += [0, 1, 2, 4][dictIdFlag]; // 0 / 1 / 2 / 4-byte Dictionary_ID field
    const fcsLen = fcsFlag === 0 ? (singleSegment ? 1 : 0) : fcsFlag === 1 ? 2 : fcsFlag === 2 ? 4 : 8;
    if (pos + fcsLen > data.length) return null;
    let contentSize = 0; // 0 = not provided
    if (fcsLen > 0) {
        const lo = (data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16) | (data[pos + 3] << 24)) >>> 0;
        if (fcsLen === 1) contentSize = data[pos];
        else if (fcsLen === 2) contentSize = (data[pos] | (data[pos + 1] << 8)) + 256; // spec: 2-byte field stores size - 256
        else if (fcsLen === 4) contentSize = lo;
        else { // 8: LE64, read directly (no "unknown" sentinel exists in the spec)
            const hi = (data[pos + 4] | (data[pos + 5] << 8) | (data[pos + 6] << 16) | (data[pos + 7] << 24)) >>> 0;
            contentSize = hi === 0 ? lo : Number((BigInt(hi) << 32n) | BigInt(lo));
        }
        pos += fcsLen;
    }
    for (;;) { // spec: each frame has at least one block
        if (pos + 3 > data.length) return null;
        const bh = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16);
        const last = bh & 1;
        const type = (bh >> 1) & 3; // 0 raw, 1 RLE, 2 compressed, 3 reserved
        const size = bh >> 3;
        pos += 3;
        if (type === 3) return null;
        let body = size;
        if (type === 1) body = 1; // RLE body is a single byte; header size is the repeat count
        else if (type === 2 && size === 0) return null; // zero-size compressed block cannot decode
        if (pos + body > data.length) return null;
        pos += body;
        if (last) break;
    }
    if (hasChecksum) {
        if (pos + 4 > data.length) return null;
        pos += 4;
    }
    if (pos !== data.length) return null; // trailing garbage / multi-frame payload
    return { contentSize, hasContentSize: fcsLen > 0 };
}

// ---------- raw-driver core ops (fresh context per op; `$` is the instance) ----------

// Drive the compressor over one input slice (already copied into
// [inP, inP+size)) with the given endOp (0 = continue, 2 = end), calling
// onOutput with each non-empty Uint8Array view produced. Ported from
// @tootallnate/zstd-wasm (MIT). Views are re-acquired every iteration because
// a heap growth detaches them.
function runCompress($, cctx, inP, outP, bufP, outCap, size, endOp, onOutput) {
    let srcPos = 0;
    for (;;) {
        let view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        view.setUint32(BUF.SRC, inP, true);
        view.setUint32(BUF.SRC_SIZE, size, true);
        view.setUint32(BUF.SRC_POS, srcPos, true);
        view.setUint32(BUF.DST, outP, true);
        view.setUint32(BUF.DST_SIZE, outCap, true);
        view.setUint32(BUF.DST_POS, 0, true);
        const ret = $.compress_stream(cctx, bufP, endOp);
        checkError($, ret);
        // Memory may have grown — refresh the view before reading it back.
        view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        const dstPos = view.getUint32(BUF.DST_POS, true);
        if (dstPos > 0) onOutput(new Uint8Array($.memory.buffer, outP, dstPos));
        srcPos = view.getUint32(BUF.SRC_POS, true);
        if (endOp === 0) {
            if (srcPos >= size) break; // all input consumed
        } else if (ret === 0) {
            break; // end/flush: internal buffers drained
        }
    }
}

// Compress `data` into one self-contained zstd frame at `level`. Fresh cctx,
// freed when done.
function compressWith($, data, level) {
    const cctx = $.cctx_new();
    if (!cctx) throw new Error('zstd wasm: failed to allocate compressor context');
    const inCap = $.cstream_in_size();
    const outCap = $.cstream_out_size();
    const inP = $.zstd_malloc(inCap);
    const outP = $.zstd_malloc(outCap);
    const bufP = $.zstd_malloc(BUF.SIZE);
    if (!inP || !outP || !bufP) {
        $.cctx_free(cctx);
        throw new Error('zstd wasm: failed to allocate streaming buffers');
    }
    try {
        checkError($, $.cctx_set_level(cctx, level)); // applies to the next frame
        const parts = [];
        let total = 0;
        const onOutput = (view) => {
            const copy = new Uint8Array(view);
            parts.push(copy);
            total += copy.length;
        };
        // Input MUST be sliced into inCap-sized pieces (the wasm input buffer
        // bound); feeding more at once silently corrupts the heap.
        for (let off = 0; off < data.length; off += inCap) {
            const take = Math.min(data.length - off, inCap);
            new Uint8Array($.memory.buffer).set(data.subarray(off, off + take), inP);
            runCompress($, cctx, inP, outP, bufP, outCap, take, 0, onOutput);
        }
        runCompress($, cctx, inP, outP, bufP, outCap, 0, 2, onOutput); // end
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    } finally {
        $.cctx_free(cctx);
        $.zstd_free(inP);
        $.zstd_free(outP);
        $.zstd_free(bufP);
    }
}

// Drive the decoder over one input slice (already copied into
// [inP, inP+size)) until it is fully consumed, calling onOutput with each
// non-empty Uint8Array view produced. Ported from @tootallnate/zstd-wasm (MIT),
// tightened: a frame that ends before the slice is exhausted is trailing
// garbage (the streaming path relies on this; the one-shot path is already
// gated by inspectFrame). Views are re-acquired every iteration.
function runDecompress($, dctx, inP, outP, bufP, outCap, size, onOutput) {
    let srcPos = 0;
    while (srcPos < size) {
        let view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        view.setUint32(BUF.SRC, inP, true);
        view.setUint32(BUF.SRC_SIZE, size, true);
        view.setUint32(BUF.SRC_POS, srcPos, true);
        view.setUint32(BUF.DST, outP, true);
        view.setUint32(BUF.DST_SIZE, outCap, true);
        view.setUint32(BUF.DST_POS, 0, true);
        const ret = $.decompress_stream(dctx, bufP);
        checkError($, ret);
        // Memory may have grown — refresh the view before reading it back.
        view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        const dstPos = view.getUint32(BUF.DST_POS, true);
        if (dstPos > 0) onOutput(new Uint8Array($.memory.buffer, outP, dstPos));
        const newSrcPos = view.getUint32(BUF.SRC_POS, true);
        if (newSrcPos === srcPos && dstPos === 0) throw new Error('zstd: decoder made no progress');
        srcPos = newSrcPos;
        if (ret === 0) { // frame fully decoded
            if (srcPos < size) throw new Error('zstd: trailing bytes after frame end');
            break;
        }
    }
}

// One-shot decompress. expectedSize: the exact decompressed size (authoritative
// container metadata); when 0, the frame's declared content size is the gate.
// Fresh dctx, freed when done.
function decompressWith($, data, expectedSize = 0) {
    const frame = inspectFrame(data);
    if (!frame) throw new Error('zstd: invalid frame (bad header, truncated, or trailing bytes)');
    const cap = expectedSize > 0 ? expectedSize : (frame.hasContentSize ? frame.contentSize : 0);
    const dctx = $.dctx_new();
    if (!dctx) throw new Error('zstd wasm: failed to allocate decompressor context');
    const inCap = $.dstream_in_size();
    const outCap = $.dstream_out_size();
    const inP = $.zstd_malloc(inCap);
    const outP = $.zstd_malloc(outCap);
    const bufP = $.zstd_malloc(BUF.SIZE);
    if (!inP || !outP || !bufP) {
        $.dctx_free(dctx);
        throw new Error('zstd wasm: failed to allocate streaming buffers');
    }
    try {
        const parts = [];
        let total = 0;
        const onOutput = (view) => {
            const copy = new Uint8Array(view);
            parts.push(copy);
            total += copy.length;
            if (cap > 0 && total > cap) throw new Error(`zstd: decompressed size exceeds expected (${cap})`);
        };
        // Same inCap slicing rule as the compressor.
        for (let off = 0; off < data.length; off += inCap) {
            const take = Math.min(data.length - off, inCap);
            new Uint8Array($.memory.buffer).set(data.subarray(off, off + take), inP);
            runDecompress($, dctx, inP, outP, bufP, outCap, take, onOutput);
        }
        if (cap > 0 && total !== cap) throw new Error(`zstd: size mismatch (got ${total}, expected ${cap})`);
        const out = new Uint8Array(total);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    } finally {
        $.dctx_free(dctx);
        $.zstd_free(inP);
        $.zstd_free(outP);
        $.zstd_free(bufP);
    }
}

// ---------- node:zlib backend ----------

let nodeZlibPromise = null;
function nodeZlib() {
    if (!nodeZlibPromise) nodeZlibPromise = import('node:zlib');
    return nodeZlibPromise;
}

// node:zlib zstd params. Keys MUST be the numeric ZSTD_c_* constants (string
// names are rejected: "X is not a valid zstd parameter"). Long mode (python
// nsz -L) = libzstd's defaults for the level + LDM enabled — python-zstandard
// from_level(level, enable_ldm=True) leaves the ldm sub-parameters default.
async function zstdCompressParams(level, ldm) {
    const zlib = await nodeZlib();
    const params = { [zlib.constants.ZSTD_c_compressionLevel]: level };
    if (ldm) params[zlib.constants.ZSTD_c_enableLongDistanceMatching] = 1;
    return params;
}

async function compressNode(data, level, ldm = false) {
    const zlib = await nodeZlib();
    return new Uint8Array(zlib.zstdCompressSync(data, { params: await zstdCompressParams(level, ldm) }));
}

async function decompressNode(data) {
    const zlib = await nodeZlib();
    return new Uint8Array(zlib.zstdDecompressSync(data));
}

// ---------- public API ----------

// Test/bench override: when true, force the tootallnate WASM backend for ALL
// ops (compressBlock / decompressBlock / decompressStream / ZstdDecompressor)
// even under Node, where node:zlib is the default. node:zlib silently
// tolerates trailing garbage after a frame (which is why the NCZ reader-length
// bug #43 sailed through the Node test suite), while the WASM backend gates the
// decompressed byte count and the decoder rejects trailing garbage. The
// override lets tests hit the strict path and Node-side benchmarks A/B
// backends. (Browser is already forced-WASM — isNode is false there.)
let forceWasm = false;
export function setZstdStreamForcedWasm(v = false) { forceWasm = v; }

// Compress one chunk into a self-contained zstd frame (NCZ block / payload).
// Node uses in-process node:zlib; browser (and forced-WASM) uses the
// tootallnate WASM encoder.
// ldm (long-distance matching, python nsz -L) needs the node:zlib parameter
// API — the tootallnate wasm exposes no compressor parameters, so it is
// CLI-only.
// Whether a chunk is stored raw (incompressible) vs compressed is
// container-level knowledge kept in fs/compress.js, not here.
export async function compressBlock(data, level = 18, ldm = false) {
    if (ldm && !isNode) {
        throw new Error('zstd long mode (LDM) is CLI-only: the browser wasm build has no compressor parameters');
    }
    if (isNode && !forceWasm) return compressNode(data, level, ldm);
    const $ = await loadWasm();
    return compressWith($, data, level);
}

// Decompress one zstd frame. expectedSize: exact decompressed size when known
// (NCZ block size); 0 falls back to the frame's declared content size.
export async function decompressBlock(data, expectedSize = 0) {
    if (isNode && !forceWasm) return decompressNode(data);
    const $ = await loadWasm();
    return decompressWith($, data, expectedSize);
}

// Node streaming backend: push-compressed model (write/end + backpressure),
// output consumed concurrently via the async iterator so the zlib transform
// stream never deadlocks on a full readable buffer.
async function* decompressNodeStream(readChunk) {
    const { createZstdDecompress } = await import('node:zlib');
    const decompressor = createZstdDecompress({ highWaterMark: 1024 * 1024 });
    const outIt = decompressor[Symbol.asyncIterator]();
    let feedError = null;
    let aborted = false;
    // 'drain' wait must also resolve when the stream is destroyed (consumer
    // exited early) or errors out, otherwise feed deadlocks on backpressure
    // and nobody is consuming output anymore.
    const waitDrain = () => new Promise((resolve, reject) => {
        if (aborted) return resolve();
        const onDrain = () => { cleanup(); resolve(); };
        const onError = (e) => { cleanup(); reject(e); };
        const onClose = () => { cleanup(); resolve(); };
        const cleanup = () => {
            decompressor.removeListener('drain', onDrain);
            decompressor.removeListener('error', onError);
            decompressor.removeListener('close', onClose);
        };
        decompressor.once('drain', onDrain);
        decompressor.once('error', onError);
        decompressor.once('close', onClose);
    });
    const feed = (async () => {
        try {
            while (!aborted) {
                const chunk = await readChunk();
                if (!chunk || !chunk.byteLength) break;
                if (!decompressor.write(chunk)) {
                    await waitDrain();
                    if (aborted) return;
                }
            }
            if (!aborted) decompressor.end();
        } catch (e) {
            feedError = e;
            decompressor.destroy(e);
        }
    })();
    try {
        while (true) {
            const { value, done } = await outIt.next();
            if (done) break;
            if (value && value.byteLength) {
                yield new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
            }
        }
        await feed;
        if (feedError) throw feedError;
    } finally {
        aborted = true;
        if (!decompressor.destroyed) decompressor.destroy();
        await feed.catch(() => {});
    }
}

// Node-only STREAMING zstd compressor for SOLID NCZ (python nsz -S /
// SolidCompressor): one frame over the whole NCA payload, fed in chunks.
// The tootallnate wasm does have a streaming compressor (ZSTD_compressStream2
// via compress_stream, driven by this facade) — but solid mode is not wired
// into the browser path yet (only the CLI uses it), so it stays CLI-only.
//
// Usage:
//   const comp = await createSolidCompressor({ level, ldm });
//   const pump = (async () => { for await (const c of comp) await out(c); })();
//   await comp.write(plainChunk);  // backpressured (bounded queue)
//   comp.finish();                 // no more input
//   await pump;                    // resolves when the frame is fully flushed
// On error: comp.abort() to tear the compressor down, then rethrow.
// Buffers are COPIED on write() — the caller may reuse its own buffers.
//
// The producer (write) and the compressor's readable side are decoupled by a
// bounded queue (QUEUE_MAX chunks, 16 MiB each by convention): the feed loop
// shifts chunks into createZstdCompress with drain backpressure, exactly the
// pump model of decompressNodeStream — so peak memory is O(window + queue),
// never the whole payload.
export async function createSolidCompressor({ level = 18, ldm = false } = {}) {
    if (!isNode) {
        throw new Error('Solid compression is CLI-only (node:zlib streaming zstd): solid mode is not wired into the browser path yet');
    }
    const zlib = await nodeZlib();
    const compressor = zlib.createZstdCompress({ highWaterMark: 1 << 20, params: await zstdCompressParams(level, ldm) });

    const QUEUE_MAX = 8;
    const queue = [];
    let spaceWaiters = [];   // write() callers waiting for queue space
    let itemWaiters = [];    // feed loop waiting for the next chunk / end
    let inputEnded = false;
    let aborted = false;
    let feedError = null;

    const wake = () => {
        spaceWaiters.splice(0).forEach((r) => r());
        itemWaiters.splice(0).forEach((r) => r());
    };

    const write = async (chunk) => {
        if (aborted) throw new Error('zstd solid compressor: aborted');
        if (!chunk || !chunk.byteLength) return;
        while (queue.length >= QUEUE_MAX) {
            await new Promise((resolve) => {
                if (aborted) return resolve();
                spaceWaiters.push(resolve);
            });
            if (aborted) throw new Error('zstd solid compressor: aborted');
        }
        queue.push(new Uint8Array(chunk)); // copy — the caller may reuse its buffer
        wake();
    };

    const finish = () => { inputEnded = true; wake(); };

    const abort = () => {
        if (aborted) return;
        aborted = true;
        queue.length = 0;
        wake();
        if (!compressor.destroyed) compressor.destroy();
    };

    async function* pump() {
        const outIt = compressor[Symbol.asyncIterator]();
        // 'drain' wait must also resolve when the stream is destroyed or
        // errors out, otherwise the feed deadlocks on backpressure.
        const waitDrain = () => new Promise((resolve, reject) => {
            if (aborted) return resolve();
            const onDrain = () => { cleanup(); resolve(); };
            const onError = (e) => { cleanup(); reject(e); };
            const onClose = () => { cleanup(); resolve(); };
            const cleanup = () => {
                compressor.removeListener('drain', onDrain);
                compressor.removeListener('error', onError);
                compressor.removeListener('close', onClose);
            };
            compressor.once('drain', onDrain);
            compressor.once('error', onError);
            compressor.once('close', onClose);
        });
        const feed = (async () => {
            try {
                for (;;) {
                    if (aborted) return;
                    if (queue.length > 0) {
                        const chunk = queue.shift();
                        wake(); // queue space freed
                        if (!compressor.write(chunk)) {
                            await waitDrain();
                            if (aborted) return;
                        }
                        continue;
                    }
                    if (inputEnded) { compressor.end(); return; }
                    await new Promise((resolve) => {
                        if (aborted) return resolve();
                        itemWaiters.push(resolve);
                    });
                }
            } catch (e) {
                feedError = e;
                if (!compressor.destroyed) compressor.destroy(e);
            }
        })();
        try {
            for (;;) {
                const { value, done } = await outIt.next();
                if (done) break;
                if (value && value.byteLength) {
                    yield new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
                }
            }
            await feed;
            if (feedError) throw feedError;
        } finally {
            aborted = true;
            queue.length = 0;
            wake();
            if (!compressor.destroyed) compressor.destroy();
            await feed.catch(() => {});
        }
    }

    return { write, finish, abort, [Symbol.asyncIterator]: pump };
}

// Stream-decompress lazily from an async readChunk() source, yielding
// decompressed chunks. Single platform dispatch: Node uses in-process
// node:zlib (true streaming); browser/forced-WASM uses the tootallnate WASM
// streaming decoder — a TRUE streaming push (chunks fed as they arrive, output
// yielded as produced), so the wasm heap stays bounded by the frame window
// rather than the whole payload.
//   expectedSize: exact decompressed payload size (NCZ: ncaSize - 0x4000).
//                 Gates the output byte count exactly (see Strictness).
//   inputSize: compressed payload length when known — kept for API compat with
//              the old one-shot preallocation; now an INPUT upper-bound check.
// Chunks are always COPIES: the SW output adapter may transfer (detach) chunk
// buffers, and a view into the WASM heap would detach the whole heap.
export async function* decompressStream(readChunk, expectedSize = 0, inputSize = 0) {
    if (isNode && !forceWasm) {
        yield* decompressNodeStream(readChunk);
        return;
    }
    const $ = await loadWasm();
    const dctx = $.dctx_new();
    if (!dctx) throw new Error('zstd wasm: failed to allocate decompressor context');
    const inCap = $.dstream_in_size();
    const outCap = $.dstream_out_size();
    const inP = $.zstd_malloc(inCap);
    const outP = $.zstd_malloc(outCap);
    const bufP = $.zstd_malloc(BUF.SIZE);
    if (!inP || !outP || !bufP) {
        $.dctx_free(dctx);
        throw new Error('zstd wasm: failed to allocate streaming buffers');
    }
    let produced = 0;
    let inputTotal = 0;
    try {
        for (;;) {
            const chunk = await readChunk();
            if (!chunk || !chunk.byteLength) break;
            inputTotal += chunk.byteLength;
            if (inputSize > 0 && inputTotal > inputSize) {
                throw new Error(`zstd stream: input larger than inputSize (${inputSize})`);
            }
            // Drain this chunk through the decoder (in inCap slices), yielding
            // decompressed copies as they are produced.
            for (let off = 0; off < chunk.byteLength; off += inCap) {
                const take = Math.min(chunk.byteLength - off, inCap);
                new Uint8Array($.memory.buffer).set(chunk.subarray(off, off + take), inP);
                for (const out of drainDecode($, dctx, inP, outP, bufP, outCap, take)) {
                    produced += out.length;
                    if (expectedSize > 0 && produced > expectedSize) {
                        throw new Error(`zstd stream: decompressed size exceeds expected (${expectedSize})`);
                    }
                    yield out;
                }
            }
        }
        if (inputSize > 0 && inputTotal !== inputSize) {
            throw new Error(`zstd stream: input ended early (${inputTotal}/${inputSize})`);
        }
        if (expectedSize > 0 && produced !== expectedSize) {
            throw new Error(`zstd stream: size mismatch (got ${produced}, expected ${expectedSize})`);
        }
    } finally {
        $.dctx_free(dctx);
        $.zstd_free(inP);
        $.zstd_free(outP);
        $.zstd_free(bufP);
    }
}

// Drain one inCap-sized slice (in [inP, inP+size)) through `dctx`, yielding
// non-empty Uint8Array COPIES of the decompressed output. A sync generator:
// the wasm calls are synchronous; the surrounding async generator interleaves
// the readChunk() awaits between slices.
function* drainDecode($, dctx, inP, outP, bufP, outCap, size) {
    let srcPos = 0;
    while (srcPos < size) {
        let view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        view.setUint32(BUF.SRC, inP, true);
        view.setUint32(BUF.SRC_SIZE, size, true);
        view.setUint32(BUF.SRC_POS, srcPos, true);
        view.setUint32(BUF.DST, outP, true);
        view.setUint32(BUF.DST_SIZE, outCap, true);
        view.setUint32(BUF.DST_POS, 0, true);
        const ret = $.decompress_stream(dctx, bufP);
        checkError($, ret);
        view = new DataView($.memory.buffer, bufP, BUF.SIZE);
        const dstPos = view.getUint32(BUF.DST_POS, true);
        if (dstPos > 0) yield new Uint8Array($.memory.buffer, outP, dstPos).slice();
        const newSrcPos = view.getUint32(BUF.SRC_POS, true);
        if (newSrcPos === srcPos && dstPos === 0) throw new Error('zstd: decoder made no progress');
        srcPos = newSrcPos;
        if (ret === 0) { // frame fully decoded
            if (srcPos < size) throw new Error('zstd: trailing bytes after frame end');
            return;
        }
    }
}

// Compat facade kept for converter.js init() and scripts/test-ncz.mjs.
// load() pre-warms the WASM in the browser; under Node there is nothing to
// load (node:zlib is native).
export class ZstdDecompressor {
    static async load() {
        if (isNode) return;
        await loadWasm();
    }

    async decompress(data, expectedSize = 0) {
        if (isNode && !forceWasm) return decompressNode(data);
        const $ = await loadWasm();
        return decompressWith($, data, expectedSize);
    }
}
