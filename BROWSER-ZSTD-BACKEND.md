# Browser Zstd Compress + Decompress

## The Problem

NSZ files can use zstd compression with any window size. The browser has no native zstd API (`DecompressionStream('zstd')` throws `Unsupported compression format` in all browsers), so we use a WASM-based library.

## Solution: @tootallnate/zstd-wasm

[@tootallnate/zstd-wasm](https://github.com/TooTallNate/switch-tools) wraps the real zstd C library (zstd 1.5.7 single-file build) compiled to WebAssembly via wasi-sdk. **One WASM binary (546,166 B, `static/zstd.wasm`, an unmodified copy of `node_modules/@tootallnate/zstd-wasm/dist/zstd.wasm`) handles both compression and decompression with a TRUE streaming API** (`ZSTD_compressStream2` / `ZSTD_decompressStream` via the `compress_stream` / `decompress_stream` exports) — it replaced the old one-shot `@bokuweb/zstd-wasm` build entirely.

```javascript
import { compressBlock, decompressBlock, decompressStream } from './crypto/zstd.js';
const frame = await compressBlock(data, 18);                 // one zstd frame
const back = await decompressBlock(frame, expectedSize);      // expectedSize 0 = use frame FCS
// true streaming (browser code path; forced-WASM in Node for A/B tests):
for await (const chunk of decompressStream(readChunk, expectedSize, inputSize)) { ... }
```

The WASM is loaded once, lazily, by `crypto/zstd.js`:

- **Node**: `readFileSync(new URL('../static/zstd.wasm', import.meta.url))`
- **Browser**: `fetch(new URL('static/zstd.wasm', document.baseURI))` (the bundle serves the asset from `out/static/`, copied by `build.js`)

Load validates the named-export layout and runs a level-3/level-18 compress→decompress self-test roundtrip.

- **Native zstd 1.5.7** — handles any window size, compression levels 1–22
- **Standalone `.wasm` asset** (fetched at load; no base64 embedding). On disk 546,166 B; over the wire with brotli `-q11` it is **~107 KB** (gzip -9 ≈ 143 KB). A one-time cached asset.
- **True streaming** — `decompressStream()` feeds chunks as they arrive and yields output as produced, so the WASM heap stays bounded by the frame *window* (a 128 MiB-window frame → ~130 MiB heap), never the whole payload.
- **Fast** — decompress ~311–330 MB/s (forced-WASM, real 406 MB solid frame, best-of-3); compress L18 ~5 MB/s in on the same payload.

## Why tootallnate over the alternatives (4-backend A/B)

The browser backend was chosen by a 4-way A/B on the real `base.nsz` solid frame (406,227,831 B compressed, 920 MB payload, level 18; decompress best-of-3, MB/s in; memory = RSS delta):

| Backend | Decompress | Compress L18 | Memory (decompress) | Verdict |
|---|---|---|---|---|
| A `node:zlib` | 494 MB/s | 406,227,831 B / 144.6 s | — (Node only) | Reference; Node path |
| B `@bokuweb/zstd-wasm` (one-shot) | 309 MB/s | 8,747,110 B (block 64 MiB) | RSS **+2.50 GiB** | One-shot only: no streaming API, buffers the whole payload |
| **C `@tootallnate/zstd-wasm` (chosen)** | **329 MB/s** | 406,227,822 B / 181.2 s (solid) | heap **129.8 MiB** | **True streaming compress + decompress; lowest memory** |
| D `zstd-stream` (TransformStream) | 311 MB/s | 406,227,826 B / 196.2 s (solid) | ~C | Level cap 19 (CLI wants 1–22); checksums hardcoded on; unverifiable prebuilt (no C source shipped) |

Notes from the A/B:

- **C ≡ D encoder, byte-for-byte** for a given level (both libzstd 1.5.7; D's output = C's + FHD bit 2 + a 4-byte xxh32 trailer). D's −6…−8% compress throughput is its JS wrapper overhead (ReadableStream + 1 MiB HWM + legacy `ZSTD_compressStream`) vs C's tight push + `ZSTD_compressStream2`.
- C's solid-frame output is a **byte-identical prefix** of A's (node:zlib); A's extra 9 B are a trailing empty frame node:zlib appends.
- The 256 MiB random-data micro-bench overstates throughput ~2.5× (data-dependent); the sustained real-payload numbers above are the honest ones.
- Long-distance matching (LDM) stays CLI-only for both C and D (no parameter API exposed by either wasm).

## Driver design (one shared instance, fresh context per op)

`crypto/zstd.js` is a **raw driver** over the WASM (the package's JS classes are not used — they instantiate a new WebAssembly instance per call, which would be ~920 instantiations in block mode). Design:

- **ONE shared WebAssembly instance** — its linear memory is the expensive part (starts 8 MiB, self-grows via wasi-libc `sbrk`; the module has **no imports**, so no grow-heap callback). Loaded once.
- **FRESH `cctx`/`dctx` + I/O buffers per operation**, freed when done. This is deliberate: a `DCtx` is **permanently tainted after any `decompress_stream` error** (every later call returns `-10`), so a shared one-shot context would poison all later decompression after one corrupt block. Reuse across *successful* frames works, but error-safety wins.
- **Input is sliced into `inCap` pieces** (`cstream_in_size` = 131072 / `dstream_in_size` = 131075) before each call — feeding more at once silently corrupts the heap.
- **Views into `memory.buffer` are re-acquired after every wasm call** (a heap growth detaches them).

## Strictness model

node:zlib silently tolerates trailing garbage after a complete frame (which is why the NCZ reader-length bug #43 sailed through the Node suite). The WASM paths stay strict:

- **One-shot (`decompressBlock`)**: `inspectFrame()` validates the full single-frame shape **before** decoding (rejects bad magic, reserved bit, truncation, trailing bytes, multi-frame payloads, skippable frames, reserved block type, zero-size compressed blocks), then decodes and checks the output byte count **exactly** against `expectedSize` (or the frame's declared FCS).
- **Streaming (`decompressStream`)**: a true push gated by an EXACT `expectedSize` byte count (throw on `>` mid-stream, `<` at end — catches the decoder's silent mid-frame truncation) plus the decoder's own trailing-garbage rejection (input after the frame ends → "trailing bytes after frame end").

The tootallnate **encoder emits multi-segment frames with no FCS field**, so the frame does not declare its content size — `expectedSize` (always passed by `fs/ncz.js`: NCZ block size, or `ncaSize − 0x4000`) is the authoritative byte-count gate.

## The Node.js Path

Node ≥ 22.11 has native zstd via `node:zlib` — the CLI and Node test paths use it (faster than WASM):

- Streaming decompression: `zlib.createZstdDecompress()` (in-process, streaming, any window size)
- Block decompression: `zlib.zstdDecompressSync`
- Block compression: `zlib.zstdCompressSync` with `ZSTD_c_compressionLevel`

`crypto/zstd.js` picks the backend automatically (Node → `node:zlib`, browser → WASM). `setZstdStreamForcedWasm(true)` forces the browser code path under Node for A/B verification (and it covers the one-shot ops too, so the full WASM backend is testable in Node).

## Current Implementation

- `crypto/zstd.js` — single facade: `compressBlock(data, level=18)`, `decompressBlock(data, expectedSize=0)`, `decompressStream(readChunk, expectedSize=0, inputSize=0)` (async generator), `inspectFrame(data)` (strict single-frame shape check, exported), `setZstdStreamForcedWasm(v)` A/B hook, `ZstdDecompressor` compat class (its `load()` is a no-op on Node).
- `fs/ncz.js` — passes known sizes (`ncaSize − 0x4000`, per-block decompressed size) into the facade; branches on Node (`node:zlib` streaming) vs browser (WASM streaming).
- `static/zstd.wasm` — shipped asset (unmodified package copy).

## History

- **fzstd** (pure-JS zstd) was the original block decoder. It had two bugs with large zstd windows (>32 MB): corrupted output and "invalid zstd data" throws.
- **zstddec** (decoder-only WASM) replaced it, handling streaming + block decompression (but had a `decode()` bug with explicit `uncompressedSize` on >1 GB streams, and no compression).
- **@bokuweb/zstd-wasm** (one-shot WASM) added browser compression but had no streaming API — the browser "streaming" path buffered the whole payload in WASM memory and did a single `ZSTD_decompress` (RSS +2.5 GiB on the 920 MB payload).
- **@tootallnate/zstd-wasm** (current) is the single browser zstd library for **all** compress and decompression, with true streaming and a bounded heap.

## Files

- `static/zstd.wasm` — prebuilt WASM, unmodified copy of `node_modules/@tootallnate/zstd-wasm/dist/zstd.wasm`
- `crypto/zstd.js` — facade + raw driver + frame inspector + forced-WASM paths
- `scripts/verify_zstd.mjs` — frame-encoding cross-validation suite vs the reference decoder
- `scripts/verify_wasm_real_nsz.mjs` — forced-WASM vs node:zlib A/B on a real .nsz
