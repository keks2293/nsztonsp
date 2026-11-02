# Rules for AI Agents

## Start Checklist

- [ ] Read all `.md` files in the project root
- [ ] Check `IMPROVEMENTS.md` for completed tasks and planned improvements
- [ ] Check `CHANGELOG.md` for recent changes and remaining issues
- [ ] Check `TESTS.md` for test suite documentation and test vectors

### MD Files Reference

| File | Description |
|---|---|
| `AGENTS.md` | This file — rules, static files, workarounds |
| `NSZ-FORMAT-ANALYSIS.md` | NCZ/XCZ/NCA format specs, crypto types, Python nsz comparison, known bugs and fixes |
| `PLAN.md` | Action plan, completed steps, success criteria |
| `CHANGELOG.md` | Working components, recent fixes, remaining issues |
| `TESTS.md` | Test suite documentation, test vectors, how to run tests |
| `IMPROVEMENTS.md` | Improvement opportunities, planned fixes, and completed tasks |

## Update CHANGELOG.md After Changes

**Always update CHANGELOG.md after making functional changes.** Add entries under the appropriate section:
- New features or fixes → add to "Recent Changes" with date and description
- When sections grow long, move older entries to a collapsed `<details>` block

CHANGELOG.md is the single source of truth for what works and what doesn't.

### CHANGELOG numbering follows the new commit order

When rewriting/splitting history (e.g., splitting one commit into several, or reordering commits), the numbering and ordering of entries in `CHANGELOG.md` must follow the **order of the rewritten commits**, NOT be copied from the original commit(s). Each commit adds its entry with the next sequential number (its position in the new history). Do not preserve the original numbering if it conflicts with the new commit order.

### History rewrite verification

When rewriting/splitting history, always verify after the rewrite:
- `git diff <old tip> <new tip>` must be empty — the final tree must contain exactly the same content as the original, nothing lost or added.
- Each intermediate commit must be self-sufficient: its imports/dependencies resolve using only files present at that commit (nothing depending on changes from future commits).

### Force-push only on explicit request

Never force-push to a shared branch without asking the user first. When asking, state the divergence (e.g. `ahead X / behind Y`) and explain what the force-push will change.

## Static Files

**DO NOT manually edit files in the `static/` folder.**

The `static/` folder contains downloaded/copied dependencies for browser use:
- `static/zstd.wasm` - Copied from `node_modules/@tootallnate/zstd-wasm/dist/zstd.wasm` (prebuilt WASM, 546,166 B, unmodified; sha256 `9854c20b4bec375b3e98b5edc5b361761337fe34806b397ae4750ca0215f844f`). One WASM for **both** compress and decompress, with a **true streaming** API (`ZSTD_compressStream2` / `ZSTD_decompressStream` via the `compress_stream` / `decompress_stream` exports). Loaded by `crypto/zstd.js` via `fetch('static/zstd.wasm')` in browser / `readFileSync` in Node. The package's source (public `wrapper.c` + `Makefile` in TooTallNate/switch-tools) makes it a verifiable prebuilt, so it satisfies the unmodified-asset policy.
- `static/prod.keys` - User-provided Nintendo Switch keys file

### How to update static files:

1. Update the npm packages:
   ```bash
   npm install @tootallnate/zstd-wasm@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/@tootallnate/zstd-wasm/dist/zstd.wasm static/zstd.wasm
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/zstd.js`), not in the static files
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Source-first research

When reverse-engineering or implementing behavior from an external tool/library:
- **If the source is publicly available (GitHub, etc.) — read the source directly.** Don't guess, probe, or reverse-engineer from output files when the implementation is open source.
- Example: to understand how `hacpack --plaintext` packs NCAs, read `nca.c` in the hacpack repo instead of trying to reconstruct the structure from a packed NCA.

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `DecompressionStream` API doesn't support `'zstd'` format in any browser — constructor throws `"Failed to construct 'DecompressionStream': Unsupported compression format: 'zstd'"`.
  **Solution**: Use `@tootallnate/zstd-wasm` (real zstd 1.5.7 C library compiled to WASM) for **all** zstd compress/decompress in browser via `static/zstd.wasm`. Loaded and wrapped in `crypto/zstd.js`; unlike the old one-shot backends it has a **true streaming** API, so `decompressStream()` is a genuine push (chunks fed as they arrive, output yielded as produced — the WASM heap stays bounded by the frame window, not the payload size).

- **Problem**: The tootallnate `zstd.wasm` is a **raw driver** (named exports, no JS classes shipped for our use): a `DCtx` is **permanently tainted after any `decompress_stream` error** — every later call on the same context returns a `-10` generic error (verified empirically). Reusing a shared one-shot context across ops would silently poison all later decompression after a single corrupt block.
  **Solution**: `crypto/zstd.js` keeps ONE shared WebAssembly instance (its memory + `zstd_malloc` are the expensive part) but allocates a **FRESH `cctx`/`dctx` + I/O buffers per operation** and frees them when done (in `finally`). `dctx_new`/`cctx_new` are cheap small mallocs. (Reusing a context across *successful* frames works, but error-safety wins.)

- **Problem**: The raw driver's input buffer is bounded (`cstream_in_size` = 131072, `dstream_in_size` = 131075). Feeding a larger slice at once **silently corrupts the heap** (no error return).
  **Solution**: All feed loops slice input into `inCap`-sized pieces before each `compress_stream`/`decompress_stream` call (the package's own `push()` does exactly this). Ported verbatim into `runCompress`/`runDecompress`/`drainDecode`.

- **Problem**: The module has **no imports** — wasi-libc grows the linear memory itself via `sbrk`. The 8 MiB initial heap self-grows on big windows (a 128 MiB-window frame → ~130 MiB heap). A heap growth **detaches every existing `ArrayBuffer`-backed view**.
  **Solution**: No grow-heap import object is provided (instantiate with `{}`). Every `Uint8Array`/`DataView` into `memory.buffer` is re-acquired **after each wasm call** (the `runCompress`/`runDecompress`/`drainDecode` loops refresh their `bufView` and heap each iteration).

- **Problem**: Strictness. node:zlib silently tolerates trailing garbage after a complete frame (which is why the NCZ reader-length bug #43 sailed through the Node suite). The tootallnate decoder rejects trailing garbage itself, but **silently decodes some truncated mid-frame payloads** (no error) — so a byte-count gate is still required.
  **Solution**: Two strict paths in `crypto/zstd.js`. (1) **One-shot** (`decompressBlock`): `inspectFrame()` validates the full single-frame shape **before** decoding (bad magic, reserved bit, truncation, trailing bytes, multi-frame, skippable frames, reserved block type, zero-size compressed block → `null`), then decodes and checks the output byte count exactly against `expectedSize` (or the frame's declared FCS). (2) **Streaming** (`decompressStream`): a true push whose gates are an EXACT `expectedSize` byte count (throw on `>` mid-stream, `<` at end — catches silent truncation) plus the decoder's own trailing-garbage rejection (input after the frame ends → "trailing bytes after frame end"). `inspectFrame()` frame layout is the zstd 1.5.7 spec, decoder-verified: FHD bits 7-6 = FCS flag (0→1B only if single-segment, 1→2B storing **size−256**, 2→4B, 3→8B LE, all direct — **no** "all-0x01 = unknown" sentinel exists), bit 5 = single segment (no window descriptor), bit 3 reserved (must be 0), bit 2 = single-bit content-checksum flag (4-byte xxh32 trailer, **no** xxh64), bits 1-0 = Dictionary_ID_flag → 0/1/2/4-byte field; block header: bit 0 last, bits 1-2 type (0 raw / 1 RLE / 2 compressed / 3 reserved-invalid), RLE body is **always 1 byte** (header size field = repeat count), each frame has ≥ 1 block.

- **Problem**: The tootallnate streaming **encoder emits multi-segment frames with NO FCS field** (frame header descriptor `0x00`), unlike node:zlib which emits single-segment frames with a 4-byte FCS. So the frame does not declare its content size.
  **Solution**: `expectedSize` (the authoritative container metadata — NCZ block size, or `ncaSize − 0x4000` for the solid/streaming payload) is always passed by `fs/ncz.js` and is the byte-count gate. The one-shot path falls back to the frame FCS only when `expectedSize` is 0 AND the frame has one.

- **Problem**: When `writePlaintextProgramNca` writes a Uint8Array via the SW adapter (`postMessage` with `transfer`), the buffer is detached. Subsequent reads of `.length` return 0 (spec: detached ArrayBuffer has byteLength 0). This caused the romPos calculation to omit the hash table size (0xB000), placing IVFC levels and RomFS data 0xB000 bytes too early — a backward write that corrupted the output.
  **Solution**: Snapshot all buffer lengths (`htableLen`, `exefsLen`, `levelLengths`) into local variables **before** any writes in `writePlaintextProgramNca` (`fs/nca-pack.js`). Same pattern applied defensively in `packProgramNcaStream`.

`static/zstd.wasm` is a standalone binary asset (no JS wrapper is shipped from the package for our use): `crypto/zstd.js` fetches it (`fetch(new URL('static/zstd.wasm', document.baseURI))` in browser, `readFileSync(new URL('../static/zstd.wasm', import.meta.url))` in Node), instantiates it with **no imports** (wasi-libc self-grows the heap via sbrk), and validates the named-export layout on load (`memory`, `zstd_malloc`/`zstd_free`, `cctx_new`/`cctx_free`/`cctx_set_level`/`compress_stream`/`cstream_in_size`/`cstream_out_size`, `dctx_new`/`dctx_free`/`decompress_stream`/`dstream_in_size`/`dstream_out_size`, `is_error`/`get_error_name`) plus a level-3/level-18 compress→decompress self-test roundtrip. The shared in/out cursor struct is 6×u32 LE (`{src, srcSize, srcPos, dst, dstSize, dstPos}`); `compress_stream` takes an `endOp` (0 = continue, 2 = end; return 0 = drained) and `decompress_stream` returns 0 = frame fully decoded. Error strings are stripped in this build, so failures surface as a fixed placeholder + the numeric code.

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Benchmarking

**Never write benchmark output to real disk repeatedly** — it wears the SSD. Benchmark rules:

- **Real-pipeline benchmarks**: run on the real `.nsz`/`.ncz` file with output **discarded** (stream to `/dev/null`, i.e. `writeChunk` that drops data). Do NOT write full decompressed output to disk just to measure throughput.
- **Micro-benchmarks** (e.g. AES primitives): use in-memory buffers (64 MiB), no disk I/O at all.
- Report **best-of-N** (≥3 runs) and **MB/s**, not wall time of a single run. Warm up before measuring.
- When comparing an optimization, verify **byte-identical output** vs. the reference implementation first (e.g. `verify_clean.mjs` pattern), then measure.
- Persist useful bench/verify scripts in the repo (`bench_*.mjs`, `test_*.mjs`) instead of throwing them away.

## Package Versions

Current versions (update this when upgrading):
- `@tootallnate/zstd-wasm`: 0.1.0 (prebuilt WASM for both compress and decompress, true streaming API; the `^0.1.0` caret tracks 0.1.x; asset copied to `static/zstd.wasm`)

## Streaming SHA256 backends

There is no third-party SHA-256 dependency. The streaming hash (`createStreamingSHA256()` in `crypto/sha256.js`) is:
- **Node**: native `node:crypto` streaming (`NodeSHA256` wrapping `createHash`; mid-state clone via `hash.copy()`).
- **Browser / forced**: the pure-JS `SHA256` class (flat `Int32Array(64)` schedule + word-wise aligned input load, ~260 MB/s; `crypto.subtle` is one-shot async and cannot be cloned). `FORCE_JS=1` runs it in Node via the `setForceJsSha256` hook — scripts A/B both backends.
- Do not reintroduce hash-wasm: at big chunks it was only ~1.36× the port and memcpys every chunk into the WASM heap (zero-copy in the ported aligned path).


