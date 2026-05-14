# NSZ to NSP Converter - Status Report

## ✅ Recent Changes (2026-05-14)

1. **Replaced pure-JS SHA-256 with hash-wasm (WASM)** — `crypto/sha256.js` now uses `hash-wasm` for near-native speed SHA-256 (~424 ms/100MB vs ~752 ms pure-JS). WASM binary embedded as base64 in `static/hash-wasm.mjs` (211 kB, covers all hash algorithms). Module-level `await` pre-initializes WASM at import time, keeping all methods synchronous — no caller changes needed.

   **SHA-256 implementation benchmarks (100MB):**
   | Approach | Time | vs Native |
   |----------|------|-----------|
   | **Node native** (OpenSSL) | **55 ms** | 1.0× |
   | **hash-wasm WASM** | **436 ms** | 0.13× |
   | **32-bit pure JS** (streaming class) | **752 ms** | 0.07× |
   | **8-bit pure JS** (one-shot tight loop) | **650 ms** | 0.08× |
   | **64-bit BigInt** | **~26 s** | 0.002× (broken — `RR` used 64-bit mask instead of 32-bit, wrong hash) |

   WASM is 1.7× faster than the pure-JS streaming class. BigInt is catastrophically slow — never use for SHA-256.

2. **Streaming decompression memory fix (`fs/ncz.js`)** — `_decompressWithStreamingStream` no longer accumulates all compressed chunks in memory before piping to zstd stdin on Node.js. Reads chunk → immediately writes to stdin, eliminating peak memory doubling for large NSZ files. Browser path still accumulates as before (WASM `decodeStreaming` requires array).

3. **Hoisted dynamic SHA256 imports in CLI (`nsz-cli.js`)** — `SHA256` imported statically at module level instead of 3 separate `await import()` calls inside decompression loops.

4. **Async zstd streaming wrapper (`crypto/zstddec-stream.js`)** — New module monkey-patches `ZSTDDecoder._init` to capture the WASM instance, then implements an async generator that reads+decompresses one chunk at a time. Browser streaming path in `fs/ncz.js` no longer accumulates all compressed chunks before decompression — peak compressed memory drops from file-size to `READ_CHUNK_SIZE` (16 MB).

## ✅ Recent Changes (2026-05-13)

1. **SW streaming: fixed `<a download>` not intercepted by SW** — Chrome's download manager bypasses the Service Worker for `<a download>` fetches (no `[SW] fetch` log seen). Replaced with `window.open(streamUrl)` — navigation fetches are always routed through the SW. The SW responds with `Content-Disposition: attachment` which triggers the download.

2. **Blob parts instead of giant Uint8Array** — `buildPFS0Memory` now passes file data as individual Blob parts instead of allocating a contiguous `new Uint8Array(totalSize)` and copying. Eliminates peak 2× memory overhead during PFS0 container building.

3. **NCZ→NCA streaming write support** — Added `writable` path to `decompressNCZtoNCA`. Uses NCZ decompressor's `writeChunk` callback with correct absolute positions for random-access `createWritable` writes. Memory path unchanged (NCZ needs random-access, not sequential).

4. **Mobile: SW streaming download instead of Blob** — On mobile (broken `createWritable`), registers a Service Worker at `sw.js` that creates a `ReadableStream`. Data chunks are sent to the SW via `postMessage` with zero-copy `Transferable` buffers and enqueued into the stream. The browser download manager consumes the stream immediately — peak memory drops from file-size to chunk-size. Falls back to Blob download if SW unavailable.

5. **Download mode switch** — UI radio buttons in `index.html` let the user pick: Auto (FSA→SW→Blob), File System (force FSA), Stream (force SW), Blob (force memory download). Mode state in `downloadMode` variable in `main.js`.

## ✅ Recent Changes (2026-05-10)

1. **Consolidated PFS0 writing into `pfs0.js`** — All PFS0 header building logic moved into `PFS0Writer` class. Removed duplicated inline header builders from `converter.js`, `nsz-cli.js`, `node/decompressor.js`.

2. **PFS0 alignment: two modes matching Python nsz** — Default uses 16-byte alignment `(16 - n%16) % 16` (Python nsz default); `--fix-padding` uses 0x20 alignment via `0x20 - n%0x20` (Python's `align0x20`). Verified: JS default output is byte-identical to Python nsz output.

3. **Fixed absolute offset bug in `node/decompressor.js:writeNSP`** — Was writing absolute file positions instead of offsets relative to header end. Fixed by `PFS0Writer` which correctly tracks relative offsets from 0.

4. **Fixed `FileDescriptorReader.read` for Node v25** — `fs/promises` dropped the `read` export; switched to callback-based `fs.read` wrapped in Promise.

5. **Verified JS output vs Python nsz** — Both default and `--fix-padding` modes produce byte-identical file data to Python nsz. Default mode output is 100% byte-identical. `--fix-padding` provides 0x20-aligned headers.

6. **Moved modules to `fs/` directory** — `pfs0.js`, `ncz.js`, `xci.js`, `ticket.js` moved from root to `fs/` matching Python nsz's `Fs/` layout. Removed unused `node/fs/` directory. All imports updated.

7. **Cleanup: removed dead code** — Removed `crypto/aesxts.js` (never imported), `node/nsz.js` + `node/decompressor.js` + `node/fileExistingChecks.js` (broken CLI chain referencing deleted `node/fs/`), `node/pathTools.js` + `node/parseArguments.js` (both never imported). Removed dead `sha256` import/export from `fs/ticket.js`. Updated `package.json` — `main` → `nsz-cli.js`, scripts use `nsz-cli.js`.

8. **Added `--help`/`-h` flag to CLI** — `nsz-cli.js` now handles `--help` and `-h` flags to display usage. Previously fell through to `stat()` call and crashed with ENOENT.

9. **Renamed `nsz-convert.js` → `nsz-cli.js`** — Clearer name for the Node.js CLI entry point. Updated all references in `package.json`, `README.md`, `PROGRESS.md`, `BROWSER-ZSTD-LIMITATION.md`, `FIXES_PLAN.md`, and usage string.

10. **Removed `node/keys.js`** — Dead code; nothing imported it. Functionality superseded by `keys.js` (KeysParser) and `crypto/` modules.

## ✅ Recent Changes (2026-05-09)

1. **Node.js CLI rewritten for large files** — No more `fs.readFileSync`. Uses `FileDescriptorReader` for random access reads from file descriptor. Output written via `fs.writeSync` with positional writes. Works for files of any size (limited only by disk space). Handles NCZ, XCZ, and NSZ formats.

2. **XCZ browser path: streaming write support** — Stream-decompresses with `writeChunk` in pass 2. Uses File System Access API for large XCZ→XCI conversion. Memory path preserved as fallback.

3. **NSZ→NSP streaming decompression for large files** — Replaced the >1.5 GB guard with `zstddec.decodeStreaming()`. Reads compressed data in sub-2GB chunks, per-section AES-CTR decryption during streaming.

4. **XCZ input refactored** — `XCIReader` now uses `DataReader`, only reads 0x200-byte header + HFS0 header. `HFS0Reader` handles sliced `Uint8Array` correctly.

5. **DataReader abstraction** — `BufferReader`, `ChunkedBufferReader`, `FileSliceReader`, `FileDescriptorReader` for pluggable random-access reading.

6. **Native AES-CTR acceleration** — Node.js uses `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI), browser uses `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API). ~2.3x speedup in browser (3min → 1m17s for 5GB NSZ). Dropped `aes-js` dependency entirely — no more pure-JS AES. Removed `AESCTR_BKTR` (dead code) and stale `node/crypto/` directory. Removed static `aes-js.js` from HTML.

7. **Removed compressed NCZ memory cache** — No longer caches 2GB+ compressed NCZ data in RAM. Pass 2 reads directly from the dropped File via `FileSliceReader`. Zero speed impact, eliminates peak memory bottleneck.

## ✅ Working Components

1. **PFS0 Container Parsing**
   - Reads uint32 at offset 4 (fileCount) and offset 8 (strTableSize)
   - Correctly parses 7 files from NSZ container

2. **PFS0 Writer**
   - Writes proper header structure with file entries and string table

3. **NCZ Discovery**
   - Finds NCZSECTION magic at offset 0x41D0 (16848)
   - Correctly parses 3 sections from section table

4. **zstd Decompression**
   - Uses zstddec WASM library for all decompression (browser and Node.js block)
   - Node.js streaming uses system `zstd` CLI via spawn piping
   - Successfully decompresses files of any size

5. **Section Handling**
   - Correctly calculates NCA size (0x4000 + sections)
   - Handles cryptoType: 1 (none), 3 (CTR), 4 (BKTR)

6. **AES-CTR Encryption**
   - Counter block: nonce[0:8] + BE64(blockIndex) matching PyCryptodome
   - Node.js: `crypto.createCipheriv('aes-128-ctr')` (OpenSSL/AES-NI)
   - Browser: `crypto.subtle.encrypt('AES-CTR')` (Web Crypto API)
   - Hardware-accelerated, ~2.3x faster than pure-JS aes-js

## ✅ Recent Fixes (2026-04-29)

1. **Fixed AESCTR class**
   - Was XORing data directly with key/nonce (wrong)
   - Now properly encrypts counter block with AES-ECB using aes-js
   - Counter format: nonce[0:8] + BE64(blockIndex) - matches Python PyCryptodome

2. **Fixed AESCTR_BKTR class** (since removed — dead code, BKTR uses AESCTR)

3. **Fixed decryptSection in ncz.js**
   - Removed double addition of UNCOMPRESSABLE_HEADER_SIZE
   - Removed `&& this.keys` condition that was blocking decryption
   - Now properly calls AESCTR/AESCTR_BKTR with correct offset

4. **Added aes-js library** (since removed — replaced by native crypto)

## ✅ Recent Fixes (2026-05-08)

5. **Fixed streaming decompression HACK in ncz.js**
   - Removed wrong pre-decryption of compressed data before zstd decompression
   - Correct order is now: zstd decompress → AES-CTR decrypt per section (matching Python nsz)
   - Fixed `ncaSize` scope bug (was undefined in sub-methods, would cause ReferenceError in progress callback)

6. **Improved zstd error handling in crypto/zstd.js**
   - Throws errors instead of silently returning empty Uint8Array
   - Uses console.error for error logging
   - Checks for empty decompressor output

7. **Rewrote nsz-cli.js (Node.js CLI)**
   - Now uses proper project modules (NCZDecompressor, PFS0Reader, KeysParser, sha256)
   - Supports optional keys file as third argument
   - No longer downloads fzstd from CDN at runtime
   - Proper PFS0 writing with correct 64-bit offsets

8. **Added NCA file type detection in ncz.js**
   - Detects NCA files (no NCZSECTN magic) and returns them as-is

9. **Fixed test-ncz.mjs test**
   - Was passing entire NSZ file to NCZDecompressor instead of sliced NCZ data

## ✅ Recent Fixes (2026-05-08, continued)

10. **Fixed fzstd decompression bug — 6-byte NCA SHA256 mismatch**
     - Root cause: fzstd (pure JS) produces 6 incorrect bytes at one location when decompressing large zstd streams (~600MB compressed, 1.6GB decompressed)
     - Fix: Node.js streaming decompression uses `zstd` CLI via `child_process`; browser uses zstddec WASM
     - Verification: Output NCA SHA256 matches working NSP reference byte-for-byte

11. **Node.js zstd CLI improvement: temp files → stdin/stdout piping**
     - Replaced `execSync` with temp files → `spawn('zstd', ['-d', '--no-check'])` with stdin/stdout pipes

12. **ncz.js code cleanup**
     - Removed dead classes and unused utility functions
     - Unified section decryption loop for both Node.js and browser paths

## ✅ Recent Changes (2026-05-08, continued)

15. **Dropped fzstd dependency entirely**
     - Replaced fzstd with zstddec WASM in all decompression paths (crypto/zstd.js, node/crypto/zstd.js, node/fs/ncz.js)
     - Removed `static/fzstd.mjs` and fzstd from `package.json`
     - All zstd decompression now uses a single library: zstddec (WASM-based, handles any window size)
     - Node.js streaming still uses system `zstd` CLI via spawn for performance
     - See `BROWSER-ZSTD-LIMITATION.md` for rationale

16. **Added .nspz/.nsx format support**
     - Browser UI and CLI now accept .nspz, .nsx files (same format as .nsz)
     - Updated accept filters, extension detection, and output naming

17. **Added standalone .ncz file support**
     - Browser: drop .ncz files → decompressed to .nca
      - CLI: `node nsz-cli.js game.ncz` → outputs game.nca
     - NCZDecompressor already detected standalone NCZ (NCZSECTN at offset 0); just needed UI/CLI routing

18. **Added XCZ decompression**
     - New `HFS0Writer` class in `xci.js` for building HFS0 partitions
     - Browser: drop .xcz files → decompressed to .xci
      - CLI: `node nsz-cli.js game.xcz` → outputs game.xci
     - Parses XCI secure partition, decompresses NCZ files inside, rebuilds HFS0

19. **Removed dead code**
     - Removed `getZstdWindowSize()` from `ncz.js` (no longer needed with zstddec)
     - Removed orphaned `decompressor.js` (not imported anywhere)

20. **Cleaned up test files**
     - Replaced hardcoded paths in `test_ticket_keys.mjs` and `test_decompress.mjs` with CLI args

## ⚠️ Known Limitations

1. **Memory download path (no File System Access API)**: Falls back to `Blob` download — builds full output in memory, fails for games >2 GB. Use browser with File System Access API (Chrome/Edge) for large files.

## ✅ Verified

- **Full end-to-end NSZ→NSP conversion** tested with `Little Nightmares II` (1.56 GB update NSZ)
- **All NCA data byte-identical** to Python nsz reference output
- **AES-CTR implementation** verified against Node.js native `crypto.createCipheriv('aes-128-ctr')` — both are correct
- **zstd CLI piping + Node.js native AES-CTR** confirmed to produce byte-identical output to the reference
- **PFS0 header padding**: Default uses 16-byte alignment (matching Python nsz). `--fix-padding` uses Python's `align0x20` (32-byte alignment, minimum 0x20 padding). All file data is identical between modes. Default mode output is byte-identical to Python nsz.
- XCZ output is a flat HFS0 partition without full XCI header/metadata — enough for game loading but not a byte-for-byte copy of the original XCI structure.

