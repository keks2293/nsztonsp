# NSZ to NSP Converter - Improvement Plan

Action plan for speed, memory, code-reduction and DX improvements. Status 2026-09-11.
Each item lists `file:line`, expected effect and effort. Items already implemented or
explicitly rejected live in `IMPROVEMENTS.md` (marked ✅/❌) — check there before starting.

## Done (removed from plan)
P2 (`AesXts._encData` hoist, ~33× XTS-encrypt), P3 (`_nativeDigest` zero-copy, ~+21%),
P4 (shared `yieldToEventLoop`), P5 (pooled block buffers + borrow fast path),
P6 (bktr.js AES-ECB loop dedupe), P7 (ncz.js double dispatch),
P8 (`CNMT_ENTRY_TYPE` names), P10/C2 (extractExefs/extractRomfs as collect wrappers).
B1 (update tail once — writeFinalPfs0Header + finalizeNspTail, −4× tail, merged two-pass).
C1 (mergeRomFS/scatterRomFS per-run walkers — readBaseRun + readPatchRun).
A1 (scatterRomFS makeUpdateSource) + A2 (base source unconditional registerRange).
B2 (programPfs0Offset helper), D1 (dead kind!==‘ncz’ branch dropped). Committed 2026-09-11.

## Remaining

### P1. NCZBLOCK parallel decompression via workers (deferred by user decision)
- **Where**: `fs/ncz.js` — `decompress()` / `_decompressBlocks()` / `AsyncBlockDecompressorReader` decode blocks strictly sequentially; the repo has zero `worker_threads` / `Web Worker` usage.
- **Why**: NCZBLOCK blocks are independent (keyed by `blockIndex` only) → near-linear scaling on multi-core. Requires **no** `SharedArrayBuffer`/COOP-COEP — plain `postMessage` + ArrayBuffer transfer suffices (this is what distinguishes it from the rejected streaming-worker idea, `IMPROVEMENTS.md:198`).
- **Browser**: worker pool, each worker gets a `File`/`Blob` slice, returns `Uint8Array` (transferred). **Node CLI**: `worker_threads` + `zlib.zstdDecompressSync`/`createZstdDecompress`.
- **Effect**: ~×2–×4 on convert/merge for block-mode files (decompression is the dominant cost). Not applicable to streaming mode (sections are sequential).
- **Effort**: high (pool, ordered result handling for ≤256 blocks, memory control).
- **Verify**: byte-identical output vs current (`verify_clean.mjs` pattern) + real-file benchmark with output discarded (AGENTS.md benchmark rules).

### P9. Single 16 MB chunk constant (postponed — unverified edits in `stash@{0}`)
- **Where**: `fs/ncz.js:5,23`, `fs/bktr-merge.js:139`, `fs/nca-pack.js:953` (+ inline `0x1000000` at `nca-pack.js:892,1067,1120,1129`).
- **Fix**: one shared `CHUNK_16MB` constant. Low priority, pure maintenance.
- **State**: edits done (shared `CHUNK_16MB` in `fs/bytes.js`, wrapped in `SECTION_CHUNK_SIZE`/`READ_CHUNK_SIZE`/`SCRATCH_CHUNK`/`CHUNK` + the 6 inline sites) but **not verified/committed** — restoring touches `fs/bytes.js`, `fs/ncz.js`, `fs/bktr-merge.js`, `fs/nca-pack.js`; then `npm run build` + `test_update_sw_sim`.

### P10. Non-stream `extractExefs`/`extractRomfs` as collect wrappers
- **Where**: `fs/nca-pack.js` (plus `update.js` RomFS paths).
- **Fix**: implement the buffered variants as collect over the existing `*Stream` functions instead of duplicating parse+CTR logic. −20–30 lines. Verify callers first (only memory-tolerant paths).

### P11. Gate the debug `console.log` in `fs/ncz.js` (deferred by user decision)
- **Where**: `fs/ncz.js:100,107,109,124,162,169` — printed on **every** parse, in browser console and CLI.
- **Fix**: remove or gate behind a `DEBUG_NCZ` flag. Removes noise + per-parse string formatting cost.

## Refactor audit — double dispatch / duplicated variants (2026-09-11, follow-up of commit `b83a7e6`)
Full sweep of `fs/*.js` + `crypto/*.js` for the same anti-pattern the `decompress()` fix collapsed.

### A1. `scatterRomFS` double-dispatches on `updateCtx.streamable` (true same-shape duplicate)
- **Where**: `fs/bktr-merge.js:284` (U1, BKTR tables) and `:356` (U2, patch data) — each: `if (streamable)` → fresh `NczStreamSource(reader, parsed, log)` + `registerRange(...)` loop, `else` → reuse `updateCtx.source`. Live scatter path.
- **Fix**: one local `const makeUpdateSource = (ranges) => streamable ? (register ranges into a fresh NczStreamSource) : updateCtx.source;`, called for U1's table ranges and U2's patch ranges. `streamable` branch appears once.

### A2. Redundant `instanceof NczStreamSource` branch in `scatterRomFS`
- **Where**: `fs/bktr-merge.js:322-331` — `if (baseInput.source instanceof NczStreamSource) { baseSource = source; registerRange loop } else { baseSource = source; }` — both arms set the same value; `RangeSource.registerRange()` is a deliberate no-op (`fs/range-source.js:78`, real override only in `NczStreamSource`), and `mergeRomFS` runs the same loop **unconditionally** (`fs/bktr-merge.js:157-163`).
- **Fix**: delete the if/else — `const baseSource = baseInput.source;` + the unconditional `registerRange` loop.

### B1. Update tail duplicated 4× (largest real duplication, post-#49 remainder)
- **Where**: `fs/update.js:363-378` (appendOnly two-pass), `:398-406` (seekable two-pass), `:746-753` (streaming), `:857-878` (buffered) — each repeats `rebuildCnmtNca → buildFinalPfs0 → adapter.write(0, pfs0Header.buffer) → finalizeOutputNsP`; only the contentId source and phase bookkeeping differ.
- **Fix**: one `writePfs0HeaderAndTail({adapter, contentId, programSize, otherNcas, base, update, keys, log, progress, output, phaseLabel, phaseBaseDone, phaseTotal})`; each branch keeps only its distinct NCA-write step (`packProgramNcaStream` / `writeProgramNcaTwoPass` / `writePlaintextProgramNca`).

### B2. Duplicate `pfs0HeaderSize` layout computation
- **Where**: `fs/update.js:385-388` and `:702-705` — byte-identical `programNcaPfs0Offset` computation (two of the four paths).
- **Fix**: 3-line helper `programPfs0Offset(otherNcas)`.

### C1. `mergeRomFS` vs `scatterRomFS` duplicate both per-run loops
- **Where**: `fs/bktr-merge.js` — base-copy run (`:230-238` vs `:334-347`) and patch-subsection walk (`:202-223` vs `:368-382`) are identical save the sink (`emitChunk` vs `scatterWrite`) and iteration order (virtual vs physical).
- **Fix**: sink-parameterized helpers `readBaseRun(src, physBase, virtStart, len, sink)` + `readPatchRun(src, updateRomfsSecOffset, subBlock, titlekey, secureValue, physBase, virtStart, len, sink)`. **Bigger than the others — its own commit** (both paths are live).

### C2. Buffered `extractExefs`/`extractRomfs` duplicate the raw-vs-CTR dispatch — **= P10** (see P10 above).

### D1. Dead `kind !== 'ncz'` arm in `extractNcaSections` (dead code, small)
- **Where**: `fs/update.js:196-201` — the direct-read branch is unreachable: the only call site (`:613`) sits inside `if (updateKind === 'ncz')` (`:596`); non-NCZ uses `FileRangeSource`.
- **Fix**: drop the `kind` param and the dead branch (leftover of the #50 `isNcz`→`kind` migration).

### Checked — clean or noise (leave)
- `crypto/*` (`aes128.js`, `zstd.js`, `sha256.js`), `fs/adapter.js`, `fs/range-source.js`, `fs/convert-common.js` (`writeFromReader` — the exemplar single `switch(kind)`), `nca-pack.js` scatter/contentId feed paths, `fs/ncz.js` block/stream internals.
- `fs/update.js:690/772/806` 3-way split — early-return-mutually-exclusive (not a double dispatch); optional readability: derive one `mode` enum (`'streaming' | 'two-pass' | 'buffered'`) and `switch`.

## P12 (rejected after measurement) — fold the contentId hash into Pass 1's RomFS merge

- **Where**: `fs/nca-pack.js` `computeProgramNcaContentId` (`contentIdInPass1`, SW append-only) re-streams RomFS a second time for the contentId ("Pass 1 RomFS (SHA256 re-stream)").
- **Why it fails**: `contentId = sha256(encHeader | htable | exefs | exePad | **levels** | **romfs** | romPad)` — the true NCA file order (`nca-pack.js:1225`, CNMT hash must equal the file sha). `levels` are stored before the RomFS data but only computable after a **full** RomFS pass (`StreamingIvfcHasher.finalize()`), so a single forward pass can never absorb levels-before-romfs. The two options are exactly the two existing paths: a second pass (the ~200 KB two-pass design, documented at `nca-pack.js:1220-1229` / `update.js:762-764`) or a RomFS buffer (the buffered path, which already hashes from RAM). **Not a regression** — the re-stream is the structural price of low-memory append-only, not a leftover.

## Real-pipeline perf measurement (2026-09-11, real Stardew base+update NSZ pair, Node native, output hashed/discarded, best-of-3, all byte-identical `deec91cf…`)

| Path | Wall | RomFS decompress passes | Note |
|---|---|---|---|
| SW two-pass append-only (no read-back) | **31.0s** | 3× (8.4 + 8.2 + 8.2) | Pass-1 contentId = 16.8s |
| buffered merge-to-RAM (Buffer pill) | **18.5s** | 1× | hash precompute from the RAM buffer |
| **seekable streaming** (merge→output + contentId re-read) | **15.6s** | **1×** | fastest available, ×2.0 vs SW |

- **Takeaway**: on seekable outputs (fd / FSA with read) prefer the streaming path over the Buffer pill — measured **−16% vs buffered, −50% vs SW two-pass**. Browser proportions hold (decompression dominates; WASM zstd ~2–3× slower than node:zlib explains the user's ~60s browser run vs 18.5s Node buffered). The P2/P3/P4 micro-wins (AesXts-encrypt 33×, digest32 +21%) sit on paths that are ≤0.1s here — they move micro-benchmarks, not this pipeline.
- Tooling: `scripts/bench_real_update.mjs` gained `--streaming` / `--buffered` flags (memory output + read-back, no disk writes).

## Proposed order of work (when resumed)
1. P9 — resume from `stash@{0}`, verify, commit (smallest unit).
2. A1, A2, B2, D1 — small, provably behavior-preserving refactors; build + `scripts/test_update_sw_sim.mjs` after each.
3. B1 — the big tail dedupe (4 paths); build + `test_update_sw_sim` + `test_twopass_*` sims.
4. C1 — `mergeRomFS`/`scatterRomFS` run-loop helpers; build + `test_update_sw_sim` (scatter modes) + `test_merge_ncz`.
5. P10/C2 — collect-wrappers for test-only buffered extract twins.
6. P1 — the real speed win; assess again (user deferred it).
7. P11 — deferred by user decision.

## Note (already done, do NOT re-plan)
Selective NCZ decompression + streaming NCA pack + BKTR merge streaming is fully implemented and
annotated in the history (see `IMPROVEMENTS.md` "Analysis / Plan", landed at `1f2412a` and `110e7d2`).

## Do not touch (already optimal / decided)
- Fire-all `BatchDigestor` for independent blocks (CHANGELOG #81).
- 16 MB read chunk (decision recorded in IMPROVEMENTS.md).
- WebCrypto one-shot contentId hash — rejected by user (RAM peak +700 MB).
- Streaming Web Worker + SharedArrayBuffer (~33%) — rejected (COOP/COEP), IMPROVEMENTS.md:198.