# nsz-js Test Suite

## Overview

This document describes the test files available in the nsz-js project for verifying correctness of the implementation against Python nsz reference.

---

## 1. AES-CTR Crypto Tests

### test_aes_ctr.py (Python - Reference)
**Location:** `/test_aes_ctr.py`
**Purpose:** Generate reference AES-CTR keystream using Python PyCryptodome
**What it tests:**
- AES-CTR keystream generation matching Python nsz
- Counter format: `Counter.new(64, prefix=nonce[0:8], initial_value=(offset >> 4))`
- Verifies big-endian encoding of block index in counter bytes 8-15

**How to run:**
```bash
python3 test_aes_ctr.py
```

**Expected output:** Keystream hex string starting with `e95fed2b7d0afca982d145a0ddea1c84...`

---

### test_vector.mjs (Node.js)
**Location:** `scripts/test_vector.mjs`
**Purpose:** AES-CTR test vector verification matching Python nsz
**What it tests:**
- AES-CTR keystream matches Python output
- Counter block construction (nonce[0:8] + BE64 blockIndex)
- Native AES-CTR encrypt/decrypt (Node.js `crypto.createCipheriv` or browser Web Crypto API)

**How to run:**
```bash
node scripts/test_vector.mjs
```

**Expected output:**
```
Result: ✅ PASS
```

---

### test_aesctr.mjs (Node.js)
**Location:** `scripts/test_aesctr.mjs`
**Purpose:** AES-CTR with explicit seek and encrypt
**What it tests:**
- AES-CTR seek to specific offset
- Encrypt known plaintext and compare with expected output

**How to run:**
```bash
node scripts/test_aesctr.mjs
```

**Expected output:** Shows encrypted zstd magic matching `874786d3`

---

### test_aes_manual.cjs (Node.js - Manual)
**Location:** `/test_aes_manual.cjs`
**Purpose:** Standalone AES-CTR test with no dependencies
**What it tests:**
- Manual AES-CTR implementation using Node.js crypto
- Counter construction without external libraries

**How to run:**
```bash
node test_aes_manual.cjs
```

---

### test_aes128.mjs (Node.js)
**Location:** `scripts/test_aes128.mjs`
**Purpose:** Regression vectors for the software AES-128 primitives (`crypto/aes128.js`)
**What it tests:**
- `AesEcb.encrypt` single-block, `encryptBlock` with caller-provided `out` (in-place) and without (fresh alloc)
- `AesCtrJS` keystream XOR (js-fallback browser path)
- `AesXts` sector decrypt against a fixed sector-0 vector
- XTS streaming invariant: whole decrypt == concatenation of sector-aligned chunk decrypts (`startSector` advancing)
- XTS determinism

Fixed vectors are byte-identical to the pre-optimization reference.

**How to run:**
```bash
node scripts/test_aes128.mjs
```

**Expected output:** `8 passed, 0 failed`

---

### bench_aes128.mjs (Node.js — Micro-benchmark)
**Location:** `scripts/bench_aes128.mjs`
**Purpose:** In-memory throughput of the software AES primitives (NO disk I/O)
**Measures (best-of-5, MB/s, `node scripts/bench_aes128.mjs [mib]`):**
- AES-CTR software js-fallback keystream (browser path)
- AES-XTS software
- AES-128-CTR via `node:crypto` (reference for the Node/webcrypto path)

**How to run:**
```bash
node scripts/bench_aes128.mjs 64
```

---

### bench_real_nsz.mjs (Node.js — Real-pipeline benchmark)
**Location:** `scripts/bench_real_nsz.mjs`
**Purpose:** Decompress a real `.nsz` (all `.ncz` members) with the output **discarded** (dev-null) so the SSD is not worn. Reports total MiB, wall time, MB/s (best of N).

**How to run:**
```bash
node scripts/bench_real_nsz.mjs path/to/file.nsz [runs]
```

Reference `Little Nightmares II` (5.02 GiB NCZ): ~684 MB/s best-of-3 on the Node path (WebCrypto/native zstd dominate).

---

### bench_own_bktr_phases.mjs (Node.js — Real-pipeline phase baseline)
**Location:** `scripts/bench_own_bktr_phases.mjs`
**Purpose:** Per-phase timing of the own-BKTR two-pass path (`fs/bktr-pack.js`) on the real Stardew NSZ, seekable-no-read (FSA-shaped) output. Uses the `setBktrPhaseHook` instrumentation hook added to `bktr-pack.js` (no-op unless set). **Mode-aware:** detects whether the seekable branch emits the Tier-1 single-pass layout (no Pass-1 sha phases — current, since #138) or the old two-walk layout, and prints a comparison against the committed #137 baseline. Unlike `test_twopass_fsa_sim.mjs` it does no byte-compare and uses a preallocated-doubling writable (the test's `FsaSim` regrows per write — O(n²) — inflating Pass 2: ~88–94 s vs ~10.2 s here). Output is an in-memory throwaway (never written to disk).
**Measures (best-of-N, `node scripts/bench_own_bktr_phases.mjs [runs]`):**
- Single-pass layout (current): Pass 1 phases `resolve`, `tables` (update decompress to the reloc/sub tail), `build` (exefs PFS0 hash + header/table AES) — no contentId hash walk; Pass 2 phases `hdr-write`, `walk-write-hash` (merged decrypt+AES+write+inline sha, write wall via `cpuMs`), `tl-write`; e2e.
- Two-pass layout (pre-#138): Pass 1 adds `sha-head`, `walk-hash`, `sha-tail`; Pass 2 reports `walk-write`.

**How to run:**
```bash
node scripts/bench_own_bktr_phases.mjs 3
```

Reference (Stardew, best-of-3, Tier-1 single-pass): e2e 13.6 s = Pass 1 3.4 s (resolve/tables/build only) + Pass 2 10.2 s (merged walk 10.1 s; write+sha wall 0.5 s ⇒ decompress+AES ≈ 9.6 s). Two-pass baseline (pre-#138): e2e 24.8 s = Pass 1 14.2 s + Pass 2 10.6 s → Tier 1 is −45% e2e.

---

### bench_aes.mjs (Node.js — Benchmark)
**Location:** `scripts/bench_aes.mjs`
**Purpose:** AES-CTR throughput benchmark
**What it measures:**
- Encrypt throughput (MB/s) for large contiguous data
- Decrypt throughput (MB/s) for large contiguous data
- Seek+decrypt throughput (simulates per-section NCZ decrypt pattern)

**How to run:**
```bash
node scripts/bench_aes.mjs
```

**Output:**
```
AES-CTR encrypt 500MB: 456ms (1096 MB/s)
AES-CTR decrypt 500MB: 462ms (1082 MB/s)
AES-CTR seek+decrypt 500MB (500 seeks): 481ms (1039 MB/s)
```

---

## 2. Browser-based AES-CTR Tests

### test_browser.html
**Location:** `/test_browser.html`
**Purpose:** AES-CTR keystream verification in browser
**What it tests:**
- AES-CTR with PyCryptodome-compatible counter
- Uses `crypto.subtle.encrypt` (Web Crypto API, hardware-accelerated)

**How to run:** Open in browser

---

## 3. Conversion & Analysis Tests

### test_convert.mjs (Node.js)
**Location:** `scripts/test_convert.mjs`
**Purpose:** Full NSZ to NSP conversion pipeline
**What it tests:**
- PFS0 parsing
- NCZ decompression with AES-CTR
- SHA256 hashing of output

**How to run:**
```bash
node scripts/test_convert.mjs path/to/file.nsz
```

**Prerequisites:**
- Requires NSZ file input

---

### test_decompress.mjs (Node.js)
**Location:** `scripts/test_decompress.mjs`
**Purpose:** Compare decompressed output against reference NSP
**What it tests:**
- NCZ decompression
- Byte-by-byte comparison with working NSP
- SHA256 hash comparison

**How to run:**
```bash
node scripts/test_decompress.mjs input.nsz [working.nsp]
```

When `working.nsp` is provided, finds and reports the first mismatching byte.

---

### test_ticket_keys.mjs (Node.js)
**Location:** `scripts/test_ticket_keys.mjs`
**Purpose:** Analyze ticket keys and AES-CTR decryption in NSZ files
**What it tests:**
- NCZSECTN parsing
- Section key/counter extraction
- Ticket (.tik) parsing and comparison
- AES-CTR decryption with various keys (section key, title key, etc.)
- zstd magic detection in decrypted data

**How to run:**
```bash
node scripts/test_ticket_keys.mjs input.nsz [working.nsp]
```

Useful for debugging key derivation and verifying section decryption manually.

---

### test-ncz.mjs (Node.js)
**Location:** `scripts/test-ncz.mjs`
**Purpose:** NCZ decompressor component tests
**What it tests:**
- AES-CTR encrypt produces correct bytes
- NCZ section parsing from NSZ container
- Full NCZ decompression vs working NCA (when files available)
- Zstd decompressor error handling

**How to run:**
```bash
node scripts/test-ncz.mjs
```

Tests with hardcoded paths skip gracefully when files are not present.

### Merge / Split NSP (Node.js + Browser)

**Purpose:** verify the new NSP merge and split operations (`fs/merge.js`, `fs/split.js`).

**What merge does:** unions the members of 2+ NSPs/NSZs/XCIs/XCZs into one NSP, deduplicating by output filename (first occurrence wins). Compressed `.ncz` members are decompressed to `.nca` on the fly (both streaming-zstd and NCZBLOCK modes; section AES keys come from the NCZ headers, so no keys file needed). XCI/XCZ inputs contribute their secure-partition files (read header-only via `XCIReader.getSecureFiles()`); mixed `base.xci + update.nsp` → `.nsp` works. Output: `<stem of first input>_merged.nsp`.

**What split does:** for each `.cnmt.nca` in the input, decrypts the NCA header (XTS) and the first section (AES-CTR), parses the inner PFS0 → CNMT, groups the referenced NCAs into a per-title NSP, and attaches the matching `.tik`/`.cert` via rights-id lookup. Needs `header_key` + title-key derivation (any `static/prod.keys`). Output: `{titleId}_{base|update|dlc}_v{version}.nsp` per title.

**How to run (CLI):**
```bash
node nsz-cli.js --merge base.nsp update.nsp dlc.nsp -o ./out          # merge NSPs (dedup by name)
node nsz-cli.js --merge base.xci update.nsp -o ./out                  # merge XCI base + NSP update -> NSP
node nsz-cli.js --merge base.nsz update.nsp -o ./out                  # merge NSZ base (decompresses .ncz members) + NSP update
node nsz-cli.js --merge base.xcz dlc.nsp -o ./out                     # merge XCZ base (decompresses .ncz members) + NSP DLC
node nsz-cli.js --split merged.nsp ./static/prod.keys -o ./out        # split per title
node nsz-cli.js --merge a.nsp b.nsp -o ./out --rm-source              # delete sources after
```

**Synthetic component tests** (build valid-PFS0 NSPs and synthetic XCIs; split uses real `static/prod.keys` with generated NCA headers):
- merge: 5 members after dedup, member data copied byte-identically
- merge with XCI input: XCI secure-partition files unioned with NSP files, first-wins dedup across containers, data verified byte-identically (both `[xci, nsp]` and `[nsp, xci]` orders)
- merge with NSZ input (`test_merge_ncz.mjs`, fixtures synthesized in-process via `zlib.zstdCompressSync`, no zstd CLI needed): streaming-zstd and NCZBLOCK `.ncz` members decompressed to `.nca`, bytes verified against expected NCA; plain members copied; `.ncz`/`.nca` same-stem dedup across inputs keeps the first input. On Node the `.ncz` streaming decompression uses in-process `zlib.createZstdDecompress` (no CLI subprocess); verified separately with a 200MB synthetic NCZ (byte-identical, ~144ms)
- split: 1 title group, output has 4 members (meta NCA, program NCA, `.tik`, `.cert`), meta NCA byte-identical to source
- split round-trip: `--split` then `--merge` reproduces the original member set

**Browser:** Mode switcher (Convert / Merge / Split). Merge needs ≥2 `.nsp`/`.nsz`/`.xci`/`.xcz`, Split needs exactly 1 `.nsp`. Works with File System (FSA), Stream (Service Worker), or Blob download modes.

---

### Update pipeline tests (Node.js)

Test data: `/Users/rmitkov/Downloads/Stardew Valley [NSZ]/` (base `.nsz` v0 + update `.nsz` v1310720), yanu reference at the Downloads root, verified output `[NSZ]/…_updated.nsp` (sha256 `3bae0bac…`, 701,770,512 B).

| Script | What it verifies | Run (workdir) |
|---|---|---|
| `scripts/test_update_e2e.mjs` | fd (seekback) update e2e; member compare vs yanu reference (Program/CNMT contentId diff is the documented repack artifact, not a failure) | `scripts/` — `node test_update_e2e.mjs` |
| `scripts/test_update_sw_sim.mjs` | **all three modes** — fd/seekback, SW-sim/two-pass, fd/buffered — must yield ONE sha256 (`3bae0bac…`) and `exit(1)` on mismatch | `scripts/` — `node test_update_sw_sim.mjs` |
| `scripts/test_twopass_sw_sim.mjs` | two-pass through a faithful SW simulation (detach + copy transfer modes): 272 B header, 0 gap-fills/backward writes, **merge-level** equality (produced Program NCA merges byte-identical to the real update's merge), PFS0 name embeds sha256(Pass-2 NCA), detach ≡ copy contentId. The SW two-pass output is now a self-contained own-BKTR NCA (`fs/bktr-pack.js`), so the old yanu byte-compare no longer applies | `scripts/` — `node test_twopass_sw_sim.mjs` |
| `scripts/test_twopass_fsa_sim.mjs` | two-pass through a faithful FSA simulation (seek + positioned write, NO read): 272 B header, exactly one trailing 272-B PFS0-header write-back at offset 0 (the seekable two-pass NCA-first branch), **merge-level** equality (produced Program NCA merges byte-identical to the real update's merge), PFS0 name embeds sha256(Pass-2 NCA). Merge-level because the FSA two-pass output is a self-contained own-BKTR NCA (`fs/bktr-pack.js`); the old `_updated.nsp` yanu byte-compare no longer applies | `scripts/` — `node test_twopass_fsa_sim.mjs` |
| `scripts/test_own_bktr_pack.mjs` | **own-BKTR packer** on Stardew NSZ: direct packer (Pass-1 contentId == sha256(Pass-2 NCA), FsHeader/table/section structure, `mergeRomFS(base, own-NCA)` byte-identical to the real update's scatter merge — 606,401,864 B) + full `update()` SW run (no gaps, produced NCA merges byte-identical, determinism across passes). All in RAM, no disk | `scripts/` — `node test_own_bktr_pack.mjs` |
| `scripts/test_own_bktr_pack_ln2.mjs` | **own-BKTR structural** on the >2 GiB crash case (LN2): reloc/sub tables, bucket count, `totalSize` + virtual window preserved, all `isPatch=1`, phys offsets inside the data region & 16-aligned, sub = single `{0,0}` subsection, emit window covered; counting adapter proves no section-sized buffer is ever allocated | `scripts/` — `node test_own_bktr_pack_ln2.mjs` |
| `scripts/test_sw_chunk.mjs` | `sw-downloader.js` unit test (FakeSW with ack mocking): byte-for-byte stream equality for the 14-write buffered sequence (scaled), wasm-subarray safety (no detached transfer), small-write zero-copy, gap-fill correctness | `scripts/` — `node test_sw_chunk.mjs` |
| `scripts/test_truncated_container.mjs` | truncated-container diagnostics (synthetic PFS0, self-contained): valid PFS0 still opens; an entry past EOF is rejected by `openContainer` with the file/member/sizes in the message (the real 40 %-downloaded LOLLIPOP base `.nsz` case, which used to surface as `bad magic ''`); readers without a usable `length` skip the check; `decryptNcaHeader` reports empty/0x400 reads as short instead of a magic error, while full-size garbage keeps `bad magic` | repo root — `node scripts/test_truncated_container.mjs` |
| `scripts/test_update_progress.mjs` | update **progress protocol** (real pair, in-memory, no disk): per-phase fraction (0–1) with its OWN denominator, stable phase labels in order (two-pass/own-BKTR — 3 stages: `Reading BKTR tables... (1/3)` (own scale = table prefix decompression) → `Computing contentId (2/3)` (2×exefs + data region) → `Writing output (3/3)`; streaming: `Reading update sections...` → `Writing output (1/1)`; buffered — 2 stages: `Computing contentId (1/2)` → `Writing output (2/2)`), writes continuous across program+tail (monotonic within the write phase), each phase ends at exactly 1.0, write-phase `phaseBytes` == Program NCA + tail (two-pass) / > Program NCA + tail (streaming, contentId re-read), streaming ≡ buffered sha (the two-pass emits the self-contained own-BKTR NCA post-#135 — a different format by design, verified at merge level by `test_twopass_sw_sim`) | `scripts/` — `node test_update_progress.mjs` |
| `scripts/verify_ln2_update_nsz.mjs` | **LN2 two-pass update on the `.nsz` (NCZ) base** — the path the `.nsp` harness (`verify_ln2_update.mjs`) can't reach, because a `FileRangeSource` base's `registerRange()` is a no-op and never exercises the NCZ base-range registration. LN2's base `physOffset`s are a non-monotonic, overlapping permutation in reloc order (see `diag_ln2_reloc.mjs`), which used to throw `NczStreamSource: ranges must be strictly increasing`. Hash-only append-only writer; checks the Program-NCA contentId (`067f1c50…`) + declared size (5,326,224,720) against the known-good values. Needs the real LN2 `.nsz` pair (`/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]/`); ~110 s, ~5 GB RAM | `scripts/` — `node verify_ln2_update_nsz.mjs` |
| `scripts/verify_lollipop_update_nsz.mjs` | **LOLLIPOP CHAINSAW RePOP two-pass own-BKTR update on the `.nsz` pair — the browser-SW OOM case (#140)**. Hash-only append-only writer = the exact SW two-pass branch, no disk writes; samples its own peak RSS and (with `EXPECTED_CONTENT_ID`/`EXPECTED_SHA`) asserts byte-identity against the known-good run: contentId `f5dc3681…`, full-output sha256 `3b37bc21…`, 7,017,765,136 B / 4 members. Post-lockstep-fix peak RSS ≈ 0.81 GiB (`/usr/bin/time -l` maxrss) vs 6.77 GiB pre-fix (eager 6.94 GB range registration). Needs the real LOLLIPOP `.nsz` pair (`/Users/rmitkov/Downloads/Lollipop Chainsaw RePop [NSZ]/`); ~75 s | `scripts/` — `node verify_lollipop_update_nsz.mjs` |

Analysis tools (persisted forensics): `scripts/diag_ln2_reloc.mjs` (LN2 reloc table: dumps base non-patch ranges in virtual vs. physical order and the merge-into-union result — the non-monotonicity/overlap forensics behind the `registerBaseRanges` fix), `scripts/cmp_nsp_top.mjs` (top-level NSP PFS0 + Program NCA section tables of two outputs), `scripts/cmp_tail.mjs` (common-region diff + tail analysis of the larger file), `scripts/dump_buffered_writes.mjs` (buffered-path write sequence: pos/len/gap/backward per write), `scripts/cmp_exefs.mjs` / `cmp_exefs2.mjs` (ExeFS/RomFS bucket diffing vs the original update).

---

## 4. Test Coverage Summary

| Component | Python Ref | Node.js | Browser |
|-----------|-------------|---------|---------|
| AES-CTR keystream | ✅ test_aes_ctr.py | ✅ test_vector.mjs | ✅ test_browser.html |
| Counter format (BE64) | ✅ test_aes_ctr.py | ✅ test_vector.mjs | ✅ test_browser.html |
| AES-CTR seek + encrypt | - | ✅ test_aesctr.mjs | - |
| AES-CTR manual (Node crypto) | - | ✅ test_aes_manual.cjs | - |
| NCZ decompression | - | ✅ test_convert.mjs, test-ncz.mjs | - |
| Byte-level decompress verify | - | ✅ test_decompress.mjs | - |
| PFS0 parsing | - | ✅ test_convert.mjs | - |
| Ticket key analysis | - | ✅ test_ticket_keys.mjs | - |
| AES-CTR + zstd | - | ✅ test_convert.mjs | - |
| NSP/XCI merge (union + dedup, XCI inputs) | ✅ FinalRom merger | ✅ CLI (synthetic NSP + XCI) | ✅ browser/Playwright |
| NSZ/XCZ merge (NCZ decompression to .nca) | - | ✅ test_merge_ncz.mjs (streaming + NCZBLOCK) | ✅ browser/Playwright |
| NSP split (CNMT grouping, per-title NSP) | ✅ FinalRom unmerger | ✅ CLI (synthetic NSP + real keys) | ✅ browser/Playwright |
| Update: 3 modes ≡ 1 sha (Stardew) | ✅ yanu reference | ✅ test_update_sw_sim.mjs, test_update_e2e.mjs | ✅ browser retest |
| Update two-pass SW sim (detach + copy) | ✅ merge-level (own-BKTR) | ✅ test_twopass_sw_sim.mjs | - |
| Update two-pass FSA sim (seek, no read) | ✅ merge-level (own-BKTR) | ✅ test_twopass_fsa_sim.mjs | - |
| Own-BKTR packer (Stardew) | ✅ own layout | ✅ test_own_bktr_pack.mjs | - |
| Own-BKTR >2 GiB structural (LN2) | ✅ own layout | ✅ test_own_bktr_pack_ln2.mjs | - |
| SW backpressure (PULL ack flow) | - | ✅ test_sw_chunk.mjs | - |

---

## 5. Key Test Vectors

### AES-CTR Test Vector (from Python nsz)

This test verifies that keystream generation matches Python nsz.

**Inputs:**
- `Key` — encryption key (16 bytes, AES-128)
- `Nonce` — initial counter (16 bytes)
- `Offset` — file position where keystream is needed

**Calculation:**
1. `BlockIdx = Offset >> 4` (divide offset by AES block size = 16 bytes)
2. Build counter block: first 8 bytes = nonce[0:8], last 8 bytes = BlockIdx in big-endian
3. Encrypt counter block with AES-ECB → get keystream block

**Result:**
```
Key:       3c8358e37c54aca5bb20fc36741c1727
Nonce:    00000002000000000000000000000000 (16 bytes)
Offset:    131072 (0x20000)
BlockIdx:  8192 (offset >> 4)

Counter block (BE64): 00000002000000000000000000002000
Expected keystream (48 bytes): e95fed2b7d0afca982d145a0ddea1c84799cd6049be13c145365e02e7c0cd67c7dda265086d308349093deb0c56bd1e5
```

**Run the test:**
```bash
node scripts/test_vector.mjs
```

---

## 6. Running All Tests

### Self-contained (no external files needed):
```bash
# AES-CTR test vector (section 5)
node scripts/test_vector.mjs

# AES-CTR with seek + encrypt
node scripts/test_aesctr.mjs

# AES-CTR manual (uses Node crypto)
node test_aes_manual.cjs

# NCZ component tests (skips file-dependent tests)
node scripts/test-ncz.mjs

# Truncated-container diagnostics (synthetic PFS0 + short NCA-header reads)
node scripts/test_truncated_container.mjs
```

### Require NSZ file input:
```bash
# Full conversion pipeline
node scripts/test_convert.mjs path/to/file.nsz

# Decompression comparison against reference NSP
node scripts/test_decompress.mjs input.nsz [working.nsp]

# Ticket key and section analysis
node scripts/test_ticket_keys.mjs input.nsz [working.nsp]
```

### Browser tests:
Open `test_browser.html` in a browser.

---

## 7. Debugging Tips

1. **AES-CTR mismatch:** Check counter byte order (bytes 8-15 must be big-endian)
2. **NCZ magic not found:** Check if NCA header is present (0x4000 bytes before "NCZSECTN")
3. **Decompression fails:** Enable debug logs in `ncz.js` (already added)
4. **Hash mismatch:** Verify AES-CTR is using correct offset (must be `offset >> 4`, not `offset`)

---

## 8. Adding New Tests

When adding new tests:
1. Use Python nsz as reference implementation
2. Test against known-good keystream/output
3. Include both Node.js and browser versions if testing crypto
4. Document test vectors and expected output
