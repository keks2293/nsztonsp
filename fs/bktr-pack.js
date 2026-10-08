// Own-BKTR Program NCA writer for sequential (SW) outputs with an NCZ BKTR update.
//
// Why this exists: on an append-only (SW) output with an NCZ BKTR update, the
// two-pass path previously merged the RomFS by relying on the update's sparse
// view. For updates whose BKTR section is a single run
// larger than the platform ArrayBuffer ceiling (~2 GiB, e.g. LOLLIPOP CHAINSAW
// RePOP), holding or slicing that section is impossible. This writer instead
// EMITS a self-contained BKTR NCA whose section-1 layout is entirely ours:
//
//   sec1 = [ dataRegion ][ relocTable ][ subTable ][ pad ]
//
//   dataRegion = ALL merged RomFS bytes in a fresh physical layout
//                (patch union intervals in physical-asc order, then base
//                union intervals) — every run is copied (patches re-CRT'd from
//                the update, base runs CTR-decrypted from the base and
//                re-encrypted), so the resulting NCA needs NO base or update
//                at read time.
//   relocTable = our own bucket tree: every entry isPatch=1 and maps the
//                ORIGINAL virtual offsets onto our data region.
//   subTable   = one subsection [0, dataRegionSize) with ctrVal=0, encrypted
//                with our own FsHeader section_ctr (gen=1,secv=2).
//
// mergeRomFS(base, ours) then reproduces byte-identical merged RomFS output
// without ever touching the base source, and the writer itself only streams
// (no section-sized ArrayBuffer anywhere).
//
// Discipline mirrors the rest of the two-pass path:
//   Pass 1 (computeOwnBktrContentId): hashes the final NCA bytes in FILE order
//     (encHeader | exe htable | exefs | exePad | dataRegion | relocEnc | subEnc
//     | romPad). The data region is hashed WHILE it is produced, in physical
//     order — the same single read pass feeds both the AesCtr and the hash.
//   Pass 2 (writeOwnBktrProgramNca): re-reads the same patch + base runs with
//     FRESH sources and a FRESH AesCtr (seek(sec1Start), same nonce), so the
//     ciphertext is deterministic between the passes, then writes sequentially.
//
// Sources: compute/write take closures makeUpdateSource(ranges) and
// makeBaseSource() (see update.js) so a fresh sequential base/update source can
// be created per pass (an NczStreamSource with the pre-registered ranges).

import { AesCtr } from '../crypto/aes-ops.mjs';
import { createStreamingSHA256 } from '../crypto/sha256.js';
import { readLeU32, readLeU64, writeU32LE, writeU64LE } from './bytes.js';
import { decryptNcaHeader } from './nca.js';
import {
    NCA_HEADER_SIZE, NCA_HDR, FS_HDR, NCA_CONTENT_TYPE,
    SECTION_FS_TYPE, SECTION_CRYPTO_TYPE,
    decryptNcaHeaderBytes, fsHeaderAt, reversedSectionCtr,
} from './nca-utils.js';
import { decryptBktrTableData } from './bktr.js';
import { resolveBktrMeta, readBktrTables, readPatchRun, readBaseRun, registerBaseRanges, createLockstepReader } from './bktr-merge.js';
import {
    buildNcaHeader, buildPfs0FsHeader, fillPfs0Superblock, fillSectionHashes,
    encryptNcaHeader, StreamingPfs0Hasher, pad200, PFS0_EXEFS_HASH_BLOCK_SIZE, CRYPT,
} from './nca-pack.js';

const BKTR_MAGIC = 0x52544B42; // "BKTR"
const BUCKET_SIZE = 0x4000;
const RELOC_ENTRIES_PER_BUCKET = 818;  // 0x3FF0 / 0x14
const RELOC_ENTRY_SIZE = 0x14;         // virt u64 | phys u64 | isPatch u32
const SUB_ENTRIES_PER_BUCKET = 1023;   // 0x3FF0 / 0x10
const SUB_ENTRY_SIZE = 0x10;           // offset u64 | _0x8 u32 | ctr_val u32
const GENERATION = 1;                  // ours — any value ≥ real update's gen works for the reader
const SECURE_VALUE = 2;                // matches the base/update secure value (AesCtrUpperIv)
// Our data region is one AES-CTR(-EX) stream with counter head
// [secv_BE ‖ ctrVal_BE] = [00 00 00 02 00 00 00 00], starting at sec1Start.
const OWN_DATA_NONCE = new Uint8Array([0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]);

function ceil16(n) { return Math.ceil(n / 16) * 16; }
function numBucketsOf(n, per) { return Math.max(1, Math.ceil(n / per)); }

// Sort runs by start, merge overlapping/nesting runs into their union (includes
// a defensive copy so caller arrays are never mutated).
function unionIntervals(runs) {
    const sorted = [...runs].sort((a, b) => a.start - b.start);
    const merged = [];
    for (const r of sorted) {
        const last = merged[merged.length - 1];
        if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
        else merged.push({ start: r.start, end: r.end });
    }
    return merged.map((m) => ({ start: m.start, end: m.end, len: m.end - m.start }));
}

// Binary search: last interval with interval.start <= start (intervals sorted
// asc, disjoint). Returns the interval or null.
function findInterval(ivs, start) {
    let lo = 0, hi = ivs.length - 1, ans = -1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (ivs[mid].start <= start) { ans = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    return ans < 0 ? null : ivs[ans];
}

// ── Own layout ───────────────────────────────────────────────────────────────
// ── Optional phase instrumentation (benchmarks) ───────────────────────────────
// No-op unless setBktrPhaseHook() is called. Reports { name, bytes, ms, cpuMs }
// when a phase ends; cpuMs carries a wall-time charge for the phase's inner hot
// op (sha.update in pass 1, adapter.write in pass 2) so benchmark scripts can
// attribute walk time to decompress+AES vs hash/write.
let _phaseHook = null;
export function setBktrPhaseHook(fn) { _phaseHook = fn; }
function repPhase(name, bytes, t0, cpuMs = 0) {
    if (_phaseHook) _phaseHook({ name, bytes, ms: performance.now() - t0, cpuMs });
}

export function buildOwnBktrLayout(exefsSize, dataRegionSize, nReloc, nSub) {
    const exeHtableSize = pad200(Math.ceil(exefsSize / PFS0_EXEFS_HASH_BLOCK_SIZE) * 0x20);
    const exeSectionSize = pad200(exeHtableSize + exefsSize);
    const sec0Start = NCA_HEADER_SIZE;
    const sec0DataOff = sec0Start + exeHtableSize;
    const sec0End = sec0Start + exeSectionSize;
    const sec1Start = sec0End;
    const relocBlockSize = BUCKET_SIZE + numBucketsOf(nReloc, RELOC_ENTRIES_PER_BUCKET) * BUCKET_SIZE;
    const subBlockSize = BUCKET_SIZE + numBucketsOf(nSub, SUB_ENTRIES_PER_BUCKET) * BUCKET_SIZE;
    const relocOff = dataRegionSize;
    const subOff = relocOff + relocBlockSize;
    const romSectionSize = pad200(subOff + subBlockSize);
    const sec1End = sec1Start + romSectionSize;
    const ncaSize = sec1End;
    return {
        exeHtableSize, exeSectionSize, sec0Start, sec0End, sec0DataOff,
        sec1Start, sec1End, relocOff, subOff, relocBlockSize, subBlockSize,
        romSectionSize, ncaSize, exefsSize,
        exePaddingSize: exeSectionSize - (exeHtableSize + exefsSize),
        romPaddingSize: romSectionSize - (subOff + subBlockSize),
    };
}

// ── Table buffers (plaintext; encrypted later with our own section_ctr) ──────
// Relocation block layout (hactool bktr.h, verified against real updates):
//   _0x0 u32 = 0, num_buckets u32, total_size u64,
//   bucket_virtual_offsets[num_buckets] u64 @0x10,
//   bucket[b] @ 0x4000 + b*0x4000: idx u32, n_entries u32, bucket_end u64,
//   entries @ +0x10 (virt u64 | phys u64 | is_patch u32).
function buildRelocationBlock(entries, totalSize) {
    const numBuckets = numBucketsOf(entries.length, RELOC_ENTRIES_PER_BUCKET);
    const block = new Uint8Array(BUCKET_SIZE + numBuckets * BUCKET_SIZE);
    writeU32LE(block, 0x00, 0);
    writeU32LE(block, 0x04, numBuckets);
    writeU64LE(block, 0x08, totalSize);
    for (let b = 0; b < numBuckets; b++) {
        const first = b * RELOC_ENTRIES_PER_BUCKET;
        writeU64LE(block, 0x10 + b * 8, entries[first].virtOffset);
        const bOff = BUCKET_SIZE + b * BUCKET_SIZE;
        const n = Math.min(RELOC_ENTRIES_PER_BUCKET, entries.length - first);
        writeU32LE(block, bOff, b);
        writeU32LE(block, bOff + 4, n);
        const nextFirst = first + n;
        const end = nextFirst < entries.length ? entries[nextFirst].virtOffset : totalSize;
        writeU64LE(block, bOff + 8, end);
        let e = bOff + 0x10;
        for (let i = 0; i < n; i++) {
            const en = entries[first + i];
            writeU64LE(block, e, en.virtOffset);
            writeU64LE(block, e + 8, en.physOffset);
            writeU32LE(block, e + 0x10, en.isPatch ? 1 : 0);
            e += RELOC_ENTRY_SIZE;
        }
    }
    return block;
}

// Subsection block: same bucket structure; entries are
//   offset u64 | _0x8 u32=0 | ctr_val u32.
function buildSubsectionBlock(entries, totalSize) {
    const numBuckets = numBucketsOf(entries.length, SUB_ENTRIES_PER_BUCKET);
    const block = new Uint8Array(BUCKET_SIZE + numBuckets * BUCKET_SIZE);
    writeU32LE(block, 0x00, 0);
    writeU32LE(block, 0x04, numBuckets);
    writeU64LE(block, 0x08, totalSize);
    for (let b = 0; b < numBuckets; b++) {
        const first = b * SUB_ENTRIES_PER_BUCKET;
        writeU64LE(block, 0x10 + b * 8, entries[first].offset); // bucket_physical_offsets
        const bOff = BUCKET_SIZE + b * BUCKET_SIZE;
        const n = Math.min(SUB_ENTRIES_PER_BUCKET, entries.length - first);
        writeU32LE(block, bOff, b);
        writeU32LE(block, bOff + 4, n);
        const nextFirst = first + n;
        const end = nextFirst < entries.length ? entries[nextFirst].offset : totalSize;
        writeU64LE(block, bOff + 8, end);
        let e = bOff + 0x10;
        for (let i = 0; i < n; i++) {
            const en = entries[first + i];
            writeU64LE(block, e, en.offset);
            writeU32LE(block, e + 8, 0);
            writeU32LE(block, e + 12, en.ctrVal);
            e += SUB_ENTRY_SIZE;
        }
    }
    return block;
}

// ── Section-1 FsHeader + full NCA header ─────────────────────────────────────
// fs_type/hash_type/crypt_type bytes batch a real BKTR update (fs_header
// [0x02]=0x00, [0x03]=0x03, [0x04]=0x04). The IVFC superblock [0x08:0xE8) is
// copied verbatim from the update so the reader sees the same merged-data
// window. PatchInfo slots carry our table placement (section-relative).
function buildOwnBktrFsHeader({ updateFsHdr, relocOff, relocSize, subOff, subSize, nReloc, nSub }) {
    const fh = new Uint8Array(0x200);
    const v = new DataView(fh.buffer);
    v.setUint16(0, 2, true);
    fh[0x02] = 0x00;      // fs_type ROMFS (pack domain)
    fh[0x03] = 0x03;      // hash_type ROMFS — parse-domain section fsType
    fh[0x04] = 0x04;      // crypt_type BKTR
    fh.set(updateFsHdr.subarray(0x08, 0xE8), 0x08); // superblock verbatim copy
    fillPatchInfo(fh, FS_HDR.PATCH_INFO, relocOff, relocSize, nReloc);
    fillPatchInfo(fh, FS_HDR.PATCH_INFO_AESCTREX, subOff, subSize, nSub);
    writeU32LE(fh, FS_HDR.SECURE_VALUE - 4, GENERATION); // generation @0x140
    writeU32LE(fh, FS_HDR.SECURE_VALUE, SECURE_VALUE);   // secure_value @0x144
    return fh;
}

function fillPatchInfo(fh, off, blockOff, blockSize, nEntries) {
    writeU64LE(fh, off, blockOff);
    writeU64LE(fh, off + 8, blockSize);
    writeU32LE(fh, off + 0x10, BKTR_MAGIC);
    writeU32LE(fh, off + 0x14, 1);
    writeU64LE(fh, off + 0x18, nEntries);
}

function buildOwnBktrNcaHeader({ titleId, keys, ourTitlekey, L, exeHash, ownFsHdr }) {
    const header = buildNcaHeader(titleId, [
        { offset: L.sec0Start, endOffset: L.sec0End, size: L.exeSectionSize },
        { offset: L.sec1Start, endOffset: L.sec1End, size: L.romSectionSize },
    ], keys, NCA_CONTENT_TYPE.PROGRAM, { keyAreaSlot2: ourTitlekey });
    // Section 0: ExeFS (PFS0, CRYPT_NONE) with its standard superblock.
    const exeFsHdr = buildPfs0FsHeader(CRYPT.NONE);
    fillPfs0Superblock(exeFsHdr, exeHash.masterHash, {
        blockSize: PFS0_EXEFS_HASH_BLOCK_SIZE,
        hashTableSize: exeHash.rawHashSize,
        pfs0Offset: L.exeHtableSize,
        pfs0Size: L.exefsSize,
    });
    header.set(exeFsHdr, NCA_HDR.FS_HEADERS);
    header.set(ownFsHdr, NCA_HDR.FS_HEADERS + NCA_HDR.FS_HEADER_SIZE);
    fillSectionHashes(header);
    writeU64LE(header, NCA_HDR.SIZE, L.ncaSize);
    return encryptNcaHeader(header, keys);
}

// ── Data region: one sequential stream per pass ──────────────────────────────
// Re-read the patch union intervals (asc) then the base union intervals (asc),
// decrypt each from its source, re-encrypt with a fresh AesCtr over our own
// layout, and hand the ciphertext to onChunk(cipher, dataRegionOffset).
//
// Sources are fed through a BOUNDED lockstep reader when they are sequential
// NCZ streams (createLockstepReader), NOT range-registered: registration
// pre-allocates one Uint8Array per range, and patch + base together span the
// WHOLE data region (0x19de3b3c0 ≈ 6.9 GB on LOLLIPOP CHAINSAW RePOP) held
// simultaneously — the browser refuses that ("Array buffer allocation
// failed"). Both walks are union-sorted ascending and read forward-only (the
// lockstep contract), so one NCZ pass per source with a ~64 MiB window serves
// every read: peak memory is the window + one 16 MiB read, not the run set.
// Random-access sources keep the register path (a no-op for them).
async function walkDataRegion({ L, meta, makeUpdateSource, makeBaseSource, onChunk }) {
    const baseCtr = new AesCtr(meta.baseTitlekey, meta.baseNonce);
    // Guard the lockstep contract up front: a backward read would otherwise
    // surface as a confusing "stream ended before read". unionIntervals sorts
    // + merges, so this holds by construction.
    const asc = (arr, k) => arr.every((r, i, a) => i === 0 || r[k] >= a[i - 1][k] + a[i - 1].len);
    if (!asc(meta.patchAbsRanges, 'off') || !asc(meta.baseAbsRanges, 'start')) {
        throw new Error('own-BKTR: data-region intervals are not forward-only (union sort broken?) — cannot stream');
    }
    const patchSource = makeUpdateSource(meta.patchAbsRanges, null, { register: false });
    const baseSource = makeBaseSource();
    // Last wanted byte + 1 per source — the lockstep pass stops there.
    const patchEnd = meta.patchAbsRanges.reduce((e, r) => Math.max(e, r.off + r.len), 0);
    const baseEnd = meta.baseAbsRanges.reduce((e, r) => Math.max(e, r.start + r.len), 0);
    const patchLock = createLockstepReader(patchSource, patchEnd, 'patch');
    const baseLock = createLockstepReader(baseSource, baseEnd, 'base');
    // Fallback: non-NCZ sources get the (no-op) registration — reads go direct.
    if (!patchLock) {
        for (const r of meta.patchAbsRanges) patchSource.registerRange(r.off, r.len);
    }
    if (!baseLock) {
        registerBaseRanges(baseSource, meta.baseAbsRanges.map((r) => ({ start: r.start, end: r.start + r.len })));
    }
    const patchReader = patchLock || patchSource;
    const baseReader = baseLock || baseSource;

    const ownCtr = new AesCtr(meta.ourTitlekey, OWN_DATA_NONCE);
    ownCtr.seek(L.sec1Start);

    let placed = 0;
    try {
        for (const iv of meta.patchIntervals) {
            await readPatchRun(
                patchReader, meta.updateRomfsSecOffset, meta.updateSubBlock,
                meta.updateTitlekey, meta.secureValue,
                iv.start, iv.place, iv.len,
                async (chunk) => {
                    const cp = await ownCtr.encrypt(chunk);
                    placed += cp.length;
                    await onChunk(cp, placed - cp.length);
                }
            );
        }
        for (const iv of meta.baseIntervals) {
            await readBaseRun(
                baseReader, meta.baseRomfsSecMeta.offset, meta.baseRomfsSecMeta.size, baseCtr,
                iv.start, iv.place, iv.len,
                async (chunk) => {
                    const cp = await ownCtr.encrypt(chunk);
                    placed += cp.length;
                    await onChunk(cp, placed - cp.length);
                }
            );
        }
        if (placed !== L.relocOff) {
            throw new Error(`own-BKTR: data region mismatch — placed 0x${placed.toString(16)} bytes, layout expects 0x${L.relocOff.toString(16)}`);
        }
    } finally {
        // Stop any in-flight lockstep pass (error path); a clean pass already
        // stopped itself at totalEnd (finish is idempotent).
        if (patchLock) patchLock.finish();
        if (baseLock) baseLock.finish();
    }
}

// ── Pass 1: compute layout + contentId ───────────────────────────────────────
// streamExefs must be re-callable (a fresh factory result, one ExeFS extract
// stream per call): once for the PFS0 hash table, once for the contentId hash.
// ── Pass 1 (seekable variant): resolve layout + header, NO data walk ─────────
// The seekable (FSA/memory) two-pass branch has no Pass-1 hash walk: the NCA is
// written FIRST and the 272-B PFS0 header only overwrites offset 0 at the very
// end (writeTwoPassProgramAndFinish), so the contentId is needed only AFTER the
// NCA bytes exist. The combined write pass (writeOwnBktrProgramNcaSinglePass)
// hashes the bytes as it writes them; this function only builds the
// layout/header/tables (tables pass + exefs PFS0 hash + encHeader + relocEnc/
// subEnc). The data walk — and with it the second update+base decompression +
// AES pass — is gone: update reads 3×→2×, base 2×→1× on this branch.
// NOTE: this is the layout-only half of computeOwnBktrContentId below (same
// tables/build work, no sha stream, no walkDataRegion). Keep them in sync.
export async function resolveOwnBktrLayout({
    baseNcaData, updateNcaData,
    makeUpdateSource, makeBaseSource,
    keys, baseTik, updateTik, baseTitlekey, updateTitlekey,
    titleId, exefsSize, romfsDataSize,
    streamExefs,
    log, progress,
}) {
    const _log = typeof log === 'function' ? log : () => {};
    const _prog = typeof progress === 'function' ? progress : () => {};

    _log('info', '  Single-pass own-BKTR (seekable): resolving own NCA layout (tables + header), contentId computed during the write...');
    let ph0 = performance.now();

    // Preamble: resolve BKTR parameters from the REAL update (titlekeys, table
    // absolute offsets) and grab its section-1 FsHeader for the superblock copy.
    const metaB = await resolveBktrMeta(baseNcaData, updateNcaData, { keys, baseTik, updateTik, baseTitlekey, updateTitlekey });
    _log('info', `  BKTR: romfsSec offset=0x${metaB.updateRomfsSec.offset.toString(16)}, reloc@0x${metaB.relocAbsOffset.toString(16)}+0x${metaB.relocHeader.size.toString(16)}, sub@0x${metaB.subAbsOffset.toString(16)}+0x${metaB.subHeader.size.toString(16)}`);

    const updateHeader = decryptNcaHeader(updateNcaData.headerRaw, keys);
    const updIdx = updateHeader.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
    if (updIdx < 0) throw new Error('own-BKTR: update has no BKTR romfs section');
    const updateDecHeader = decryptNcaHeaderBytes(updateNcaData.headerRaw, keys);
    const updateFsHdr = fsHeaderAt(updateDecHeader, updIdx);
    repPhase('resolve', 0, ph0);
    ph0 = performance.now();

    // Parse the real tables. Reaching them means a sequential NCZ pass over the
    // whole prefix up to the last table (reloc/sub sit deep in the file) — that
    // prefix decompression was previously invisible to the progress bar. Fold it
    // in as its own phase: the table source reports the far-most decompressed
    // absolute offset through the new onProgress hook.
    const tableRanges = [
        { off: metaB.relocAbsOffset, len: metaB.relocHeader.size },
        { off: metaB.subAbsOffset, len: metaB.subHeader.size },
    ].sort((a, b) => a.off - b.off);
    const tableReadEnd = tableRanges[tableRanges.length - 1].off + tableRanges[tableRanges.length - 1].len;
    // Pass 1 here does the table prefix + ONE exefs pass (the PFS0 hash table
    // → exeHash → encHeader); there is no data walk — the write pass owns it.
    // Phase protocol (#71): 'Reading BKTR tables... (1/3)' is stage 1 of the 3-stage
    // own-BKTR run (tables → resolve → write) with its OWN denominator — the
    // sequential prefix decompression to the tables (tableReadEnd bytes) fills
    // the bar 0→1, then the next stage starts at 0.
    let tablesDone = false;
    const tableSource = makeUpdateSource(tableRanges, (reached) => {
        if (tablesDone) return; // late pump event — phase already ended at 1.0
        _prog(Math.min(1, reached / tableReadEnd), 'Reading BKTR tables... (1/3)', tableReadEnd);
    });
    const { relocBlock, subBlock } = await readBktrTables(tableSource, metaB);
    tablesDone = true;
    _prog(1, 'Reading BKTR tables... (1/3)', tableReadEnd); // phase ends at exactly 1.0
    repPhase('tables', tableReadEnd, ph0);
    ph0 = performance.now();

    // Entry run lengths in VIRTUAL order.
    const entries = [];
    for (let i = 0; i < relocBlock.entries.length; i++) {
        const e = relocBlock.entries[i];
        const nextVirt = i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
        const len = nextVirt - e.virtOffset;
        if (len <= 0) throw new Error(`own-BKTR: zero-length relocation run at virt=0x${e.virtOffset.toString(16)}`);
        if (len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned run len 0x${len.toString(16)} — cannot build own layout`);
        entries.push({ virtOffset: e.virtOffset, physOffset: e.physOffset, isPatch: !!e.isPatch, len });
    }
    const totalVirtSize = relocBlock.totalSize;

    // Physical runs in the SOURCE data regions → union intervals (asc), placed
    // physically: patch first, then base copies.
    const patchRuns = [], baseRuns = [];
    for (const e of entries) (e.isPatch ? patchRuns : baseRuns).push({ start: e.physOffset, end: e.physOffset + e.len });
    const patchIntervals = unionIntervals(patchRuns);
    const baseIntervals = unionIntervals(baseRuns);
    if (patchIntervals.length === 0 && baseIntervals.length === 0) {
        throw new Error('own-BKTR: no patch or base runs to pack');
    }
    let cursor = 0;
    for (const iv of patchIntervals) {
        if (iv.len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned patch interval len 0x${iv.len.toString(16)}`);
        iv.place = cursor;
        cursor += ceil16(iv.len);
    }
    for (const iv of baseIntervals) {
        if (iv.len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned base interval len 0x${iv.len.toString(16)}`);
        iv.place = cursor;
        cursor += ceil16(iv.len);
    }
    const dataRegionSize = cursor;
    _log('info', `  own-BKTR: reloc=${entries.length} entries (patch=${patchRuns.length}, base=${baseRuns.length}), patch intervals=${patchIntervals.length}, base intervals=${baseIntervals.length}, data region=0x${dataRegionSize.toString(16)}`);

    // Map every run into our data region; every outgoing entry stays isPatch=1.
    const ownEntries = entries.map((e) => {
        const ivs = e.isPatch ? patchIntervals : baseIntervals;
        const iv = findInterval(ivs, e.physOffset);
        if (!iv || e.physOffset + e.len > iv.end) {
            throw new Error(`own-BKTR: run (${e.isPatch ? 'patch' : 'base'} phys=0x${e.physOffset.toString(16)} len=0x${e.len.toString(16)}) not covered by its union intervals`);
        }
        return { virtOffset: e.virtOffset, physOffset: iv.place + (e.physOffset - iv.start), isPatch: true };
    });

    const nReloc = ownEntries.length;
    const nSub = 2;
    const L = buildOwnBktrLayout(exefsSize, dataRegionSize, nReloc, nSub);
    _log('info', `  own-BKTR layout: exeSection=0x${L.exeSectionSize.toString(16)}, sec1Start=0x${L.sec1Start.toString(16)}, reloc@0x${L.relocOff.toString(16)}+0x${L.relocBlockSize.toString(16)}, sub@0x${L.subOff.toString(16)}+0x${L.subBlockSize.toString(16)}, ncaSize=0x${L.ncaSize.toString(16)}`);

    // Plaintext tables.
    const relocPlain = buildRelocationBlock(ownEntries, totalVirtSize);
    const subEntries = [
        { offset: 0, ctrVal: 0 },
        { offset: dataRegionSize, ctrVal: 1 }, // sentinel (boundary marker)
    ];
    const subPlain = buildSubsectionBlock(subEntries, dataRegionSize);

    // ExeFS PFS0 hash table (feeds exeHash → encHeader).
    let done = 0;
    // Own denominator for this phase (the table prefix was the previous phase,
    // already shown 0→100% on its own scale): the single exefs pass fills 0→1
    // and lands exactly on 1.0.
    const rep = (n) => {
        done += n;
        _prog(Math.min(1, done / exefsSize), 'Resolving layout (2/3)', exefsSize);
    };
    const pfs0 = new StreamingPfs0Hasher(PFS0_EXEFS_HASH_BLOCK_SIZE);
    await streamExefs(async (chunk) => { pfs0.update(chunk, true); rep(chunk.length); });
    const exeHash = await pfs0.finalize();

    // Header + encrypted tables.
    const ownFsHdr = buildOwnBktrFsHeader({
        updateFsHdr, relocOff: L.relocOff, relocSize: L.relocBlockSize,
        subOff: L.subOff, subSize: L.subBlockSize, nReloc, nSub,
    });
    const encHeader = buildOwnBktrNcaHeader({ titleId, keys, ourTitlekey: metaB.updateTitlekey, L, exeHash, ownFsHdr });
    const ownTableNonce = reversedSectionCtr(ownFsHdr); // [00 00 00 02 00 00 00 01]
    const relocEnc = await decryptBktrTableData(relocPlain, metaB.updateTitlekey, ownTableNonce, L.sec1Start + L.relocOff);
    const subEnc = await decryptBktrTableData(subPlain, metaB.updateTitlekey, ownTableNonce, L.sec1Start + L.subOff);
    repPhase('build', exefsSize, ph0);
    ph0 = performance.now();

    // Meta handed to the single write+hash pass (sources re-created fresh).
    const meta = {
        L, encHeader, exeHash, ourTitlekey: metaB.updateTitlekey,
        patchIntervals, baseIntervals,
        patchAbsRanges: patchIntervals.map((iv) => ({ off: metaB.updateRomfsSec.offset + iv.start, len: iv.len })),
        baseAbsRanges: baseIntervals.map((iv) => ({ start: metaB.baseRomfsSecMeta.offset + iv.start, len: iv.len })),
        updateRomfsSecOffset: metaB.updateRomfsSec.offset,
        baseRomfsSecMeta: metaB.baseRomfsSecMeta,
        updateSubBlock: subBlock,
        updateTitlekey: metaB.updateTitlekey, secureValue: metaB.secureValue,
        baseTitlekey: metaB.baseTitlekey, baseNonce: metaB.baseNonce,
        relocEnc, subEnc,
    };

    return { size: L.ncaSize, meta };
}

export async function computeOwnBktrContentId({
    baseNcaData, updateNcaData,
    makeUpdateSource, makeBaseSource,
    keys, baseTik, updateTik, baseTitlekey, updateTitlekey,
    titleId, exefsSize, romfsDataSize,
    streamExefs,
    log, progress,
}) {
    const _log = typeof log === 'function' ? log : () => {};
    const _prog = typeof progress === 'function' ? progress : () => {};

    _log('info', '  Two-pass own-BKTR: computing own NCA layout + contentId (Pass 1)...');
    const t0 = performance.now();
    let ph0 = performance.now();

    // Preamble: resolve BKTR parameters from the REAL update (titlekeys, table
    // absolute offsets) and grab its section-1 FsHeader for the superblock copy.
    const metaB = await resolveBktrMeta(baseNcaData, updateNcaData, { keys, baseTik, updateTik, baseTitlekey, updateTitlekey });
    _log('info', `  BKTR: romfsSec offset=0x${metaB.updateRomfsSec.offset.toString(16)}, reloc@0x${metaB.relocAbsOffset.toString(16)}+0x${metaB.relocHeader.size.toString(16)}, sub@0x${metaB.subAbsOffset.toString(16)}+0x${metaB.subHeader.size.toString(16)}`);

    const updateHeader = decryptNcaHeader(updateNcaData.headerRaw, keys);
    const updIdx = updateHeader.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
    if (updIdx < 0) throw new Error('own-BKTR: update has no BKTR romfs section');
    const updateDecHeader = decryptNcaHeaderBytes(updateNcaData.headerRaw, keys);
    const updateFsHdr = fsHeaderAt(updateDecHeader, updIdx);
    repPhase('resolve', 0, ph0);
    ph0 = performance.now();

    // Parse the real tables. Reaching them means a sequential NCZ pass over the
    // whole prefix up to the last table (reloc/sub sit deep in the file) — that
    // prefix decompression was previously invisible to the progress bar. Fold it
    // in as its own phase: the table source reports the far-most decompressed
    // absolute offset through the new onProgress hook.
    const tableRanges = [
        { off: metaB.relocAbsOffset, len: metaB.relocHeader.size },
        { off: metaB.subAbsOffset, len: metaB.subHeader.size },
    ].sort((a, b) => a.off - b.off);
    const tableReadEnd = tableRanges[tableRanges.length - 1].off + tableRanges[tableRanges.length - 1].len;
    // Phase protocol (#71): 'Reading BKTR tables... (1/3)' is stage 1 of the 3-stage
    // own-BKTR run (tables → compute → write) with its own denominator — the
    // sequential prefix decompression to the tables (tableReadEnd bytes, the
    // zstd/AES pass that physically must decode the whole RomFS prefix to reach
    // the tables at its tail) fills the bar 0→1; the compute stage (2/3) that
    // follows starts fresh at 0 with its own scale.
    let tablesDone = false;
    const tableSource = makeUpdateSource(tableRanges, (reached) => {
        if (tablesDone) return; // late pump event — phase already ended at 1.0
        _prog(Math.min(1, reached / tableReadEnd), 'Reading BKTR tables... (1/3)', tableReadEnd);
    });
    const { relocBlock, subBlock } = await readBktrTables(tableSource, metaB);
    tablesDone = true;
    _prog(1, 'Reading BKTR tables... (1/3)', tableReadEnd); // phase ends at exactly 1.0
    repPhase('tables', tableReadEnd, ph0);
    ph0 = performance.now();

    // Entry run lengths in VIRTUAL order.
    const entries = [];
    for (let i = 0; i < relocBlock.entries.length; i++) {
        const e = relocBlock.entries[i];
        const nextVirt = i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
        const len = nextVirt - e.virtOffset;
        if (len <= 0) throw new Error(`own-BKTR: zero-length relocation run at virt=0x${e.virtOffset.toString(16)}`);
        if (len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned run len 0x${len.toString(16)} — cannot build own layout`);
        entries.push({ virtOffset: e.virtOffset, physOffset: e.physOffset, isPatch: !!e.isPatch, len });
    }
    const totalVirtSize = relocBlock.totalSize;

    // Physical runs in the SOURCE data regions → union intervals (asc), placed
    // physically: patch first, then base copies.
    const patchRuns = [], baseRuns = [];
    for (const e of entries) (e.isPatch ? patchRuns : baseRuns).push({ start: e.physOffset, end: e.physOffset + e.len });
    const patchIntervals = unionIntervals(patchRuns);
    const baseIntervals = unionIntervals(baseRuns);
    if (patchIntervals.length === 0 && baseIntervals.length === 0) {
        throw new Error('own-BKTR: no patch or base runs to pack');
    }
    let cursor = 0;
    for (const iv of patchIntervals) {
        if (iv.len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned patch interval len 0x${iv.len.toString(16)}`);
        iv.place = cursor;
        cursor += ceil16(iv.len);
    }
    for (const iv of baseIntervals) {
        if (iv.len % 16 !== 0) throw new Error(`own-BKTR: non-16-aligned base interval len 0x${iv.len.toString(16)}`);
        iv.place = cursor;
        cursor += ceil16(iv.len);
    }
    const dataRegionSize = cursor;
    _log('info', `  own-BKTR: reloc=${entries.length} entries (patch=${patchRuns.length}, base=${baseRuns.length}), patch intervals=${patchIntervals.length}, base intervals=${baseIntervals.length}, data region=0x${dataRegionSize.toString(16)}`);

    // Map every run into our data region; every outgoing entry stays isPatch=1.
    const ownEntries = entries.map((e) => {
        const ivs = e.isPatch ? patchIntervals : baseIntervals;
        const iv = findInterval(ivs, e.physOffset);
        if (!iv || e.physOffset + e.len > iv.end) {
            throw new Error(`own-BKTR: run (${e.isPatch ? 'patch' : 'base'} phys=0x${e.physOffset.toString(16)} len=0x${e.len.toString(16)}) not covered by its union intervals`);
        }
        return { virtOffset: e.virtOffset, physOffset: iv.place + (e.physOffset - iv.start), isPatch: true };
    });

    const nReloc = ownEntries.length;
    const nSub = 2;
    const L = buildOwnBktrLayout(exefsSize, dataRegionSize, nReloc, nSub);
    _log('info', `  own-BKTR layout: exeSection=0x${L.exeSectionSize.toString(16)}, sec1Start=0x${L.sec1Start.toString(16)}, reloc@0x${L.relocOff.toString(16)}+0x${L.relocBlockSize.toString(16)}, sub@0x${L.subOff.toString(16)}+0x${L.subBlockSize.toString(16)}, ncaSize=0x${L.ncaSize.toString(16)}`);

    // Plaintext tables.
    const relocPlain = buildRelocationBlock(ownEntries, totalVirtSize);
    const subEntries = [
        { offset: 0, ctrVal: 0 },
        { offset: dataRegionSize, ctrVal: 1 }, // sentinel (boundary marker)
    ];
    const subPlain = buildSubsectionBlock(subEntries, dataRegionSize);

    // ExeFS PFS0 hash table (pass A).
    let done = 0;
    // Own denominator for this phase (the table prefix was the previous phase,
    // already shown 0→100% on its own scale): 2×exefs + data region — the
    // exact bytes this phase walks, so it fills 0→1 and lands exactly on 1.0.
    const computeTotal = 2 * exefsSize + dataRegionSize;
    const rep = (n) => {
        done += n;
        _prog(Math.min(1, done / computeTotal), 'Computing contentId (2/3)', computeTotal);
    };
    const pfs0 = new StreamingPfs0Hasher(PFS0_EXEFS_HASH_BLOCK_SIZE);
    await streamExefs(async (chunk) => { pfs0.update(chunk, true); rep(chunk.length); });
    const exeHash = await pfs0.finalize();

    // Header + encrypted tables.
    const ownFsHdr = buildOwnBktrFsHeader({
        updateFsHdr, relocOff: L.relocOff, relocSize: L.relocBlockSize,
        subOff: L.subOff, subSize: L.subBlockSize, nReloc, nSub,
    });
    const encHeader = buildOwnBktrNcaHeader({ titleId, keys, ourTitlekey: metaB.updateTitlekey, L, exeHash, ownFsHdr });
    const ownTableNonce = reversedSectionCtr(ownFsHdr); // [00 00 00 02 00 00 00 01]
    const relocEnc = await decryptBktrTableData(relocPlain, metaB.updateTitlekey, ownTableNonce, L.sec1Start + L.relocOff);
    const subEnc = await decryptBktrTableData(subPlain, metaB.updateTitlekey, ownTableNonce, L.sec1Start + L.subOff);
    repPhase('build', exefsSize, ph0);
    ph0 = performance.now();

    // Meta handed to Pass 2 (sources re-created fresh per pass).
    const meta = {
        L, encHeader, exeHash, ourTitlekey: metaB.updateTitlekey,
        patchIntervals, baseIntervals,
        patchAbsRanges: patchIntervals.map((iv) => ({ off: metaB.updateRomfsSec.offset + iv.start, len: iv.len })),
        baseAbsRanges: baseIntervals.map((iv) => ({ start: metaB.baseRomfsSecMeta.offset + iv.start, len: iv.len })),
        updateRomfsSecOffset: metaB.updateRomfsSec.offset,
        baseRomfsSecMeta: metaB.baseRomfsSecMeta,
        updateSubBlock: subBlock,
        updateTitlekey: metaB.updateTitlekey, secureValue: metaB.secureValue,
        baseTitlekey: metaB.baseTitlekey, baseNonce: metaB.baseNonce,
        relocEnc, subEnc,
    };

    // ContentId = sha256 over the NCA in file order.
    const sha = createStreamingSHA256();
    sha.update(encHeader);
    sha.update(exeHash.hashTable);
    let shaMs = 0;
    await streamExefs(async (chunk) => { const st = performance.now(); sha.update(chunk); shaMs += performance.now() - st; rep(chunk.length); });
    if (L.exePaddingSize > 0) sha.update(new Uint8Array(L.exePaddingSize));
    repPhase('sha-head', exefsSize, ph0, shaMs);
    shaMs = 0;
    ph0 = performance.now();
    await walkDataRegion({ L, meta, makeUpdateSource, makeBaseSource, onChunk: async (cp) => { const st = performance.now(); sha.update(cp); shaMs += performance.now() - st; rep(cp.length); } });
    repPhase('walk-hash', dataRegionSize, ph0, shaMs);
    ph0 = performance.now();
    sha.update(relocEnc);
    sha.update(subEnc);
    if (L.romPaddingSize > 0) sha.update(new Uint8Array(L.romPaddingSize));
    const contentId = sha.hex();
    repPhase('sha-tail', 0, ph0);

    _log('info', `  Two-pass own-BKTR contentId (Pass 1): ${contentId} (${L.ncaSize} bytes NCA)`);
    return { size: L.ncaSize, contentId, meta };
}

// ── Pass 2: write the same bytes sequentially ────────────────────────────────
export async function writeOwnBktrProgramNca({ meta, adapter, ncaOffset, contentId, streamExefs, makeUpdateSource, makeBaseSource, log, progress }) {
    const _log = typeof log === 'function' ? log : () => {};
    const _prog = typeof progress === 'function' ? progress : () => {};
    const { L, encHeader, exeHash, relocEnc, subEnc } = meta;

    let expected = ncaOffset;
    let done = 0;
    const w = async (pos, data) => {
        if (pos !== expected) {
            throw new Error(`writeOwnBktrProgramNca: non-sequential write at 0x${pos.toString(16)} (expected 0x${expected.toString(16)})`);
        }
        const n = data.byteLength;
        expected += n;
        done += n;
        if (_prog) _prog(Math.min(1, done / L.ncaSize));
        return await adapter.write(pos, data);
    };

    _log('info', '  Pass 2: writing own-BKTR NCA sequentially...');
    let ph0 = performance.now();
    await w(ncaOffset, encHeader);
    await w(ncaOffset + L.sec0Start, exeHash.hashTable);
    await streamExefs(async (chunk, off) => {
        await w(ncaOffset + L.sec0DataOff + off, chunk);
    });
    if (L.exePaddingSize > 0) {
        await w(ncaOffset + L.sec0DataOff + L.exefsSize, new Uint8Array(L.exePaddingSize));
    }
    repPhase('hdr-write', L.sec0Start + L.sec0End - L.sec0DataOff, ph0);
    ph0 = performance.now();
    let writeMs = 0;
    await walkDataRegion({ L, meta, makeUpdateSource, makeBaseSource, onChunk: async (cp, placed) => {
        const wt = performance.now();
        await w(ncaOffset + L.sec1Start + placed, cp);
        writeMs += performance.now() - wt;
    } });
    repPhase('walk-write', L.relocOff, ph0, writeMs);
    ph0 = performance.now();
    await w(ncaOffset + L.sec1Start + L.relocOff, relocEnc);
    await w(ncaOffset + L.sec1Start + L.subOff, subEnc);
    if (L.romPaddingSize > 0) {
        await w(ncaOffset + L.sec1Start + L.subOff + L.subBlockSize, new Uint8Array(L.romPaddingSize));
    }
    repPhase('tl-write', L.relocBlockSize + L.subBlockSize, ph0);
    if (_prog) _prog(1);
    return contentId;
}

// ── Single-pass (seekable): write + hash inline ──────────────────────────────
// For seekable (FSA/memory) outputs the NCA is written FIRST (the contentId is
// only needed for the trailing 272-B PFS0 header that overwrites offset 0), so
// the Pass-1 hash walk and the Pass-2 write walk merge into ONE walk: every
// chunk is decrypt→AES-re-encrypt→sha.update→adapter.write in NCA file order.
// The returned id IS sha256 of the written bytes — byte-identical to the old
// Pass-1 contentId, because the walk's ciphertext is deterministic (same union
// intervals, same AesCtr key/nonce and seek(sec1Start)). This removes the
// second full update+base decompression + AES pass (update reads 3×→2×, base
// 2×→1× on the seekable branch); SW/appendOnly keeps the two-pass writers.
export async function writeOwnBktrProgramNcaSinglePass({ meta, adapter, ncaOffset, contentId, streamExefs, makeUpdateSource, makeBaseSource, log, progress }) {
    const _log = typeof log === 'function' ? log : () => {};
    const _prog = typeof progress === 'function' ? progress : () => {};
    const { L, encHeader, exeHash, relocEnc, subEnc } = meta;

    let expected = ncaOffset;
    let done = 0;
    const sha = createStreamingSHA256();
    const w = async (pos, data) => {
        if (pos !== expected) {
            throw new Error(`writeOwnBktrProgramNcaSinglePass: non-sequential write at 0x${pos.toString(16)} (expected 0x${expected.toString(16)})`);
        }
        const n = data.byteLength;
        expected += n;
        done += n;
        if (_prog) _prog(Math.min(1, done / L.ncaSize));
        sha.update(data);
        return await adapter.write(pos, data);
    };

    _log('info', '  Single-pass: writing own-BKTR NCA + hashing inline...');
    let ph0 = performance.now();
    await w(ncaOffset, encHeader);
    await w(ncaOffset + L.sec0Start, exeHash.hashTable);
    let writeMs = 0;
    await streamExefs(async (chunk, off) => {
        const wt = performance.now();
        await w(ncaOffset + L.sec0DataOff + off, chunk);
        writeMs += performance.now() - wt;
    });
    if (L.exePaddingSize > 0) {
        await w(ncaOffset + L.sec0DataOff + L.exefsSize, new Uint8Array(L.exePaddingSize));
    }
    repPhase('hdr-write', L.sec0Start + L.sec0End - L.sec0DataOff, ph0, writeMs);
    ph0 = performance.now();
    let walkMs = 0;
    await walkDataRegion({ L, meta, makeUpdateSource, makeBaseSource, onChunk: async (cp, placed) => {
        const wt = performance.now();
        await w(ncaOffset + L.sec1Start + placed, cp);
        walkMs += performance.now() - wt;
    } });
    repPhase('walk-write-hash', L.relocOff, ph0, walkMs);
    ph0 = performance.now();
    await w(ncaOffset + L.sec1Start + L.relocOff, relocEnc);
    await w(ncaOffset + L.sec1Start + L.subOff, subEnc);
    if (L.romPaddingSize > 0) {
        await w(ncaOffset + L.sec1Start + L.subOff + L.subBlockSize, new Uint8Array(L.romPaddingSize));
    }
    repPhase('tl-write', L.relocBlockSize + L.subBlockSize, ph0);
    if (_prog) _prog(1);
    const id = sha.hex();
    _log('info', `  Single-pass own-BKTR contentId (sha of written bytes): ${id}`);
    return id;
}