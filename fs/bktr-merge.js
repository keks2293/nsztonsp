import { AesCtr } from '../crypto/aes-ops.mjs';
import { decryptNcaHeader } from './nca.js';
import { NczStreamSource, STOP_STREAM } from './range-source.js';
import { readLeU64, readLeU32, CHUNK_16MB } from './bytes.js';
import { yieldToEventLoop } from './event-loop.js';
import { decryptNcaHeaderBytes, fsHeaderAt, reversedSectionCtr, extractTitlekeyFromTik, deriveTitlekeyFromKeyArea, IVFC_LEVEL_HDR, IVFC_LEVELS_OFFSET, IVFC_MAX_LEVEL, FS_HDR, SECTION_FS_TYPE, SECTION_CRYPTO_TYPE } from './nca-utils.js';
import {
    parseBktrHeader,
    decryptBktrTableData,
    parseRelocationBlock,
    parseSubsectionBlock,
    findSubsectionEntry,
    subEntryIdx,
    decryptPatchRegionData,
    lookupTitlekeyFromDatabase,
} from './bktr.js';

// An NcaInput is { headerRaw: Uint8Array(0xC00), source: RangeSource } where
// source.read(offset, length) serves NCA ciphertext by absolute offset. Callers
// (update.js) always build one; mergeRomFS/scatterRomFS/resolveBktrMeta take it
// as-is (no raw-buffer auto-wrap).
const BKTR_MAGIC = 0x52544B42; // "BKTR"

// Register the base romfs ranges on a source (possibly a sequential NczStreamSource).
// The base physical order is NOT guaranteed to match the reloc (virtual) order, and
// entries can OVERLAP or NEST: an update re-lays-out the base romfs, so several
// virtual runs may reference the same base offset with different lengths (LN2:
// 2780/2800 base ranges are non-monotonic in virtual order, 275 overlap after a
// plain sort). A sequential source needs strictly-increasing, non-overlapping
// ranges, so: sort by start, merge overlapping/nested ranges into their union, then
// register. Reads are sub-ranges and map to the merged range by physical offset,
// independent of registration order. File/buffer sources ignore registration (no-op),
// so this is a no-op for them.
//   ranges: [{ start, end }] absolute NCA offsets of each base run.
export function registerBaseRanges(source, ranges) {
    ranges.sort((a, b) => a.start - b.start);
    const merged = [];
    for (const r of ranges) {
        const last = merged[merged.length - 1];
        if (last && r.start <= last.end) {
            last.end = Math.max(last.end, r.end); // overlap or nesting — take the union
        } else {
            merged.push({ start: r.start, end: r.end });
        }
    }
    for (const r of merged) source.registerRange(r.start, r.end - r.start);
    return merged;
}

// Shared BKTR preamble, step 1: decrypt headers, find sections, resolve titlekeys.
// Purely header-based — does NOT read the update source. Returns the crypto
// parameters plus the absolute table offsets, so the caller can pre-register the
// table ranges on a streaming source BEFORE reading them (step 2).
export async function resolveBktrMeta(baseNcaData, updateNcaData, options) {
    const { keys, baseTitlekey: providedBaseTitlekey, updateTitlekey: providedUpdateTitlekey, baseTik, updateTik, titlekeysFile } = options;

    if (!keys) throw new Error('BKTR: keys required');

    let baseHeader, updateHeader;
    try {
        baseHeader = decryptNcaHeader(baseNcaData.headerRaw, keys);
        updateHeader = decryptNcaHeader(updateNcaData.headerRaw, keys);
    } catch (e) {
        throw new Error(`BKTR: failed to decrypt NCA headers: ${e.message}`);
    }

    const baseRomfsSec = baseHeader.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS);
    const updateRomfsSec = updateHeader.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
    if (!baseRomfsSec) throw new Error('BKTR: base romfs section not found');
    if (!updateRomfsSec) throw new Error('BKTR: update BKTR romfs section not found');

    const baseRomfsSecMeta = {
        offset: baseRomfsSec.offset,
        size: baseRomfsSec.size,
        secIdx: baseHeader.sections.indexOf(baseRomfsSec),
    };
    const updateRomfsSecIdx = updateHeader.sections.indexOf(updateRomfsSec);

    // Decrypt NCA headers (raw bytes)
    const updateDecHeader = decryptNcaHeaderBytes(updateNcaData.headerRaw, keys);
    const baseDecHeader = decryptNcaHeaderBytes(baseNcaData.headerRaw, keys);

    // Update FsHeader
    const updateFsHdr = fsHeaderAt(updateDecHeader, updateRomfsSecIdx);

    // Parse IVFC header from the BKTR superblock. Level IVFC_MAX_LEVEL-1 is the
    // DATA level: the actual RomFS image (see hactool nca.c:1240).
    const ivfcBase = IVFC_LEVELS_OFFSET + FS_HDR.HASH_DATA;
    const readLevelU64 = (levelIdx, fieldOff) => readLeU64(updateFsHdr, ivfcBase + levelIdx * IVFC_LEVEL_HDR.SIZE + fieldOff);
    const dataLevelOffset = readLevelU64(IVFC_MAX_LEVEL - 1, IVFC_LEVEL_HDR.LOGICAL_OFFSET); // where RomFS data starts
    const dataLevelSize = readLevelU64(IVFC_MAX_LEVEL - 1, IVFC_LEVEL_HDR.HASH_DATA_SIZE);   // size of RomFS data

    // Parse BKTR headers
    const relocHeader = parseBktrHeader(updateFsHdr, FS_HDR.PATCH_INFO);
    const subHeader = parseBktrHeader(updateFsHdr, FS_HDR.PATCH_INFO_AESCTREX);
    if (relocHeader.magic !== BKTR_MAGIC) throw new Error(`BKTR: reloc magic 0x${relocHeader.magic.toString(16).padStart(8, '0')}`);
    if (subHeader.magic !== BKTR_MAGIC) throw new Error(`BKTR: sub magic 0x${subHeader.magic.toString(16).padStart(8, '0')}`);

    // AesCtrUpperIv: FsHeader[0x140:0x148] = {generation(u32 LE), secure_value(u32 LE)}
    const secureValue = readLeU32(updateFsHdr, FS_HDR.SECURE_VALUE);
    // section_ctr for BKTR table decryption (regular AES-CTR, reversed)
    const updateNonce = reversedSectionCtr(updateFsHdr);

    // Load titlekeys database if provided
    let titlekeysMap = null;
    if (titlekeysFile) {
        const { loadTitlekeysFile } = await import('./bktr.js');
        titlekeysMap = await loadTitlekeysFile(titlekeysFile);
    }

    // Get titlekeys (prefer provided, then titlekeys database, then tik, then key_area)
    let updateTitlekey = providedUpdateTitlekey
        || (titlekeysMap ? lookupTitlekeyFromDatabase(updateHeader.rightsId, titlekeysMap) : null)
        || (updateTik ? extractTitlekeyFromTik(updateTik, keys, updateHeader.rightsId, updateDecHeader) : null)
        || deriveTitlekeyFromKeyArea(updateDecHeader, keys);
    if (!updateTitlekey) throw new Error('BKTR: cannot get update titlekey (provide titlekeysFile or valid updateTik)');

    let baseTitlekey = providedBaseTitlekey
        || (titlekeysMap ? lookupTitlekeyFromDatabase(baseHeader.rightsId, titlekeysMap) : null)
        || (baseTik ? extractTitlekeyFromTik(baseTik, keys, baseHeader.rightsId, baseDecHeader) : null)
        || deriveTitlekeyFromKeyArea(baseDecHeader, keys);
    if (!baseTitlekey) throw new Error('BKTR: cannot get base titlekey (provide titlekeysFile or valid baseTik)');

    // Base romfs AesCtr (counter = absolute section byte / 16)
    const baseFsHdr = fsHeaderAt(baseDecHeader, baseRomfsSecMeta.secIdx);
    const baseNonce = reversedSectionCtr(baseFsHdr);

    return {
        baseRomfsSecMeta, updateRomfsSec,
        dataLevelOffset, dataLevelSize,
        relocAbsOffset: updateRomfsSec.offset + relocHeader.offset,
        subAbsOffset: updateRomfsSec.offset + subHeader.offset,
        relocHeader, subHeader,
        updateTitlekey, updateNonce, secureValue,
        baseTitlekey, baseNonce,
    };
}

// Shared BKTR preamble, step 2: decrypt + parse the relocation and subsection
// tables from a given update source (read reloc + sub ranges by absolute offset).
// For a streaming source the caller must already have registered those ranges.
export async function readBktrTables(updateSource, meta) {
    const relocTableBuf = await decryptBktrTableData(
        await updateSource.read(meta.relocAbsOffset, meta.relocHeader.size),
        meta.updateTitlekey, meta.updateNonce, meta.relocAbsOffset
    );
    const subTableBuf = await decryptBktrTableData(
        await updateSource.read(meta.subAbsOffset, meta.subHeader.size),
        meta.updateTitlekey, meta.updateNonce, meta.subAbsOffset
    );

    const relocBlock = parseRelocationBlock(relocTableBuf);
    const subBlock = parseSubsectionBlock(subTableBuf);
    if (relocBlock.entries.length === 0) throw new Error('BKTR: no relocation entries');
    if (subBlock.entries.length === 0) throw new Error('BKTR: no subsection entries');

    return { relocBlock, subBlock };
}

const SCRATCH_CHUNK = CHUNK_16MB; // 16 MB

// Shared per-run walkers used by both merge strategies. The base-copy run and
// the patch-subsection walk are byte-identical between mergeRomFS (virtual
// order) and scatterRomFS (physical order) — only the sink differs.
//   sink(chunk, virtOffset) is called with each decrypted chunk at its VIRTUAL
//   offset inside the merged RomFS.

// Copy a contiguous virtual run of a non-patch entry from the base source
// (CTR-decrypted), feeding each chunk to sink.
export async function readBaseRun(baseSource, baseRomfsSecMetaOffset, baseRomfsSecSize, baseCtr, physOffset, virtOffset, runLen, sink) {
    if (physOffset + runLen > baseRomfsSecSize) {
        throw new Error(`BKTR: base read OOB at 0x${physOffset.toString(16)}`);
    }
    let done = 0;
    while (done < runLen) {
        const n = Math.min(SCRATCH_CHUNK, runLen - done);
        const phys = baseRomfsSecMetaOffset + physOffset + done;
        const cipher = await baseSource.read(phys, n);
        baseCtr.seek(phys);
        const dec = await baseCtr.decrypt(cipher);
        await sink(dec, virtOffset + done);
        done += n;
    }
}

// Decrypt a contiguous virtual run of a patch entry from the update source,
// subsection-by-subsection, feeding each chunk to sink.
export async function readPatchRun(updReader, updateRomfsSecOffset, subBlock, titlekey, secureValue, physOffset, virtOffset, runLen, sink) {
    let writePos = 0;
    while (writePos < runLen) {
        const phys = physOffset + writePos;
        const absPhys = updateRomfsSecOffset + phys;
        const subEntry = findSubsectionEntry(subBlock.entries, phys);
        if (!subEntry) throw new Error(`BKTR: no subsection entry for physOffset 0x${phys.toString(16)}`);
        const nxt = subEntryIdx(subBlock.entries, phys) + 1 < subBlock.entries.length
            ? subBlock.entries[subEntryIdx(subBlock.entries, phys) + 1].offset : Infinity;
        const remainingInSub = nxt - phys;
        const remainingToWrite = runLen - writePos;
        const readLen = Math.min(remainingInSub, remainingToWrite, SCRATCH_CHUNK);
        const patchRaw = await updReader.read(absPhys, readLen);
        const chunk = await decryptPatchRegionData(patchRaw, titlekey, secureValue, subEntry, absPhys);
        await sink(chunk, virtOffset + writePos);
        writePos += readLen;
    }
}

// ── Lockstep (bounded window over one sequential NCZ pass) ───────────────────
// Serves monotonic runs from ONE sequential NCZ pass instead of pre-allocated
// range buffers: for the merge's base non-patch runs (bases already in
// PHYSICAL order in entry (virtual) order — no backward jump, no overlap, so
// the registerRange sort+merge is unnecessary), and for walkDataRegion's BOTH
// patch and base walks (own-BKTR packer: patch intervals asc, then base
// intervals asc — each walk a forward-only cursor over its own NCZ source).
// The consumer's reads are a forward-only cursor (offsets non-decreasing), so
// a single background decompression suffices: it appends ciphertext chunks to
// a bounded window; read(offset, n) waits until [offset, offset+n) is buffered,
// returns it, and trims the front — releasing memory and unblocking the pump
// (backpressure). Peak memory is the window + one read, not the whole run set.
// This is what keeps the own-BKTR walk from pre-allocating the ENTIRE data
// region (patch + base ≈ 6.9 GB on LOLLIPOP CHAINSAW RePOP) at once — that
// eager registration was the browser's "Array buffer allocation failed".
//
// AES-CTR stays in readBaseRun — its seek() runs at 16 MiB granularity (phys =
// baseRomfsSecMeta.offset + physOffset + done, done stepping by 16 MiB), the
// same aligned path as the registerRange fallback. That keeps this reader free
// of the failure modes the decrypt-in-stream form has: decoder chunks are NOT
// 16-aligned (the node AesCtr seek requires it) and are small (~16 KiB with
// node:zlib — per-chunk cipher setup would be ~1000× readBaseRun's). The
// window is plain contiguous ciphertext at NCA offsets, and decrypt() returns
// a fresh buffer, so the copies out of it are safe.
//
// Reads are byte-oriented, not run-oriented, so a run ending exactly at the
// stream end (or a chunk boundary) needs no special case — read() simply gets
// its bytes (or a "stream ended" error on a corrupt/truncated NCZ).
const LOCKSTEP_WINDOW_BYTES = 4 * CHUNK_16MB; // pump-ahead cap (~64 MiB)

class LockstepBaseReader {
    constructor(source, totalEnd, label = 'base') {
        this._src = source;
        this._totalEnd = totalEnd; // last run's physEnd — stop the pass after it
        this._label = label;       // error wording: 'base' (merge) / 'patch' / 'base' (walk)
        this._max = LOCKSTEP_WINDOW_BYTES;
        this._chunks = [];         // { data, start } ciphertext, NCA offset order
        this._windowBytes = 0;     // bytes currently in _chunks
        this._eof = false;         // the stream completed (or stopped cleanly)
        this._err = null;          // stream error, if any
        this._stopped = false;     // finish() — stop the pass (merge error path)
        this._done = false;        // last byte served — stop the pass (clean path)
        this._started = false;
        this._readers = null;      // pending read() resolvers
        this._pumpWaiter = null;   // pump backpressure resolver
    }

    _wake() {
        if (this._readers) {
            const ws = this._readers;
            this._readers = null;
            for (const r of ws) r();
        }
        if (this._pumpWaiter) {
            const w = this._pumpWaiter;
            this._pumpWaiter = null;
            w();
        }
    }

    // Start the background pass (idempotent; lazy — the first read() kicks it
    // off, so a merge error before the first base read leaves no stream running).
    start() {
        if (this._started) return;
        this._started = true;
        this._src.stream(async (chunk, ncaPos) => {
            // Backpressure: hold the pump while the window is over budget;
            // read() trims as it consumes and wakes us here.
            while (!this._stopped && !this._done && this._windowBytes > this._max) {
                await new Promise(r => { this._pumpWaiter = r; });
            }
            if (this._stopped || this._done) throw new Error(STOP_STREAM);
            this._chunks.push({ data: chunk, start: ncaPos });
            this._windowBytes += chunk.length;
            this._wake();
        }).then(
            () => { this._eof = true; this._wake(); },
            (e) => { this._err = e; this._wake(); }
        );
    }

    // Forward-only: offsets must be non-decreasing (the gate guarantees the base
    // runs are physically monotonic in entry order, and readBaseRun walks each
    // run in 16 MiB steps; walkDataRegion's patch/base intervals are
    // union-sorted asc — same property). Returns the CIPHERTEXT for
    // [offset, offset+length); the caller (readBaseRun / readPatchRun)
    // CTR-decrypts it at its own aligned seek.
    async read(offset, length) {
        this.start();
        const end = offset + length;
        for (;;) {
            if (this._err) throw this._err;
            if (this._stopped) throw new Error(`BKTR lockstep: ${this._label} pass stopped`);
            // Trim everything fully before `offset` (frees window memory and can
            // release the pump from backpressure).
            let trimmed = 0;
            while (this._chunks.length > 0 && this._chunks[0].start + this._chunks[0].data.length <= offset) {
                trimmed += this._chunks.shift().data.length;
            }
            if (trimmed > 0) { this._windowBytes -= trimmed; this._wake(); }
            // Is [offset, end) fully buffered yet?
            let have = 0;
            for (const c of this._chunks) {
                const cEnd = c.start + c.data.length;
                if (cEnd <= offset) continue;
                if (c.start >= end) break;
                have += Math.min(end, cEnd) - Math.max(offset, c.start);
            }
            if (have >= length) {
                const out = new Uint8Array(length);
                let o = 0;
                for (const c of this._chunks) {
                    const cEnd = c.start + c.data.length;
                    if (cEnd <= offset) continue;
                    if (c.start >= end) break;
                    const a = Math.max(offset, c.start) - c.start;
                    const b = Math.min(end, cEnd) - c.start;
                    out.set(c.data.subarray(a, b), o);
                    o += b - a;
                }
                // Last run fully served — no more bytes needed from this
                // source; let the pass stop (mirrors the fallback pump's
                // STOP_PUMP).
                if (end >= this._totalEnd) { this._done = true; this._wake(); }
                return out;
            }
            if (this._eof) {
                throw new Error(`BKTR lockstep: ${this._label} stream ended before read [0x${offset.toString(16)}, 0x${end.toString(16)})`);
            }
            await new Promise(r => { (this._readers || (this._readers = [])).push(r); });
        }
    }

    // Stop the background pass (idempotent — call from the merge's finally so a
    // merge error halts the in-flight stream instead of decompressing on).
    finish() {
        if (this._stopped) return;
        this._stopped = true;
        this._wake();
    }
}

// Gate: may the base be fed via lockstep? Requires a sequential NCZ source and
// base runs already in physical order in entry order (no backward jump, no
// overlap) — then the merge's base reads are a forward-only cursor and ONE
// stream pass suffices. Returns the reader (or null — the caller takes the
// registerRange fallback).
function startLockstepIfMonotonic(baseSource, baseRuns, enabled) {
    if (!enabled) return null;
    if (!(baseSource instanceof NczStreamSource)) return null;
    if (baseRuns.length === 0) return null;
    const monotonic = baseRuns.every((r, i) => i === 0 || r.physStart >= baseRuns[i - 1].physEnd);
    if (!monotonic) return null;
    return new LockstepBaseReader(baseSource, baseRuns[baseRuns.length - 1].physEnd);
}

// Generalized lockstep reader for walkDataRegion (fs/bktr-pack.js): wrap a
// sequential NCZ source whose reads are known forward-only, WITHOUT
// registering any ranges (registration pre-allocates one Uint8Array per range
// — the whole run set held at once, which OOMs the browser on multi-GB data
// regions). Returns null for non-NCZ sources — the caller then keeps the
// registerBaseRanges / registerRange path (a no-op for random-access
// sources). totalEnd = the last wanted byte + 1 (the pass stops there);
// label only words the error messages ('patch' / 'base').
export function createLockstepReader(source, totalEnd, label) {
    if (!(source instanceof NczStreamSource)) return null;
    return new LockstepBaseReader(source, totalEnd, label);
}

// ── Virtual-order merge (default) ─────────────────────────────────────────────
export async function mergeRomFS(baseNcaData, updateNcaData, options = {}) {
    const { keys, onChunk, onProgress } = options;
    const _log = typeof options.log === 'function' ? options.log : () => {};

    const meta = await resolveBktrMeta(baseNcaData, updateNcaData, options);
    const { relocBlock, subBlock } = await readBktrTables(updateNcaData.source, meta);
    const { baseRomfsSecMeta, dataLevelOffset, dataLevelSize,
            updateRomfsSec, updateTitlekey, updateNonce, secureValue, baseTitlekey, baseNonce } = meta;
    const totalSize = relocBlock.totalSize;

    // The base non-patch runs in ENTRY (virtual) order — what the merge reads.
    // For a MONOTONIC base these are also in physical order (no backward jump,
    // no overlap), which a single lockstep NCZ pass can feed directly with no
    // range pre-allocation. For a non-monotonic base (e.g. LN2) they must be
    // sort+merged and pre-registered instead (registerBaseRanges, see its
    // comment): the merge reads them in virtual order, a read is a sub-range
    // and maps to its range by physical offset.
    const baseRuns = [];
    for (let i = 0; i < relocBlock.entries.length; i++) {
        const e = relocBlock.entries[i];
        if (e.isPatch) continue;
        const nextVirt = i + 1 < relocBlock.entries.length
            ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
        baseRuns.push({
            virtStart: e.virtOffset,
            physStart: baseRomfsSecMeta.offset + e.physOffset,
            physEnd: baseRomfsSecMeta.offset + e.physOffset + (nextVirt - e.virtOffset),
        });
    }

    const baseCtr = new AesCtr(baseTitlekey, baseNonce);

    // Lockstep gate (see startLockstepIfMonotonic): NCZ source + monotonic base
    // → base runs are served by ONE bounded sequential stream (no range
    // pre-allocation). Otherwise the registerRange + read path. Either way the
    // merge reads the base through readBaseRun (aligned CTR at 16 MiB steps).
    let lockstep = null;
    if (options.lockstep !== false) {
        lockstep = startLockstepIfMonotonic(baseNcaData.source, baseRuns, true);
        if (lockstep) {
            const baseBytes = baseRuns.reduce((s, r) => s + (r.physEnd - r.physStart), 0);
            _log('info', `Base lockstep: ${baseRuns.length} run(s), ${baseBytes.toLocaleString()} bytes — one stream, no range pre-allocation`);
        }
    }
    const baseReader = lockstep || baseNcaData.source;
    if (!lockstep) registerBaseRanges(baseNcaData.source, baseRuns.map(r => ({ start: r.physStart, end: r.physEnd })));

    const patchSource = updateNcaData.source;

    // Build merged RomFS (streaming or buffered) — see comments in the loop.
    const streaming = typeof onChunk === 'function';
    const merged = streaming ? null : new Uint8Array(totalSize);
    const dataStart = dataLevelOffset;
    const dataEnd = dataLevelOffset + dataLevelSize;
    let pos = 0;
    let entryIdx = 0;

    const emitChunk = async (chunk, virtOffset) => {
        if (streaming) {
            const a = Math.max(virtOffset, dataStart);
            const b = Math.min(virtOffset + chunk.length, dataEnd);
            if (b > a) {
                await onChunk(chunk.subarray(a - virtOffset, b - virtOffset), a - dataStart);
            }
        } else {
            merged.set(chunk, virtOffset);
        }
        onProgress?.(virtOffset + chunk.length, totalSize);
        await yieldToEventLoop();
    };

    try {
        while (pos < totalSize && entryIdx < relocBlock.entries.length) {
            const entry = relocBlock.entries[entryIdx];
            const nextVirt = entryIdx + 1 < relocBlock.entries.length
                ? relocBlock.entries[entryIdx + 1].virtOffset
                : totalSize;
            const chunkEnd = Math.min(nextVirt, totalSize);
            const readSize = chunkEnd - pos;

            if (entry.isPatch) {
                // Decrypt patch from update NCA using AesCtrEx (run at pos).
                await readPatchRun(patchSource, updateRomfsSec.offset, subBlock,
                    updateTitlekey, secureValue,
                    entry.physOffset + (pos - entry.virtOffset), pos, readSize, emitChunk);
            } else {
                // Copy from base romfs (run at pos) — via the lockstep reader
                // (monotonic NCZ base) or the range-registered source.
                await readBaseRun(baseReader, baseRomfsSecMeta.offset, baseRomfsSecMeta.size, baseCtr,
                    entry.physOffset + (pos - entry.virtOffset), pos, readSize, emitChunk);
            }

            pos = chunkEnd;
            entryIdx++;
        }
    } finally {
        if (lockstep) lockstep.finish();
    }

    return {
        mergedData: streaming ? null : merged.subarray(dataLevelOffset, dataLevelOffset + dataLevelSize),
        dataOffset: dataLevelOffset,
        dataLevelSize,
        relocEntries: relocBlock.entries.length,
        subsectionEntries: subBlock.entries.length,
    };
}

// ── Physical-order scatter merge ─────────────────────────────────────────────
// The virtual-order merge (mergeRomFS) reads update patch regions in VIRTUAL
// order, which — for an update .nsz with non-monotonic patch physical offsets —
// forces the update to be buffered in full (SparseNcaView, ~668 MB). The scatter
// merge instead walks each source in PHYSICAL order and SCATTER-writes the
// decrypted merged RomFS straight to its virtual offset in the (seekable) output,
// so the update is decompressed once per use with ~0 extra memory.
//
// Cost: one extra full decompression of the update beyond the buffered path —
// U1 captures the BKTR tables (reloc + sub, ~64 KB), U2 re-streams the patch
// data in physical order. The merged RomFS is NOT consumed in virtual order, so
// the IVFC hash + contentId come from an ORDERED re-read of the written NCA
// (see packProgramNcaStream's scatter mode). Only valid for seekable outputs.
//
//   baseInput  : { headerRaw, source } for the base NCA.
//   updateCtx  : { headerRaw, reader, parsed, streamable:true } for an NCZ update,
//                or { headerRaw, source, streamable:false } for a raw container.
//                The table ranges (U1) are served via a registered stream source;
//                patch ranges (U2) via a second one.
//   writeFn    : async (offInRomfsData, chunk) -> scatter write. offInRomfsData is
//                the offset within the RomFS DATA region.
//   onProgress : (virtPosition, totalSize) optional.
export async function scatterRomFS({ baseInput, updateCtx, options, writeFn, log, onProgress }) {
    const _log = typeof log === 'function' ? log : () => {};
    const keys = options?.keys;

    // NCZ updates stream both their tables (U1) and patch data (U2) from a fresh
    // sequential source registered with only the needed ranges (in strictly
    // increasing order); raw containers just reuse updateCtx.source. One
    // definition instead of two streamable-dispatch sites.
    const makeUpdateSource = (ranges) => {
        if (!updateCtx.streamable) return updateCtx.source;
        const src = new NczStreamSource(updateCtx.reader, updateCtx.parsed, _log);
        for (const r of ranges) src.registerRange(r.off, r.len);
        return src;
    };

    // U1: capture the BKTR tables. For an NCZ update, a fresh stream source
    // registered with just the reloc + sub ranges (in strictly increasing order).
    const meta = await resolveBktrMeta(baseInput, updateCtx, options);
    const tableSource = makeUpdateSource([
        { off: meta.relocAbsOffset, len: meta.relocHeader.size },
        { off: meta.subAbsOffset, len: meta.subHeader.size },
    ].sort((a, b) => a.off - b.off));
    const { relocBlock, subBlock } = await readBktrTables(tableSource, meta);
    const { dataLevelOffset, dataLevelSize, updateRomfsSec, baseRomfsSecMeta, updateTitlekey, updateNonce, secureValue, baseTitlekey, baseNonce } = meta;
    const totalSize = relocBlock.totalSize;
    const dataStart = dataLevelOffset;
    const dataEnd = dataLevelOffset + dataLevelSize;
    const entries = relocBlock.entries.map((e, i) => ({
        ...e,
        nextVirt: i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : totalSize,
    }));

    // Progress reports BYTES WRITTEN (monotonic), not virtual offsets: Pass U walks
    // patch entries in physical order, so virtual positions jump up and down and
    // would make any progress bar rewind.
    let reportBytes = 0;
    const scatterWrite = async (chunk, virtOffset) => {
        const a = Math.max(virtOffset, dataStart);
        const b = Math.min(virtOffset + chunk.length, dataEnd);
        if (b > a) {
            await writeFn(a - dataStart, chunk.subarray(a - virtOffset, b - virtOffset));
            reportBytes += b - a;
        }
        onProgress?.(Math.min(reportBytes, totalSize), totalSize);
        await yieldToEventLoop();
    };

    // ── Pass B: base regions ─────────────────────────────────────────────────
    // Pre-register the base non-patch ranges so an NCZ base streams in ONE pass.
    // The reads below stay in virtual (entry) order — a read is a sub-range and
    // maps to its range by physical offset, independent of registration order.
    // registerBaseRanges sorts by physical offset and merges overlaps (see its
    // comment) because the base physical order need not match the reloc (virtual)
    // order. registerRange is a no-op on non-stream sources (fs/range-source.js).
    const baseSource = baseInput.source;
    const baseRuns = [];
    for (const e of entries) {
        if (e.isPatch) continue;
        baseRuns.push({
            virtStart: e.virtOffset,
            physStart: baseRomfsSecMeta.offset + e.physOffset,
            physEnd: baseRomfsSecMeta.offset + e.physOffset + (e.nextVirt - e.virtOffset),
        });
    }

    const baseCtr = new AesCtr(baseTitlekey, baseNonce);

    // Lockstep gate (same as mergeRomFS): NCZ source + monotonic base → Pass B
    // is fed by ONE bounded sequential stream instead of pre-allocated range
    // buffers. Either way Pass B reads through readBaseRun.
    let lockstep = null;
    if (options?.lockstep !== false) {
        lockstep = startLockstepIfMonotonic(baseSource, baseRuns, true);
        if (lockstep) {
            const baseBytes = baseRuns.reduce((s, r) => s + (r.physEnd - r.physStart), 0);
            _log('info', `Base lockstep (scatter): ${baseRuns.length} run(s), ${baseBytes.toLocaleString()} bytes — one stream, no range pre-allocation`);
        }
    }
    const baseReader = lockstep || baseSource;
    if (!lockstep) registerBaseRanges(baseSource, baseRuns.map(r => ({ start: r.physStart, end: r.physEnd })));

    try {
        for (const e of entries) {
            if (e.isPatch) continue;
            // Base run via the lockstep reader (monotonic NCZ base) or the
            // range-registered source — readBaseRun does the aligned CTR.
            await readBaseRun(baseReader, baseRomfsSecMeta.offset, baseRomfsSecMeta.size, baseCtr,
                e.physOffset, e.virtOffset, e.nextVirt - e.virtOffset, scatterWrite);
        }

        // ── Pass U: patch regions, physical order ──────────────────────────
        const patchEntries = entries
            .filter(e => e.isPatch)
            .map(e => ({ e, runLen: e.nextVirt - e.virtOffset, abs: updateRomfsSec.offset + e.physOffset }))
            .sort((a, b) => a.abs - b.abs);

        const updReader = makeUpdateSource(
            patchEntries.map(r => ({ off: r.abs, len: r.runLen })));

        for (const r of patchEntries) {
            await readPatchRun(updReader, updateRomfsSec.offset, subBlock,
                updateTitlekey, secureValue,
                r.e.physOffset, r.e.virtOffset, r.runLen, scatterWrite);
        }
    } finally {
        if (lockstep) lockstep.finish();
    }

    return { dataLevelOffset, dataLevelSize, relocEntries: entries.length, subsectionEntries: subBlock.entries.length };
}
