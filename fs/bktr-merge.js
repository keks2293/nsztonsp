import { AesCtr } from '../crypto/aes-ops.mjs';
import { decryptNcaHeader } from './nca.js';
import { BufferRangeSource, NczStreamSource } from './range-source.js';
import { readLeU64, readLeU32 } from './bytes.js';
import { yieldToEventLoop } from './event-loop.js';
import { decryptNcaHeaderBytes, fsHeaderAt, reversedSectionCtr, extractTitlekeyFromTik, deriveTitlekeyFromKeyArea, IVFC_LEVEL_HDR, IVFC_LEVELS_OFFSET, IVFC_MAX_LEVEL, FS_HDR } from './nca-utils.js';
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

// Accept either a full NCA buffer (Uint8Array) or an NcaInput:
// { headerRaw: Uint8Array(0xC00), source: RangeSource } where
// source.read(offset, length) serves NCA ciphertext by absolute offset.
function toNcaInput(nca) {
    if (nca && typeof nca.subarray === 'function' && !nca.source) {
        return { headerRaw: nca.subarray(0, 0xC00), source: new BufferRangeSource(nca) };
    }
    return nca;
}

const BKTR_MAGIC = 0x52544B42; // "BKTR"

// Shared BKTR preamble, step 1: decrypt headers, find sections, resolve titlekeys.
// Purely header-based — does NOT read the update source. Returns the crypto
// parameters plus the absolute table offsets, so the caller can pre-register the
// table ranges on a streaming source BEFORE reading them (step 2).
async function resolveBktrMeta(baseNcaData, updateNcaData, options) {
    const { keys, baseTitlekey: providedBaseTitlekey, updateTitlekey: providedUpdateTitlekey, baseTik, updateTik, titlekeysFile } = options;

    if (!keys) throw new Error('BKTR: keys required');

    baseNcaData = toNcaInput(baseNcaData);
    updateNcaData = toNcaInput(updateNcaData);

    const baseHeader = decryptNcaHeader(baseNcaData.headerRaw, keys);
    const updateHeader = decryptNcaHeader(updateNcaData.headerRaw, keys);
    if (!baseHeader || !updateHeader) throw new Error('BKTR: failed to decrypt NCA headers');

    const baseRomfsSec = baseHeader.sections.find(s => s.fsType === 3);
    const updateRomfsSec = updateHeader.sections.find(s => s.fsType === 3 && s.cryptoType === 4);
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
        || (updateTik ? extractTitlekeyFromTik(updateTik, keys, updateHeader.rightsId) : null)
        || deriveTitlekeyFromKeyArea(updateDecHeader, keys);
    if (!updateTitlekey) throw new Error('BKTR: cannot get update titlekey (provide titlekeysFile or valid updateTik)');

    let baseTitlekey = providedBaseTitlekey
        || (titlekeysMap ? lookupTitlekeyFromDatabase(baseHeader.rightsId, titlekeysMap) : null)
        || (baseTik ? extractTitlekeyFromTik(baseTik, keys, baseHeader.rightsId) : null)
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
async function readBktrTables(updateSource, meta) {
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

const SCRATCH_CHUNK = 0x1000000; // 16 MB

// ── Virtual-order merge (default) ─────────────────────────────────────────────
export async function mergeRomFS(baseNcaData, updateNcaData, options = {}) {
    const { keys, onChunk, onProgress } = options;
    baseNcaData = toNcaInput(baseNcaData);
    updateNcaData = toNcaInput(updateNcaData);

    const meta = await resolveBktrMeta(baseNcaData, updateNcaData, options);
    const { baseRomfsSecMeta, dataLevelOffset, dataLevelSize, relocBlock, subBlock,
            updateRomfsSec, updateTitlekey, updateNonce, secureValue, baseTitlekey, baseNonce }
        = { ...meta, ...await readBktrTables(updateNcaData.source, meta) };
    const totalSize = relocBlock.totalSize;

    // Pre-register the base romfs ranges (in strictly increasing order) so an
    // NCZ stream source can serve them in ONE sequential decompression pass
    // without buffering the whole base romfs section. File/buffer sources
    // ignore registration.
    for (let i = 0; i < relocBlock.entries.length; i++) {
        const e = relocBlock.entries[i];
        if (e.isPatch) continue;
        const nextVirt = i + 1 < relocBlock.entries.length
            ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
        baseNcaData.source.registerRange(baseRomfsSecMeta.offset + e.physOffset, nextVirt - e.virtOffset);
    }

    const baseCtr = new AesCtr(baseTitlekey, baseNonce);

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

    while (pos < totalSize && entryIdx < relocBlock.entries.length) {
        const entry = relocBlock.entries[entryIdx];
        const nextVirt = entryIdx + 1 < relocBlock.entries.length
            ? relocBlock.entries[entryIdx + 1].virtOffset
            : totalSize;
        const chunkEnd = Math.min(nextVirt, totalSize);
        const readSize = chunkEnd - pos;

        if (entry.isPatch) {
            // Decrypt patch from update NCA using AesCtrEx
            let writePos = pos;
            let currentPhys = entry.physOffset + (pos - entry.virtOffset);

            while (writePos < chunkEnd) {
                const subEntry = findSubsectionEntry(subBlock.entries, currentPhys);
                if (!subEntry) {
                    throw new Error(`BKTR: no subsection entry for physOffset 0x${currentPhys.toString(16)}`);
                }
                const nextSubOff = subEntryIdx(subBlock.entries, currentPhys) + 1 < subBlock.entries.length
                    ? subBlock.entries[subEntryIdx(subBlock.entries, currentPhys) + 1].offset
                    : Infinity;
                const remainingInSub = nextSubOff - currentPhys;
                const remainingToWrite = chunkEnd - writePos;
                const readLen = Math.min(remainingInSub, remainingToWrite, SCRATCH_CHUNK);

                const fileOffset = updateRomfsSec.offset + currentPhys;
                const patchRaw = await updateNcaData.source.read(fileOffset, readLen);
                const chunk = await decryptPatchRegionData(
                    patchRaw, updateTitlekey, secureValue, subEntry, fileOffset
                );
                await emitChunk(chunk, writePos);

                writePos += readLen;
                currentPhys += readLen;
            }
        } else {
            // Copy from base romfs
            const baseOffset = entry.physOffset + (pos - entry.virtOffset);
            if (baseOffset + readSize > baseRomfsSecMeta.size) {
                throw new Error(`BKTR: base read OOB at 0x${baseOffset.toString(16)}`);
            }
            let done = 0;
            while (done < readSize) {
                const n = Math.min(SCRATCH_CHUNK, readSize - done);
                const cipher = await baseNcaData.source.read(baseRomfsSecMeta.offset + baseOffset + done, n);
                baseCtr.seek(baseRomfsSecMeta.offset + baseOffset + done);
                const dec = await baseCtr.decrypt(cipher);
                await emitChunk(dec, pos + done);
                done += n;
            }
        }

        pos = chunkEnd;
        entryIdx++;
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

    // U1: capture the BKTR tables. For an NCZ update, a fresh stream source
    // registered with just the reloc + sub ranges (in strictly increasing order).
    const meta = await resolveBktrMeta(baseInput, updateCtx, options);
    let tableSource;
    if (updateCtx.streamable) {
        tableSource = new NczStreamSource(updateCtx.reader, updateCtx.parsed, _log);
        const tableRanges = [
            { off: meta.relocAbsOffset, len: meta.relocHeader.size },
            { off: meta.subAbsOffset, len: meta.subHeader.size },
        ].sort((a, b) => a.off - b.off);
        for (const r of tableRanges) tableSource.registerRange(r.off, r.len);
    } else {
        tableSource = updateCtx.source;
    }
    const { relocBlock, subBlock } = await readBktrTables(tableSource, meta);
    const { dataLevelOffset, dataLevelSize, updateRomfsSec, baseRomfsSecMeta, updateTitlekey, updateNonce, secureValue, baseTitlekey, baseNonce } = meta;
    const totalSize = relocBlock.totalSize;
    const dataStart = dataLevelOffset;
    const dataEnd = dataLevelOffset + dataLevelSize;
    const entries = relocBlock.entries.map((e, i) => ({
        ...e,
        nextVirt: i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : totalSize,
    }));

    const scatterWrite = async (chunk, virtOffset) => {
        const a = Math.max(virtOffset, dataStart);
        const b = Math.min(virtOffset + chunk.length, dataEnd);
        if (b > a) {
            await writeFn(a - dataStart, chunk.subarray(a - virtOffset, b - virtOffset));
        }
        onProgress?.(virtOffset + chunk.length, totalSize);
        await yieldToEventLoop();
    };

    // ── Pass B: base regions (virtual order == physical order for base) ─────
    // Pre-register the base non-patch ranges (strictly increasing physical
    // offsets — base sectors are sequential) so an NCZ base streams in ONE pass.
    let baseSource;
    if (baseInput.source instanceof NczStreamSource) {
        baseSource = baseInput.source;
        for (const e of entries) {
            if (e.isPatch) continue;
            baseSource.registerRange(baseRomfsSecMeta.offset + e.physOffset, e.nextVirt - e.virtOffset);
        }
    } else {
        baseSource = baseInput.source;
    }

    const baseCtr = new AesCtr(baseTitlekey, baseNonce);
    for (const e of entries) {
        if (e.isPatch) continue;
        const runLen = e.nextVirt - e.virtOffset;
        let done = 0;
        while (done < runLen) {
            const n = Math.min(SCRATCH_CHUNK, runLen - done);
            const phys = baseRomfsSecMeta.offset + (e.physOffset + done);
            const cipher = await baseSource.read(phys, n);
            baseCtr.seek(phys);
            const dec = await baseCtr.decrypt(cipher);
            await scatterWrite(dec, e.virtOffset + done);
            done += n;
        }
    }

    // ── Pass U: patch regions, physical order ──────────────────────────────
    const patchEntries = entries
        .filter(e => e.isPatch)
        .map(e => ({ e, runLen: e.nextVirt - e.virtOffset, abs: updateRomfsSec.offset + e.physOffset }))
        .sort((a, b) => a.abs - b.abs);

    let updReader;
    if (updateCtx.streamable) {
        updReader = new NczStreamSource(updateCtx.reader, updateCtx.parsed, _log);
        for (const r of patchEntries) {
            updReader.registerRange(r.abs, r.runLen);
        }
    } else {
        updReader = updateCtx.source;
    }

    for (const r of patchEntries) {
        const e = r.e;
        let writePos = 0;
        while (writePos < r.runLen) {
            const phys = e.physOffset + writePos;
            const absPhys = updateRomfsSec.offset + phys;
            const subEntry = findSubsectionEntry(subBlock.entries, phys);
            if (!subEntry) throw new Error(`BKTR scatter: no subsection entry for physOffset 0x${phys.toString(16)}`);
            const nxt = subEntryIdx(subBlock.entries, phys) + 1 < subBlock.entries.length
                ? subBlock.entries[subEntryIdx(subBlock.entries, phys) + 1].offset : Infinity;
            const remainingInSub = nxt - phys;
            const remainingToWrite = r.runLen - writePos;
            const readLen = Math.min(remainingInSub, remainingToWrite, SCRATCH_CHUNK);
            const patchRaw = await updReader.read(absPhys, readLen);
            const chunk = await decryptPatchRegionData(patchRaw, updateTitlekey, secureValue, subEntry, absPhys);
            await scatterWrite(chunk, e.virtOffset + writePos);
            writePos += readLen;
        }
    }

    return { dataLevelOffset, dataLevelSize, relocEntries: entries.length, subsectionEntries: subBlock.entries.length };
}
