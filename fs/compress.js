// NSP→NSZ / XCI→XCZ compression — the inverse of the decompress path in
// nsz-decompress.js / xcz-decompress.js. Mirrors the Python `nsz` compressors
// (nicoboss/nsz BlockCompressor + SolidCompressor): eligible NCAs are
// compressed to NCZ (NCZSECTN table + either NCZBLOCK blocks — zstd level 18,
// 1 MiB blocks, raw-when-incompressible — or ONE solid zstd frame) and the
// container is rebuilt (PFS0 for NSZ; XCI/HFS0 for XCZ). Options (level,
// blockSizeExponent, ldm, mode) match python: -l, -s, -L, -S/-B — see
// normalizeCompressOptions; ldm and solid are CLI-only (node:zlib).
//
// ── Crypto model (verified byte-for-byte against real base.nsz + update.nsz
//    produced by Python nsz) ────────────────────────────────────────────────
// The NCZ section table stores, per section: offset, size, cryptoType, 8B pad,
// key (16B), counter (16B). The cryptoType is the RAW NCA FsHeader crypto byte
// (FsHeader+0x04): 1=NONE (plaintext), 3=CTR, 4=BKTR (python Type.Crypto
// numbering — NOT the nca-utils SECTION_CRYPTO_TYPE enum). The 16-byte counter
// is [head 8B][00*8] — the low 8 bytes are always zero because the
// decompressor (ncz.js) fills them via AesCtr.seek(section.offset) (=
// offset>>4). The head is:
//   * normal CTR section : reversedSectionCtr (FsHeader[0x140:0x148] byte-
//     reversed — nca.js already hands this out as section.cryptoCounter)
//   * BKTR subsection i  : [secureValue 4B BE][subEntry.ctrVal 4B BE]
//   * BKTR tail section  : reversedSectionCtr (the tables region after the data)
//
// The compressed payload is the PLAINTEXT of the continuous NCA bytes
// [0x4000, ncaSize): CTR/BKTR ranges are decrypted on the fly (the compressor
// compresses plaintext; the decompressor re-encrypts — CTR encrypt==decrypt).
// The [0x4000, firstSection) gap is plaintext; the decompressor inserts a
// FakeSection for it, so the compressor writes only the real sections.
//
// ── Re-compression (.nsz/.xcz as compress input) ────────────────────────────
// Python nsz does NOT re-compress (its compressors only accept .nsp/.xci; the
// CLI skips isCompressedGame inputs) — this is our extension. .ncz members are
// re-compressed with the SAME skip rules as .nca: their original NCA bytes are
// presented by an NczNcaReader (fs/ncz.js) — raw 0x4000 header verbatim +
// payload zstd-decompressed + re-encrypted per the member's own NCZSECTN
// table — and run through the identical per-NCA pipeline (analyzeNca →
// compressNcaToWriter). The member name stays .ncz; the CONTAINER file name
// is <stem>_blockcomp<ext> / <stem>_solidcomp<ext> (compressedOutputName —
// the same name EVERY compression output gets, so the output never collides
// with the input or a Python-nsz <stem>.nsz in the same directory). The
// output layout (level/block size/mode) comes from the CLI options, so
// re-compression can change level, block size and mode.
//
// ── Skip rules (match python + keep the round-trip lossless) ───────────────
//   - only PROGRAM(0) / PUBLIC_DATA(5) NCAs, size > 0x4000
//   - "packed": the fs sections (fsType != NONE) are contiguous from the first
//     section offset to exactly ncaSize (python isNcaPacked)
//   - a titlekey is required when any section is CTR/BKTR
//   - no XTS (raw byte 2) sections — the decompressor cannot re-encrypt XTS
// Everything else (non-.nca members, small NCAs, META/CONTROL/MANUAL/DATA,
// undecryptable headers, non-packed NCAs) is copied verbatim.

import { compressBlock, createSolidCompressor } from '../crypto/zstd.js';
import { isNode } from '../crypto/platform.js';
import { UNCOMPRESSABLE_HEADER_SIZE, NCZ_CRYPTO_TYPE, NCZ_SECTN_ENTRY, NczNcaReader } from './ncz.js';
import { readLeU64, writeU32LE, writeU64LE } from './bytes.js';
import { NCAHeader, decryptNcaSection } from './nca.js';
import {
    NCA_HEADER_SIZE, NCA_HDR, NCA_CONTENT_TYPE,
    decryptNcaHeaderBytes, deriveTitlekeyFromKeyArea, extractTitlekeyFromTik,
} from './nca-utils.js';
import { PFS0, PFS0Writer, pfs0HeaderSize } from './pfs0.js';
import { HFS0Writer } from './hfs0.js';
import { XCIReader, XCI_LAYOUT, align0x200 } from './xci.js';
import { buildAdapter, collectBlob, copyRange } from './adapter.js';
import { parseSubsectionBlock, decryptBktrTableData } from './bktr.js';
import { collectTicketMaps } from './ticket.js';

const DEFAULT_BLOCK_SIZE_EXPONENT = 20;         // 1 MiB blocks (python -s default)
const DEFAULT_LEVEL = 18;                       // python -l default

// ── Compression options (python nsz parity) ──────────────────────────────────
//   level             zstd level 1-22 (python -l, default 18)
//   blockSizeExponent NCZBLOCK block size 2^exp, exp 14-32 (python -s, default
//                     20 = 1 MiB) — block mode only
//   ldm               zstd long-distance matching (python -L: libzstd defaults
//                     for the level + LDM enabled) — CLI only (node:zlib
//                     parameters; the browser wasm has no compressor params)
//   mode              'block' (NCZBLOCK, the default here; python -B) or
//                     'solid' (one zstd frame over the whole payload; python
//                     -S; CLI only — not wired into the browser path yet; the
//                     browser wasm does have a streaming compressor, the CLI
//                     just uses node:zlib for now). NOTE: python nsz defaults
//                     to SOLID for NSZ
//                     and BLOCK for XCZ; here BLOCK is the default for both —
//                     the NCZSECTN table is identical in both modes, only the
//                     payload layout differs.
export function normalizeCompressOptions(opts = {}) {
    const level = opts.level ?? DEFAULT_LEVEL;
    const blockSizeExponent = opts.blockSizeExponent ?? DEFAULT_BLOCK_SIZE_EXPONENT;
    const ldm = !!opts.ldm;
    const mode = opts.mode ?? 'block';
    if (!Number.isInteger(level) || level < 1 || level > 22) {
        throw new Error(`Invalid zstd level ${level} (must be an integer from 1 to 22)`);
    }
    if (!Number.isInteger(blockSizeExponent) || blockSizeExponent < 14 || blockSizeExponent > 32) {
        throw new Error(`Invalid block size exponent ${blockSizeExponent} (must be an integer from 14 to 32)`);
    }
    if (mode !== 'block' && mode !== 'solid') {
        throw new Error(`Invalid compression mode '${mode}' (must be 'block' or 'solid')`);
    }
    if (!isNode && (ldm || mode === 'solid')) {
        throw new Error(`${ldm ? 'Long mode (LDM)' : 'Solid mode'} is CLI-only: ${ldm ? 'the browser zstd wasm exposes no compressor parameters' : 'solid mode is not wired into the browser path yet'}`);
    }
    return { level, blockSizeExponent, ldm, mode };
}

// Output file name for EVERY compression: <stem>_blockcomp<outExt> /
// <stem>_solidcomp<outExt>. The derived-name convention of this project
// (_merged / _updated), extended with the compression mode, so (a) a block
// and a solid compression of the same input can coexist, (b) the output never
// collides with the input or with a Python-nsz-produced <stem>.nsz in the
// same directory, and (c) the file name states its layout. outExt defaults
// to the input's own extension (re-compression: .nsz → .nsz).
// Idempotent PER MODE on re-compression — a previous compression output
// (.nsz/.xcz input) re-compressed in the same mode keeps its name (no
// _blockcomp_blockcomp growth); switching modes yields the other name.
// ldm/level/block size are payload parameters, not layout, so they don't
// appear in the name.
export function compressedOutputName(name, mode = 'block', outExt = '') {
    const m = name.match(/^(.*?)(\.[^.]+)$/);
    if (!m) return name;
    let stem = m[1];
    const inExt = m[2].toLowerCase();
    const lower = stem.toLowerCase();
    // The strip (idempotency) applies only when the input is itself a
    // compression output (.nsz/.xcz) — a coincidental _blockcomp stem on a
    // fresh .nsp/.xci input is part of the name and is kept.
    if ((inExt === '.nsz' || inExt === '.xcz') && (lower.endsWith('_blockcomp') || lower.endsWith('_solidcomp'))) {
        stem = stem.slice(0, -10);
    }
    return stem + (mode === 'solid' ? '_solidcomp' : '_blockcomp') + (outExt || m[2]);
}

// Raw NCA FsHeader crypto byte values (python nsz Type.Crypto numbering — this is
// the ACTUAL on-disk byte, verified empirically; it is NOT the nca-utils
// SECTION_CRYPTO_TYPE enum). 0=ERR, 1=NONE (plaintext), 2=XTS, 3=CTR, 4=BKTR.
// The NCZ section-table crypto type is the SAME byte (fs/ncz.js
// NCZ_CRYPTO_TYPE), imported above.
const RAW_ERR = 0, RAW_XTS = 2, RAW_CTR = 3, RAW_BKTR = 4;

// ── Single-NCA analysis ─────────────────────────────────────────────────────
// Decide whether an NCA (given its reader + size + keys) can be compressed, and
// if so, resolve the titlekey + section geometry. Pure analysis — no payload I/O.
// ncaReader = { read(offset, size) } scoped to the NCA's own bytes (offset 0 =
// NCA start). Returns { compressible, reason?, titlekey?, needsTitlekey?,
// rightsId?, titleId?, sections?, contentType?, decHeader? }.
// Sections come from NCAHeader.parse (fs/nca.js): fsType != NONE, media-table
// geometry, raw crypto byte, reversed 8B section counter.
//
// Titlekey (hactool nca.c nca_process + python NcaHeader, verified): the header
// key area is only a valid titlekey source for NON-rights-managed NCAs. Rights-
// managed (retail) NCAs carry a titlekek-wrapped/derived key in the key area —
// the real titlekey comes from the title's ticket (.tik) or a titlekeys
// database. So for rights-managed NCAs this returns needsTitlekey=true with
// titlekey=null; the caller resolves it from the container's .tik members.
export async function analyzeNca(ncaReader, ncaSize, keys, titlekeyHint = null) {
    if (!keys || !keys.header_key) return { compressible: false, headerOk: false, reason: 'no keys loaded' };
    // The header is parsed for EVERY NCA (python nsz opens every NCA header on
    // container open): the content type drives container-level filters (e.g.
    // dropping delta fragments) independent of compressibility.
    const headerRaw = await ncaReader.read(0, Math.min(ncaSize, NCA_HEADER_SIZE));
    let decHeader, header;
    try {
        decHeader = decryptNcaHeaderBytes(headerRaw, keys);
        header = NCAHeader.parse(decHeader, keys);
    } catch (e) {
        return { compressible: false, headerOk: false, reason: `undecryptable header (${e.message})` };
    }
    if (!header) return { compressible: false, headerOk: false, reason: 'not an NCA (bad magic)' };

    const base = {
        headerOk: true,
        contentType: header.contentType,
        rightsId: header.rightsId,
        titleId: header.titleId,
        decHeader,
        ncaSize,
    };

    if (ncaSize <= UNCOMPRESSABLE_HEADER_SIZE) return { ...base, compressible: false, reason: 'NCA too small' };

    const contentType = header.contentType;
    if (contentType !== NCA_CONTENT_TYPE.PROGRAM && contentType !== NCA_CONTENT_TYPE.PUBLIC_DATA) {
        return { ...base, compressible: false, reason: `content type ${contentType} (only PROGRAM/PUBLIC_DATA compress)` };
    }

    const sections = header.sections;
    if (sections.length === 0) return { ...base, compressible: false, reason: 'no sections' };

    // isNcaPacked: contiguous from the first section to exactly ncaSize.
    sections.sort((a, b) => a.offset - b.offset);
    let next = sections[0].offset;
    for (const s of sections) {
        if (s.offset !== next) return { ...base, compressible: false, reason: 'not packed (gap between sections)' };
        next = s.offset + s.size;
    }
    if (next !== ncaSize) return { ...base, compressible: false, reason: 'not packed (sections do not end at ncaSize)' };
    if (sections[0].offset < UNCOMPRESSABLE_HEADER_SIZE) return { ...base, compressible: false, reason: 'section starts before 0x4000' };

    let hasXts = false;
    for (const s of sections) {
        if (s.cryptoType === RAW_XTS) hasXts = true;
    }
    if (hasXts) return { ...base, compressible: false, reason: 'XTS section (not lossless through the NCZ round-trip)' };

    const rightsId = header.rightsId;
    const hasRights = rightsId !== '0'.repeat(32);
    let titlekey = titlekeyHint;
    if (!titlekey && !hasRights) {
        // Non-rights NCA: titlekey IS in the header key area (hactool
        // nca_decrypt_key_area; NCAHeader.parse already derived it).
        titlekey = header.titleKeyDec;
    }
    if (!titlekey) {
        // A titlekey is required for EVERY compressible NCA: python writes it
        // into every NCZ section-table entry (plaintext sections included) and
        // refuses to compress without it.
        return {
            ...base, compressible: false, needsTitlekey: true,
            reason: hasRights ? 'needs titlekey from ticket (.tik)' : 'missing titlekey (key area empty)',
            sections,
        };
    }

    return { ...base, compressible: true, titlekey, sections };
}

// Resolve a missing titlekey for a rights-managed NCA from the container's
// tickets (hactool: titlekeys db / tik; python: the Titles db is filled from
// the container's own .tik members on open). tikByRightsId / tikByTitleId map
// lowercased id → { name, read(): Promise<Uint8Array> } (raw ticket bytes).
// Returns { titlekey, tikName } or null.
async function resolveTitlekeyFromTik(analysis, keys, tikByRightsId, tikByTitleId) {
    if (!analysis.needsTitlekey) return null;
    const tik = (analysis.rightsId && tikByRightsId.get(analysis.rightsId.toLowerCase()))
        || (analysis.titleId && tikByTitleId.get(analysis.titleId.toLowerCase()));
    if (!tik) return null;
    const tikData = await tik.read();
    const titlekey = extractTitlekeyFromTik(tikData, keys, analysis.rightsId || null, analysis.decHeader);
    return titlekey ? { titlekey, tikName: tik.name } : null;
}

// ── BKTR expansion ──────────────────────────────────────────────────────────
// Expand a BKTR (raw byte 4) RomFS section into per-subsection CTR sections + a
// tail section, matching python getEncryptionSections() + setBktrCounter().
// `section` is a NCAHeader.parse section: offset/size, cryptoCounter (8B
// reversed head), bktr2Buffer (fsHdr[0x120:0x140] = the PATCH_INFO_AESCTREX
// slot: table offset@0, size@8).
async function expandBktr(ncaReader, section, titlekey) {
    const secOffset = section.offset;
    const secSize = section.size;
    const nonce = section.cryptoCounter; // 8B reversed section ctr (table counter)

    const subOffset = readLeU64(section.bktr2Buffer, 0);
    const subSize = readLeU64(section.bktr2Buffer, 8);
    if (subSize === 0) {
        // No subsection table — treat the whole section as one CTR run (defensive).
        return [makeCtrSection(secOffset, secSize, titlekey, nonce)];
    }
    const subAbs = secOffset + subOffset;
    const subCipher = await ncaReader.read(subAbs, subSize);
    const subPlain = await decryptBktrTableData(subCipher, titlekey, nonce, subAbs);
    const { totalSize, entries } = parseSubsectionBlock(subPlain);

    const secv4 = nonce.subarray(0, 4); // secure_value BE (first 4 of the reversed head)
    const sections = [];
    for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        const nextOff = i + 1 < entries.length ? entries[i + 1].offset : totalSize;
        const size = nextOff - e.offset;
        if (size <= 0) continue;
        sections.push({
            offset: secOffset + e.offset,
            size,
            nczType: NCZ_CRYPTO_TYPE.CTR,
            key: titlekey,
            counter: bktrSubsectionCounter(secv4, e.ctrVal),
            isCtr: true,
        });
    }
    // Tail: the tables region after the last subsection, encrypted with the base
    // (reversedSectionCtr) counter — the decompressor AesCtr.seek handles it.
    const lastEnd = secOffset + totalSize;
    if (lastEnd < secOffset + secSize) {
        sections.push(makeCtrSection(lastEnd, secOffset + secSize - lastEnd, titlekey, nonce));
    }
    return sections;
}

function makeCtrSection(offset, size, titlekey, head8) {
    const counter = new Uint8Array(16);
    counter.set(head8, 0);
    return { offset, size, nczType: NCZ_CRYPTO_TYPE.CTR, key: titlekey, counter, isCtr: true };
}

// BKTR subsection counter head: [secureValue 4B BE][ctrVal 4B BE] (low 8 bytes
// zero — the decompressor's AesCtr.seek(section.offset) fills them with offset>>4).
// Matches python setBktrCounter (ctr[0x8-j-1] = ctr_val LE digits → BE storage).
function bktrSubsectionCounter(secv4, ctrVal) {
    const counter = new Uint8Array(16);
    counter.set(secv4, 0);
    counter[4] = (ctrVal >>> 24) & 0xFF;
    counter[5] = (ctrVal >>> 16) & 0xFF;
    counter[6] = (ctrVal >>> 8) & 0xFF;
    counter[7] = ctrVal & 0xFF;
    return counter;
}

// ── Payload runs ────────────────────────────────────────────────────────────
// The continuous crypto runs covering [0x4000, ncaSize): a plaintext gap (if the
// first section is past 0x4000) followed by the sections in offset order.
function buildRuns(nczSections, ncaSize) {
    const runs = [];
    if (nczSections.length > 0) {
        const firstOffset = nczSections[0].offset;
        if (firstOffset > UNCOMPRESSABLE_HEADER_SIZE) {
            runs.push({ start: UNCOMPRESSABLE_HEADER_SIZE, end: firstOffset, isCtr: false, key: null, counter: null });
        }
        for (const s of nczSections) {
            runs.push({ start: s.offset, end: s.offset + s.size, isCtr: s.isCtr, key: s.key, counter: s.counter });
        }
    }
    return runs;
}

// Fill buf with the PLAINTEXT of [blockStart, blockStart+blockSize), walking the
// runs (which are contiguous + sorted). Advances runIdx; returns the new index.
// CTR runs reuse decryptNcaSection (fs/nca.js): AesCtr with the 16B section
// counter, seeked to the ABSOLUTE offset — the exact keystream the NCZ
// decompressor re-applies (encrypt == decrypt in CTR).
async function fillPlaintextBlock(ncaReader, runs, blockStart, blockSize, buf, runIdx) {
    let filled = 0;
    while (filled < blockSize) {
        while (runIdx < runs.length - 1 && blockStart + filled >= runs[runIdx].end) runIdx++;
        const run = runs[runIdx];
        const ovStart = Math.max(blockStart + filled, run.start);
        const ovEnd = Math.min(blockStart + blockSize, run.end);
        const len = ovEnd - ovStart;
        if (len <= 0) { runIdx++; continue; }
        let data = await ncaReader.read(ovStart, len);
        if (run.isCtr) {
            data = await decryptNcaSection(data, { cryptoKey: run.key, cryptoCounter: run.counter, offset: ovStart });
        }
        buf.set(data, ovStart - blockStart);
        filled += len;
    }
    return runIdx;
}

// ── Table builders ──────────────────────────────────────────────────────────
function ascii(buf, off, str) {
    for (let i = 0; i < str.length; i++) buf[off + i] = str.charCodeAt(i);
}

function buildSectnTable(sections) {
    const E = NCZ_SECTN_ENTRY;
    const buf = new Uint8Array(8 + 8 + sections.length * E.ENTRY_SIZE);
    ascii(buf, 0, 'NCZSECTN');
    writeU64LE(buf, 8, sections.length);
    for (let i = 0; i < sections.length; i++) {
        const s = sections[i];
        const off = 16 + i * E.ENTRY_SIZE;
        writeU64LE(buf, off + E.OFFSET, s.offset);
        writeU64LE(buf, off + E.SIZE, s.size);
        writeU64LE(buf, off + E.CRYPTO_TYPE, s.nczType);
        // [off+24, off+32) = 8 zero bytes (reserved)
        buf.set(s.key, off + E.KEY);
        buf.set(s.counter, off + E.COUNTER);
    }
    return buf;
}

function buildBlockHeader(numberOfBlocks, decompressedSize, blockSizeExponent) {
    const buf = new Uint8Array(24);
    ascii(buf, 0, 'NCZBLOCK');
    buf[8] = 2;                            // version
    buf[9] = 1;                            // type
    buf[10] = 0;                           // unused
    buf[11] = blockSizeExponent;           // block size exponent (2^x)
    writeU32LE(buf, 12, numberOfBlocks);
    writeU64LE(buf, 16, decompressedSize);
    return buf;
}

// ── Per-NCA compression ─────────────────────────────────────────────────────
// Compress one NCA into NCZ format via write(pos, data) (pos = absolute NCZ
// offset; the target must be seekable). Returns the total NCZ size in bytes.
// `analysis` comes from analyzeNca() (must be compressible); `opts` is the
// compression options object (level / blockSizeExponent / ldm / mode — see
// normalizeCompressOptions).
export async function compressNcaToWriter(ncaReader, ncaSize, analysis, opts, write, onProgress = null) {
    const { level, blockSizeExponent, ldm, mode } = normalizeCompressOptions(opts);
    const { titlekey, sections } = analysis;

    // 1. Raw 0x4000 NCA header, verbatim (still encrypted).
    const headerRaw = await ncaReader.read(0, UNCOMPRESSABLE_HEADER_SIZE);
    await write(0, headerRaw);

    // 2. Build the NCZ section table (expand BKTR into subsections + tail).
    const nczSections = [];
    for (const s of sections) {
        if (s.cryptoType === RAW_BKTR) {
            nczSections.push(...await expandBktr(ncaReader, s, titlekey));
        } else if (s.cryptoType === RAW_CTR) {
            // section.cryptoCounter is the reversed 8B head (nca.js).
            nczSections.push(makeCtrSection(s.offset, s.size, titlekey, s.cryptoCounter));
        } else {
            // Plaintext (NONE/ERR): no crypto applied, but python still writes
            // the titlekey and the section's (zero for plaintext) reversed
            // counter into the table entry.
            const counter = new Uint8Array(16);
            counter.set(s.cryptoCounter.subarray(0, 8), 0);
            nczSections.push({ offset: s.offset, size: s.size, nczType: s.cryptoType === RAW_ERR ? RAW_ERR : NCZ_CRYPTO_TYPE.NONE, key: titlekey, counter, isCtr: false });
        }
    }
    nczSections.sort((a, b) => a.offset - b.offset);

    // 3. NCZSECTN table at 0x4000.
    const sectnBuf = buildSectnTable(nczSections);
    await write(UNCOMPRESSABLE_HEADER_SIZE, sectnBuf);

    const payloadSize = ncaSize - UNCOMPRESSABLE_HEADER_SIZE;
    const runs = buildRuns(nczSections, ncaSize);
    const payloadStart = UNCOMPRESSABLE_HEADER_SIZE + sectnBuf.length;

    if (mode === 'solid') {
        // SOLID (python -S / SolidCompressor): ONE zstd frame over the whole
        // payload, right after the table — NO NCZBLOCK header. The frame is
        // streamed (node:zlib): plaintext is fed in 16 MiB chunks (python
        // CHUNK_SZ) and the frame is written out as it is produced.
        const comp = await createSolidCompressor({ level, ldm });
        let outPos = payloadStart;
        let runIdx = 0;
        const CHUNK = 16 * 1024 * 1024;
        const pump = (async () => {
            for await (const c of comp) {
                await write(outPos, c);
                outPos += c.length;
            }
        })();
        try {
            let pos = UNCOMPRESSABLE_HEADER_SIZE;
            while (pos < ncaSize) {
                const n = Math.min(CHUNK, ncaSize - pos);
                // FRESH buffer per chunk: the memory output adapter references
                // chunk buffers in place (no copy), and the compressor/queue
                // hold the buffers past write() — a reused buffer would
                // corrupt earlier output.
                const buf = new Uint8Array(n);
                runIdx = await fillPlaintextBlock(ncaReader, runs, pos, n, buf, runIdx);
                await comp.write(buf);
                pos += n;
                if (onProgress) onProgress(pos / ncaSize);
            }
            comp.finish();
            await pump;
        } catch (e) {
            comp.abort();
            await pump.catch(() => {});
            throw e;
        }
        return outPos;
    }

    // BLOCK (python -B / BlockCompressor, the default): NCZBLOCK header +
    // independent blocks of 2^blockSizeExponent, raw when incompressible.
    // The block size list sits right after the header — its position is KNOWN
    // before compression (numberOfBlocks = ceil(payload / blockSize)), so the
    // region is only reserved by position and filled ONCE after the block
    // loop (no zero placeholder, no same-offset rewrite: fd leaves a sparse
    // hole, FSA extends the file, the memory adapter simply has no chunk
    // there yet).
    const BLOCK_SIZE = 1 << blockSizeExponent;
    const numberOfBlocks = Math.ceil(payloadSize / BLOCK_SIZE);
    const blockHeaderPos = payloadStart;
    const sizeListPos = blockHeaderPos + 24;
    const blocksStart = sizeListPos + numberOfBlocks * 4;
    await write(blockHeaderPos, buildBlockHeader(numberOfBlocks, payloadSize, blockSizeExponent));

    // Stream the payload in blocks; compress (raw when incompressible).
    const sizeList = new Array(numberOfBlocks).fill(0);
    let outPos = blocksStart;
    let runIdx = 0;
    let pos = UNCOMPRESSABLE_HEADER_SIZE;
    let blockIdx = 0;
    while (pos < ncaSize) {
        const blockDecompSize = Math.min(BLOCK_SIZE, ncaSize - pos);
        const buf = new Uint8Array(blockDecompSize);
        runIdx = await fillPlaintextBlock(ncaReader, runs, pos, blockDecompSize, buf, runIdx);
        let stored;
        const compressed = await compressBlock(buf, level, ldm);
        if (compressed.length < blockDecompSize) stored = compressed;
        else stored = buf; // incompressible — store the plaintext verbatim
        sizeList[blockIdx] = stored.length;
        await write(outPos, stored);
        outPos += stored.length;
        blockIdx++;
        pos += blockDecompSize;
        if (onProgress) onProgress(pos / ncaSize);
    }

    // Fill the block size list (seek back).
    const sizeListBuf = new Uint8Array(numberOfBlocks * 4);
    for (let i = 0; i < numberOfBlocks; i++) writeU32LE(sizeListBuf, i * 4, sizeList[i]);
    await write(sizeListPos, sizeListBuf);

    return outPos;
}

// In-memory variant (for tests): compresses an NCA into a Uint8Array.
export async function compressNcaToBuffer(ncaReader, ncaSize, analysis, opts = {}) {
    const chunks = [];
    const write = (pos, data) => { chunks.push({ pos, data }); };
    const size = await compressNcaToWriter(ncaReader, ncaSize, analysis, opts, write);
    const out = new Uint8Array(size);
    for (const c of chunks) out.set(c.data, c.pos);
    return out;
}

// ── Per-member plan (NSP and XCI paths) ─────────────────────────────────────
// Decide compress vs copy + the output name for every member. Shared by the
// NSP path and the XCI path (identical rules); `labelOf(f)` is the log label
// (NSP: the name; XCI: "partition/name"). Plan entry:
// { file, compress, analysis?, outName } — dropped delta fragments are ABSENT
// from the returned plan (not copied).
async function planMembers(files, { reader, keys, byRightsId, byTitleId, keep, log, labelOf = (f) => f.name }) {
    const plan = [];
    for (const f of files) {
        const lower = f.name.toLowerCase();
        let nczReader = null;   // .ncz members: a virtual NCA view over the NCZ
        let ncaSize = f.size;
        if (lower.endsWith('.ncz')) {
            // Re-compression (our extension — python nsz never re-compresses):
            // present the member's original NCA bytes through an NczNcaReader
            // and run the identical per-NCA pipeline. Strict: a .ncz member
            // that is not a valid NCZ throws, like the decompress path.
            const scoped = { read: (offset, size) => reader.read(f.offset + offset, size), length: f.size };
            nczReader = new NczNcaReader(scoped);
            await nczReader.ensure();
            ncaSize = nczReader.length; // the true NCA size, not the .ncz file size
            log('info', `[RECOMPRESS] ${labelOf(f)}: .ncz member, NCA size ${ncaSize} (file ${f.size})`);
        } else if (!lower.endsWith('.nca')) {
            plan.push({ file: f, compress: false, outName: f.name });
            continue;
        }
        const ncaReader = nczReader || { read: (offset, size) => reader.read(f.offset + offset, size) };
        const analysis = await analyzeNca(ncaReader, ncaSize, keys);

        // Delta fragments (DATA NCAs) are dropped from the output unless keep
        // (python nsz default; --keep retains them for bit-identical output).
        // They are never compressed, so no titlekey is ever needed for them.
        if (!keep && analysis.headerOk && analysis.contentType === NCA_CONTENT_TYPE.DATA) {
            log('info', `[SKIPPED] ${labelOf(f)}: delta fragment (kept only with keep)`);
            continue;
        }

        const outName = nczReader ? f.name : f.name.replace(/\.nca$/i, '.ncz'); // .ncz stays .ncz
        if (analysis.compressible) {
            plan.push({ file: f, compress: true, analysis, outName, ncaSize, nczReader });
        } else if (analysis.needsTitlekey) {
            // The NCA is otherwise fully compressible but its titlekey is not
            // in the header key area (rights-managed). For .ncz members the
            // input's own NCZSECTN table carries the titlekey in every entry
            // (python writes it into ALL entries, plaintext included) — it is
            // the key the payload is encrypted with, so it is the only choice
            // that guarantees a lossless round-trip; prefer it over the
            // container's tickets (retail NSZs often carry no .tik at all).
            // For .nca members resolve from the tickets (the XCI db is global,
            // across partitions); if nothing matches, fail loudly rather than
            // silently emit a bloated output with the NCA copied verbatim.
            let resolved = null;
            if (nczReader) {
                const parsed = await nczReader.ensure();
                const src = parsed.sections.find(s => s.cryptoKey && s.cryptoKey.some(b => b !== 0));
                if (src) resolved = { titlekey: src.cryptoKey, tikName: `${f.name} section table` };
            }
            if (!resolved) resolved = await resolveTitlekeyFromTik(analysis, keys, byRightsId, byTitleId);
            if (resolved) {
                log('info', `[TITLEKEY]   ${labelOf(f)}: from ${resolved.tikName}`);
                plan.push({ file: f, compress: true, analysis: { ...analysis, compressible: true, needsTitlekey: false, titlekey: resolved.titlekey }, outName, ncaSize, nczReader });
            } else {
                throw new Error(
                    `Missing title key for ${labelOf(f)} (titleId=${analysis.titleId}, rightsId=${analysis.rightsId}). ` +
                    `Add a matching .tik to the container or provide the titlekey.`
                );
            }
        } else {
            log('info', `[SKIP] ${labelOf(f)}: ${analysis.reason}`);
            plan.push({ file: f, compress: false, outName: f.name });
        }
    }
    return plan;
}

// ── NSP → NSZ container compression ─────────────────────────────────────────
// Rebuild the NSP as an NSZ: compress eligible NCAs to .ncz, copy the rest, and
// write a fresh PFS0 header (0x10-aligned, reusing the input string-table size).
//
// Layout follows python nsz v5 Pfs0Stream: the first member is written at the
// INPUT's firstFileOffset (not at the output header end), so when the output
// header is smaller than the input one (dropped deltas, shorter names) a zero
// gap remains between the header and the first member. The gap bytes are
// written explicitly (the memory adapter's blob contains written chunks only).
// `reader` is the input NSP reader; `output` is { memory:true } | { fd } | { writable }.
export async function compressNSPtoNSZ(reader, output, options = {}) {
    const { keys, keep = false, log = () => {}, progress = () => {}, createHash } = options;
    const compressOpts = normalizeCompressOptions(options); // validate level/bs/ldm/mode up front
    if (!keys || !keys.header_key) throw new Error('Keys are required to compress (decrypt NCA headers). Load keys first.');

    const pfs0 = await PFS0.open(reader);
    const files = pfs0.getFiles();
    const adapter = await buildAdapter(output, (offset, size) => reader.read(offset, size), { log, progress, createHash });

    // Pass 0: collect the container's tickets, then analyze every member and
    // decide compress vs copy + the output name. Rights-managed NCAs resolve
    // their titlekey from the .tik members (python nsz fills its Titles db the
    // same way on container open).
    const { byRightsId, byTitleId } = await collectTicketMaps(reader, files, log);
    const plan = await planMembers(files, { reader, keys, byRightsId, byTitleId, keep, log });

    // The output PFS0 header size depends only on the member name lengths (data
    // offsets are relative to the header end), so it is known before any data is
    // written — members are streamed in place and the header is written last.
    const nameLengths = plan.map((p) => p.outName.length);
    const headerSize = pfs0HeaderSize(nameLengths, { fixPadding: false, inputStringTableSize: pfs0.stringTableSize, headerAlign: 0x10 });
    // Python Pfs0Stream starts the first member at the INPUT's firstFileOffset
    // (f.seek(headerSize) with headerSize = container.getFirstFileOffset()), so
    // a smaller output header is followed by a zero gap. Reproduce it: the
    // writer's entries are shifted by it, and the first member is written at
    // headerSize + gap — the gap itself is a HOLE that reads as zeros (fd/FSA
    // POSIX zero-fill on extend; the memory adapter materializes it at
    // collectBlob time), so no explicit zero write is needed.
    const inputFirstOffset = files.length > 0 ? files[0].offset : 0;
    const gap = Math.max(0, inputFirstOffset - headerSize);
    const dataStart = headerSize + gap;
    const writer = new PFS0Writer(false, pfs0.stringTableSize, 0x10, gap);

    let relPos = 0;
    let dataDone = 0;
    const totalInput = files.reduce((s, f) => s + f.size, 0);

    for (const p of plan) {
        const f = p.file;
        const writePos = dataStart + relPos;
        if (p.compress) {
            log('info', `[COMPRESS]   ${f.name} → ${p.outName}${p.nczReader ? ' (re-compress)' : ''}`);
            const t0 = performance.now();
            // p.nczReader: the member is an .ncz — its original NCA bytes via
            // the virtual reader, ncaSize from the parsed NCZSECTN table.
            const ncaReader = p.nczReader || { read: (offset, size) => reader.read(f.offset + offset, size) };
            const ncaSize = p.ncaSize ?? f.size;
            const nczSize = await compressNcaToWriter(
                ncaReader, ncaSize, p.analysis, compressOpts,
                (off, data) => adapter.write(writePos + off, data),
                (frac) => progress(dataDone / totalInput + (frac * ncaSize) / totalInput, `Compressing ${f.name}...`),
            );
            writer.add(p.outName, nczSize);
            relPos += nczSize;
            dataDone += f.size;
            log('info', `[timing] ${f.name}: ${((performance.now() - t0) / 1000).toFixed(1)}s → ${nczSize} bytes NCZ`);
            progress(dataDone / totalInput, `Compressed ${f.name}`);
        } else {
            await copyRange(reader, f.offset, f.size,
                (off, data) => adapter.write(writePos + off, data),
                () => {});
            writer.add(p.outName, f.size);
            relPos += f.size;
            dataDone += f.size;
            progress(dataDone / totalInput, `Copied ${f.name}`);
        }
    }

    const header = writer.buildHeader();
    if (header.headerSize !== headerSize) {
        throw new Error(`PFS0 header size mismatch: planned ${headerSize}, built ${header.headerSize}`);
    }
    await adapter.write(0, header.buffer);

    const totalSize = dataStart + relPos;
    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount: plan.length };
    return { size: totalSize, memberCount: plan.length };
}

// ── XCI → XCZ container compression ─────────────────────────────────────────
// Rebuilds the XCI as an XCZ, mirroring python nsz v5 blockCompressXci +
// XciStream:
//   * [0x000, 0x200) — the input's first 0x200 bytes VERBATIM (python's
//     "gross hack": XciStream copies headerBuffer as-is, so validDataEndOffset
//     & co stay STALE at their input values)
//   * [0x200, 0xF000) — zeros (python never writes this region; the OS
//     zero-fills it when the file is extended)
//   * 0xF000          — root HFS0 (actual size, unpadded — the rest of the
//     0x8000 region is zeros), partitions laid out sequentially from 0x17000
//   * each partition  — its own HFS0 header (actual size) at the partition
//     start, files packed contiguously from partition-relative 0x8000, and a
//     total size of actualSize + align0x200(actualSize) with
//     align0x200(n) = 0x200 - n % 0x200 (an empty partition is a 0x200 stub
//     carrying a 0-file HFS0 header)
//
// Like python, ONLY the "secure" partition is processed: blockCompressXci
// calls blockCompressContainer for the other partitions only when `keep` is
// set — with keep=false, normal/update/logo become empty 0x200 stubs even if
// the input has content in them. (The python DECOMPRESSOR does process all
// partitions; the asymmetry is in the upstream code.)
//
// Python hardcodes the output root HFS0 to 0xF000 and copies the input header
// (which carries hfs0Offset) verbatim, so non-standard layouts (backup HEAD
// at 0x1100, hfs0Offset != 0xF000) cannot be compressed into a valid file —
// we throw instead of emitting what python would (a broken file).
// `reader` is the input XCI reader; `output` is { memory:true } | { fd } | { writable }.
export async function compressXCItoXCZ(reader, output, options = {}) {
    const { keys, keep = false, log = () => {}, progress = () => {}, createHash } = options;
    const compressOpts = normalizeCompressOptions(options); // validate level/bs/ldm/mode up front
    if (!keys || !keys.header_key) throw new Error('Keys are required to compress (decrypt NCA headers). Load keys first.');

    const xci = new XCIReader(reader);
    await xci.parse();
    if (xci.headOffset !== XCI_LAYOUT.HEAD_OFFSET || xci.hfs0Offset !== XCI_LAYOUT.ROOT_HFS0_OFFSET) {
        throw new Error(
            `Unsupported XCI layout: HEAD @0x${xci.headOffset.toString(16)}, hfs0Offset=0x${xci.hfs0Offset.toString(16)}. ` +
            `Only the standard layout (HEAD @0x100, root HFS0 @0xF000) is compressible — ` +
            `Python nsz hardcodes the output root HFS0 to 0xF000.`
        );
    }

    const adapter = await buildAdapter(output, (offset, size) => reader.read(offset, size), { log, progress, createHash });

    // Pass 0: parse every partition and collect the tickets it contains —
    // python fills its global Titles db from every .tik seen while opening the
    // container, across ALL partitions, before any NCA header is resolved.
    const partitions = xci.getPartitions();
    const partInfos = [];
    const tikByRightsId = new Map();
    const tikByTitleId = new Map();
    for (const p of partitions) {
        let files = [];
        if (p.size > 0) {
            let hfs0;
            try {
                hfs0 = await xci.readPartitionFiles(p);
            } catch (e) {
                throw new Error(`Cannot parse partition ${p.name} as HFS0: ${e.message}`);
            }
            files = hfs0.getFiles();
        }
        const tics = await collectTicketMaps(reader, files, log);
        for (const [k, v] of tics.byRightsId) tikByRightsId.set(k, v);
        for (const [k, v] of tics.byTitleId) tikByTitleId.set(k, v);
        partInfos.push({ entry: p, files });
    }

    // Plan every partition (shared per-file rules, planMembers).
    let memberCount = 0;
    for (const pi of partInfos) {
        const plan = await planMembers(pi.files, {
            reader, keys, byRightsId: tikByRightsId, byTitleId: tikByTitleId, keep, log,
            labelOf: (f) => `${pi.entry.name}/${f.name}`,
        });
        // blockCompressXci: blockCompressContainer runs only when
        // `keep or partitionIn._path == "secure"` — the other partitions become
        // empty 0x200 stubs even when the input has content in them.
        const process = keep || pi.entry.name === 'secure';
        if (!process && plan.length > 0) {
            log('info', `[SKIP-PARTITION] ${pi.entry.name}: ${plan.length} file(s) dropped (only "secure" is compressed without keep)`);
        }
        pi.plan = process ? plan : [];
        memberCount += pi.plan.length;
    }

    // Stream. Partition i starts at 0x17000 + Σ(previous aligned sizes); each
    // partition's HFS0 header is written LAST (its entries carry the final
    // compressed sizes) — the same seek-back pattern as the PFS0 header in the
    // NSP path. Only DATA and FINAL EXTENTS are written: the zero regions
    // ([0x200,0xF000), the root-HFS0 tail, each partition header region, tail
    // paddings of stubs) are HOLEs that read as zeros — POSIX zero-fill on
    // extend for fd/FSA (python never writes them either), materialized at
    // collectBlob time for the memory output. The one extent that data alone
    // can't establish is a stub partition's (its only bytes are the 0-file
    // HFS0 header written later at its start), so stubs get an explicit 0x200
    // zero write; non-stub partitions get their extent from the tail padding
    // below (alignedSize is always > actualSize, so there is always one).
    const prefix = await reader.read(0, XCI_LAYOUT.HEAD_SIZE);
    const totalInput = partInfos.reduce((s, pi) => s + pi.files.reduce((a, f) => a + f.size, 0), 0);
    let dataDone = 0;
    let partStart = XCI_LAYOUT.ROOT_HFS0_OFFSET + XCI_LAYOUT.PARTITION_HEADER_SIZE;
    const rootWriter = new HFS0Writer(XCI_LAYOUT.PARTITION_HEADER_SIZE);
    const writeZeros = (pos, len) => { if (len > 0) return adapter.write(pos, new Uint8Array(len)); };

    for (const pi of partInfos) {
        const plan = pi.plan;
        const hasFiles = plan.length > 0;

        // Stub partitions carry only the 0-file HFS0 header (written at the
        // seek-back below), so their 0x200 extent must be established now.
        // Non-stub partitions need nothing: the files at +0x8000 extend the
        // file and the header-region hole zero-fills (see above).
        if (!hasFiles) await writeZeros(partStart, XCI_LAYOUT.MIN_PARTITION_SIZE);

        let relPos = 0;
        for (const p of plan) {
            const f = p.file;
            const writePos = partStart + XCI_LAYOUT.PARTITION_HEADER_SIZE + relPos;
            if (p.compress) {
                log('info', `[COMPRESS]   ${pi.entry.name}/${f.name} → ${p.outName}${p.nczReader ? ' (re-compress)' : ''}`);
                const t0 = performance.now();
                const ncaReader = p.nczReader || { read: (offset, size) => reader.read(f.offset + offset, size) };
                const ncaSize = p.ncaSize ?? f.size;
                const nczSize = await compressNcaToWriter(
                    ncaReader, ncaSize, p.analysis, compressOpts,
                    (off, data) => adapter.write(writePos + off, data),
                    (frac) => progress(totalInput > 0 ? dataDone / totalInput + (frac * ncaSize) / totalInput : 1, `Compressing ${f.name}...`),
                );
                p.outSize = nczSize;
                relPos += nczSize;
                dataDone += f.size;
                log('info', `[timing] ${pi.entry.name}/${f.name}: ${((performance.now() - t0) / 1000).toFixed(1)}s → ${nczSize} bytes NCZ`);
            } else {
                await copyRange(reader, f.offset, f.size,
                    (off, data) => adapter.write(writePos + off, data),
                    () => {});
                p.outSize = f.size;
                relPos += f.size;
                dataDone += f.size;
            }
            progress(totalInput > 0 ? dataDone / totalInput : 1, `Done ${pi.entry.name}/${f.name}`);
        }

        const actualSize = hasFiles ? XCI_LAYOUT.PARTITION_HEADER_SIZE + relPos : 0;
        const alignedSize = actualSize + align0x200(actualSize);

        // Tail padding to the 0x200-aligned partition size — the partition's
        // FINAL EXTENT (for a stub the data end partStart+0x8000 is already
        // past its 0x200 end, so the stub's extent write above stands in).
        const dataEnd = partStart + XCI_LAYOUT.PARTITION_HEADER_SIZE + relPos;
        const partEnd = partStart + alignedSize;
        if (partEnd > dataEnd) await writeZeros(dataEnd, partEnd - dataEnd);

        // Partition HFS0 header (seek back — entries carry the final sizes).
        const pWriter = new HFS0Writer(XCI_LAYOUT.PARTITION_HEADER_SIZE);
        for (const p of plan) pWriter.addEntry(p.outName, p.outSize);
        const hfs0 = pWriter.buildHeader();
        await adapter.write(partStart, hfs0.buffer.subarray(0, hfs0.actualHeader));

        rootWriter.addEntry(pi.entry.name, alignedSize);
        partStart += alignedSize;
    }

    // Root HFS0 at 0xF000 (actual size — the tail of the 0x8000 region is a
    // hole) and the verbatim 0x200 header prefix; [0x200, 0xF000) stays a hole.
    const root = rootWriter.buildHeader();
    await adapter.write(XCI_LAYOUT.ROOT_HFS0_OFFSET, root.buffer.subarray(0, root.actualHeader));
    await adapter.write(0, prefix);

    const totalSize = partStart;
    if (output.memory) return { size: totalSize, blob: collectBlob(adapter, totalSize), memberCount };
    return { size: totalSize, memberCount };
}
