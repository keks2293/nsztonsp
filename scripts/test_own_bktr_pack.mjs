// Own-BKTR packer verification on real data (Stardew Valley NSZ — the merged
// RomFS fits in RAM, so we get FULL byte-equality).
//
// Stage 1 (direct packer):
//   computeOwnBktrContentId  (Pass 1 — streams tables + patch + base + exefs)
//   writeOwnBktrProgramNca   (Pass 2 — memory collector, sequential writes)
//   → assemble the own NCA → structural checks (own FsHeader, reloc table,
//     sub table via key-area-slot-2 titlekey) → contentId == sha256(NCA)
//     (Pass-1 hash == Pass-2 bytes) →
//     mergeRomFS(base, ownNCA) == scatter merge of the REAL update, byte-identical.
// Stage 2 (end-to-end update()):
//   SW-style append-only output captured in memory → full update() run →
//   extract the produced Program NCA → same merge equality + the PFS0 program
//   name carries the Pass-1 contentId (determinism across passes).
//
// Nothing is written to disk. Run from scripts/: `node test_own_bktr_pack.mjs`.

import fs from 'fs';
import { createHash } from 'crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';
import { PFS0 } from '../fs/pfs0.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { NczStreamSource, BufferRangeSource } from '../fs/range-source.js';
import { AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import {
    decryptNcaHeaderBytes, fsHeaderAt, deriveTitlekeyFromKeyArea, reversedSectionCtr,
    FS_HDR, SECTION_FS_TYPE, SECTION_CRYPTO_TYPE,
} from '../fs/nca-utils.js';
import { parseBktrHeader, decryptBktrTableData, parseRelocationBlock, parseSubsectionBlock } from '../fs/bktr.js';
import { resolveBktrMeta, readBktrTables, mergeRomFS, scatterRomFS } from '../fs/bktr-merge.js';
import { readLeU32, readLeU64 } from '../fs/bytes.js';
import { extractExefsStream } from '../fs/nca-pack.js';
import { computeOwnBktrContentId, writeOwnBktrProgramNca } from '../fs/bktr-pack.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const log = (level, msg) => console.log(`[${level.toUpperCase()}] ${msg}`);
const progress = () => {};
const sha256 = (b) => createHash('sha256').update(Buffer.from(b.buffer, b.byteOffset, b.length)).digest('hex');

class FileReader {
    constructor(path) {
        this.path = path;
        this.fd = fs.openSync(path, 'r');
        this.size = fs.statSync(path).size;
    }
    async read(offset, size) {
        const buf = Buffer.alloc(size);
        fs.readSync(this.fd, buf, 0, size, offset);
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    close() { fs.closeSync(this.fd); }
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function firstDiff(a, b, label) {
    if (a.length !== b.length) return `${label}: SIZE ${a.length} vs ${b.length}`;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return `${label}: first diff at 0x${i.toString(16)}`;
    return null;
}

// ── Setup: base + update NSZ readers, program entries, tiks ──────────────────
const baseReader = new FileReader(basePath);
const updateReader = new FileReader(updatePath);
const baseC = await openContainer({ reader: baseReader, name: 'base' });
const updC = await openContainer({ reader: updateReader, name: 'update' });

const pickProg = (c) => c.entries
    .filter(e => /\.(nca|ncz)$/i.test(e.name) && !/\.cnmt\.(nca|ncz)$/i.test(e.name))
    .sort((a, b) => b.size - a.size)[0];
const pickTik = async (c, r) => {
    const t = c.entries.find(e => e.name.toLowerCase().endsWith('.tik'));
    return t ? await r.read(t.offset, t.size) : null;
};

const baseProg = pickProg(baseC);
const updProg = pickProg(updC);
const baseHeaderRaw = await baseReader.read(baseProg.offset, Math.min(baseProg.size, 0xC00));
const updateHeaderRaw = await updateReader.read(updProg.offset, Math.min(updProg.size, 0xC00));
const baseTik = await pickTik(baseC, baseReader);
const updateTik = await pickTik(updC, updateReader);

const baseNcz = new AdapterNCZReader(baseReader, baseProg.offset, baseProg.size);
const updateNcz = new AdapterNCZReader(updateReader, updProg.offset, updProg.size);
const baseParsed = await parseNczSections(baseNcz);
const updateParsed = await parseNczSections(updateNcz);
const baseNcaData = { headerRaw: baseHeaderRaw };
const updateNcaData = { headerRaw: updateHeaderRaw };

const updateHdr = decryptNcaHeader(updateHeaderRaw, keys);
const bktrIdx = updateHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
if (bktrIdx < 0) throw new Error('update has no BKTR romfs section');
const updateDec = decryptNcaHeaderBytes(updateHeaderRaw, keys);
const updFh = fsHeaderAt(updateDec, bktrIdx);
const exefsIdx = updateHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.PFS0);
if (exefsIdx < 0) throw new Error('update has no ExeFS section');
const updExefsFh = fsHeaderAt(updateDec, exefsIdx);
const exefsSize = readLeU64(updExefsFh, FS_HDR.PFS0_SIZE);
const titleId = decryptNcaHeader(baseHeaderRaw, keys).titleId.toLowerCase();
const dataLevelSize = readLeU64(updFh, 0x18 + 5 * 0x18 + 8); // IVFC level 5 (data) hash_data_size

log('info', `Stardew: titleId=${titleId} exefsSize=0x${exefsSize.toString(16)} mergedDataSize=0x${dataLevelSize.toString(16)}`);

const updateCtx = { headerRaw: updateHeaderRaw, source: null, reader: updateNcz, parsed: updateParsed, streamable: true };

// The exact source factories the SW two-pass branch builds (mirrors update.js
// makeOwnUpdateSource — including { register: false } for the walk):
const makeOwnUpdateSource = (ranges, onProgress, opts = {}) => {
    const src = new NczStreamSource(updateCtx.reader, updateCtx.parsed, log, onProgress);
    if (opts.register !== false) for (const r of ranges) src.registerRange(r.off, r.len);
    return src;
};
const makeOwnBaseSource = () => new NczStreamSource(baseNcz, baseParsed, log);
// ExeFS streams from its own one-shot NCZ pass registered with just the ExeFS
// range (mirrors updateSource in update.js two-pass NCZ branch).
const exefsSec = updateHdr.sections[exefsIdx];
const makeStreamExefs = () => {
    const src = new NczStreamSource(updateNcz, updateParsed, log);
    src.registerRange(exefsSec.offset, exefsSec.endOffset - exefsSec.offset);
    return src;
};
const streamExefs = (emit) => extractExefsStream({ headerRaw: updateHeaderRaw, source: makeStreamExefs() }, keys, updateTik, emit);

// ── Stage 0: reference merged data (physical-order scatter of the REAL update) ─
log('info', 'Stage 0: reference merged data via scatterRomFS (real update)...');
const mergedRef = new Uint8Array(dataLevelSize);
let refWritten = 0;
const ref = await scatterRomFS({
    baseInput: { headerRaw: baseHeaderRaw, source: new NczStreamSource(baseNcz, baseParsed, log) },
    updateCtx,
    options: { keys, baseTik, updateTik },
    writeFn: (off, chunk) => { mergedRef.set(chunk, off); refWritten += chunk.length; },
    log,
});
log('info', `reference: ${ref.relocEntries} reloc / ${ref.subsectionEntries} sub entries, ${refWritten.toLocaleString()} bytes written`);

// Real update tables (for structural comparison of the own tables).
let realRelocEntries = null, realTotalSize = null, realSubEntries = null;
{
    const metaR = await resolveBktrMeta(baseNcaData, updateNcaData, { keys, baseTik, updateTik });
    const tableRanges = [
        { off: metaR.relocAbsOffset, len: metaR.relocHeader.size },
        { off: metaR.subAbsOffset, len: metaR.subHeader.size },
    ].sort((a, b) => a.off - b.off);
    const { relocBlock: rb, subBlock: sb } = await readBktrTables(makeOwnUpdateSource(tableRanges), metaR);
    realRelocEntries = rb.entries;
    realTotalSize = rb.totalSize;
    realSubEntries = sb.entries;
}
log('info', `real update: reloc totalSize=0x${realTotalSize.toString(16)}, entries=${realRelocEntries.length}, sub=${realSubEntries.length}`);

// ── Stage 1: direct packer ────────────────────────────────────────────────────
log('info', '\nStage 1: computeOwnBktrContentId (Pass 1)...');
const t1 = performance.now();
const { size: ownSize, contentId, meta } = await computeOwnBktrContentId({
    baseNcaData, updateNcaData,
    makeUpdateSource: makeOwnUpdateSource, makeBaseSource: makeOwnBaseSource,
    keys, baseTik, updateTik,
    titleId, exefsSize,
    streamExefs,
    log, progress,
});
log('info', `[timing] Pass 1 compute: ${((performance.now() - t1) / 1000).toFixed(1)}s — ncaSize=0x${ownSize.toString(16)} contentId=${contentId}`);
if (ownSize !== meta.L.ncaSize) throw new Error('size mismatch');

log('info', 'Stage 1: writeOwnBktrProgramNca (Pass 2) into memory collector...');
const ncaChunks = [];
const collector = { write: async (pos, data) => { ncaChunks.push({ pos, data: data.slice(0) }); } };
await writeOwnBktrProgramNca({
    meta, adapter: collector, ncaOffset: 0, contentId,
    streamExefs, makeUpdateSource: makeOwnUpdateSource, makeBaseSource: makeOwnBaseSource,
    log, progress,
});

// Assemble + check sequential discipline.
const ownNca = new Uint8Array(meta.L.ncaSize);
let runPos = 0;
for (const c of ncaChunks.sort((a, b) => a.pos - b.pos)) {
    if (c.pos !== runPos) throw new Error(`Stage 1: non-sequential write at 0x${c.pos.toString(16)} (expected 0x${runPos.toString(16)})`);
    ownNca.set(c.data, c.pos);
    runPos += c.data.length;
}
if (runPos !== meta.L.ncaSize) throw new Error(`Stage 1: wrote ${runPos} bytes, expected ${meta.L.ncaSize}`);

// Pass-1 hash must equal the Pass-2 written bytes.
const ncaSha = sha256(ownNca);
log('info', `sha256(ownNCA) = ${ncaSha}`);
if (ncaSha !== contentId) throw new Error(`Stage 1: contentId mismatch — computed ${contentId}, sha256 of written NCA ${ncaSha}`);

// ── Stage 1 structural checks ─────────────────────────────────────────────────
const L = meta.L;
{
    const ownDec = decryptNcaHeaderBytes(ownNca.subarray(0, 0xC00), keys);
    const ownHdr = decryptNcaHeader(ownNca.subarray(0, 0xC00), keys);
    const ownBktrIdx = ownHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
    if (ownBktrIdx !== 1) throw new Error(`Stage 1: BKTR section index ${ownBktrIdx}, expected 1`);
    const ownFh = fsHeaderAt(ownDec, ownBktrIdx);
    const v = new DataView(ownFh.buffer, ownFh.byteOffset, ownFh.byteLength);
    if (v.getUint16(0, true) !== 2) throw new Error('Stage 1: fsHeader version != 2');
    if (ownFh[0x02] !== 0x00 || ownFh[0x03] !== 0x03 || ownFh[0x04] !== 0x04) {
        throw new Error(`Stage 1: fsHeader type bytes = [${ownFh[0x02].toString(16)}, ${ownFh[0x03].toString(16)}, ${ownFh[0x04].toString(16)}]`);
    }
    const relocH = parseBktrHeader(ownFh, FS_HDR.PATCH_INFO);
    const subH = parseBktrHeader(ownFh, FS_HDR.PATCH_INFO_AESCTREX);
    if (relocH.offset !== L.relocOff || relocH.size !== L.relocBlockSize) throw new Error('Stage 1: reloc PatchInfo mismatch');
    if (subH.offset !== L.subOff || subH.size !== L.subBlockSize) throw new Error('Stage 1: sub PatchInfo mismatch');
    if (readLeU32(ownFh, FS_HDR.SECURE_VALUE - 4) !== 1 || readLeU32(ownFh, FS_HDR.SECURE_VALUE) !== 2) throw new Error('Stage 1: gen/secv mismatch');
    // superblock verbatim parity with the real update's fsHeader
    if (!bytesEqual(ownFh.subarray(0x08, 0xE8), updFh.subarray(0x08, 0xE8))) throw new Error('Stage 1: superblock [0x08:0xE8) not verbatim');

    // titlekey from our key area slot 2 must equal the one used to encrypt
    const ourTk = deriveTitlekeyFromKeyArea(ownDec, keys);
    if (!ourTk || !bytesEqual(ourTk, meta.ourTitlekey)) throw new Error('Stage 1: deriveTitlekeyFromKeyArea != meta.ourTitlekey');

    // tables
    const ourNonce = reversedSectionCtr(ownFh);
    const relocRaw = ownNca.subarray(L.sec1Start + L.relocOff, L.sec1Start + L.relocOff + L.relocBlockSize);
    const subRaw = ownNca.subarray(L.sec1Start + L.subOff, L.sec1Start + L.subOff + L.subBlockSize);
    const relocPlain = await decryptBktrTableData(relocRaw, ourTk, ourNonce, L.sec1Start + L.relocOff);
    const subPlain = await decryptBktrTableData(subRaw, ourTk, ourNonce, L.sec1Start + L.subOff);
    const ownReloc = parseRelocationBlock(relocPlain);
    const ownSub = parseSubsectionBlock(subPlain);

    if (ownReloc.totalSize !== realTotalSize) throw new Error(`Stage 1: own reloc totalSize 0x${ownReloc.totalSize.toString(16)} != real 0x${realTotalSize.toString(16)}`);
    if (ownReloc.entries.length !== realRelocEntries.length) throw new Error(`Stage 1: reloc entries ${ownReloc.entries.length} != real ${realRelocEntries.length}`);
    for (let i = 0; i < ownReloc.entries.length; i++) {
        const o = ownReloc.entries[i], r = realRelocEntries[i];
        if (o.virtOffset !== r.virtOffset) throw new Error(`Stage 1: virt[${i}] 0x${o.virtOffset.toString(16)} != 0x${r.virtOffset.toString(16)}`);
        if (!o.isPatch) throw new Error(`Stage 1: reloc[${i}] not isPatch`);
        if (o.physOffset >= L.relocOff) throw new Error(`Stage 1: reloc[${i}] phys 0x${o.physOffset.toString(16)} outside data region 0x${L.relocOff.toString(16)}`);
        if (o.physOffset % 16 !== 0) throw new Error(`Stage 1: reloc[${i}] phys 0x${o.physOffset.toString(16)} not 16-aligned`);
    }
    const relocBuckets = Math.ceil(ownReloc.entries.length / 818);
    if (L.relocBlockSize !== 0x4000 + relocBuckets * 0x4000) throw new Error(`Stage 1: reloc block size 0x${L.relocBlockSize.toString(16)} != 0x4000 + ${relocBuckets}*0x4000`);

    if (ownSub.entries.length !== 2) throw new Error(`Stage 1: sub entries ${ownSub.entries.length}, expected 2`);
    if (ownSub.entries[0].offset !== 0 || ownSub.entries[0].ctrVal !== 0) throw new Error('Stage 1: sub[0] != {0, 0}');
    if (ownSub.entries[1].offset !== L.relocOff) throw new Error(`Stage 1: sub[1].offset != dataRegionSize 0x${L.relocOff.toString(16)}`);
    if (ownSub.totalSize !== L.relocOff) throw new Error('Stage 1: sub totalSize != dataRegionSize');

    // section entries in the NCA header
    if (ownHdr.sections[0].offset !== 0xC00 || ownHdr.sections[0].size !== L.exeSectionSize) throw new Error('Stage 1: section 0 entry mismatch');
    if (ownHdr.sections[1].offset !== L.sec1Start || ownHdr.sections[1].size !== L.romSectionSize) throw new Error('Stage 1: section 1 entry mismatch');
    log('info', `Stage 1 structure OK: reloc=${ownReloc.entries.length} (${relocBuckets} buckets), sub=2, dataRegion=0x${L.relocOff.toString(16)}, romSection=0x${L.romSectionSize.toString(16)}`);
}

// ── Stage 1 merge equality ────────────────────────────────────────────────────
log('info', 'Stage 1: mergeRomFS(base, own-NCA) vs reference scatter merge...');
{
    const ours = await mergeRomFS(
        { headerRaw: baseHeaderRaw, source: { read: async () => new Uint8Array(0) } },
        { headerRaw: ownNca.subarray(0, 0xC00), source: BufferRangeSource(ownNca) },
        { keys, log }
    );
    if (ours.dataLevelSize !== dataLevelSize) throw new Error(`Stage 1: merged data size ${ours.dataLevelSize} != ${dataLevelSize}`);
    const d = firstDiff(ours.mergedData, mergedRef, 'Stage 1 merged');
    if (d) throw new Error(d);
    log('info', `Stage 1 PASS: own-BKTR NCA merge == real update merge (${dataLevelSize.toLocaleString()} bytes byte-identical)`);
}

// ── Stage 2: full update() on an SW-style sequential output ──────────────────
if (process.env.STAGE === '1') {
    log('warn', '\nStage 2 skipped (STAGE=1)');
    baseReader.close();
    updateReader.close();
    console.log('\nPASS (Stage 1 only): own-BKTR packer — structure, determinism and full byte-equality.');
    process.exit(0);
}
log('info', '\nStage 2: full update() with append-only SW output (in-memory)...');
const outChunks = [];
const swOut = {
    writable: {
        write: async (pos, data) => {
            const u = data instanceof Uint8Array ? data : new Uint8Array(data);
            outChunks.push({ pos, data: u.slice(0) });
        },
    },
};
const readers = [
    { name: 'base.nsz', reader: baseReader },
    { name: 'update.nsz', reader: updateReader },
];
const t2 = performance.now();
await update(readers, swOut, { keys, log, progress });
log('info', `[timing] Stage 2 update(): ${((performance.now() - t2) / 1000).toFixed(1)}s`);

// Assemble the NSP from the sequential chunk stream.
outChunks.sort((a, b) => a.pos - b.pos);
let total = 0;
for (const c of outChunks) total = Math.max(total, c.pos + c.data.length);
const nsp = new Uint8Array(total);
let rpos = 0;
const gaps = [];
for (const c of outChunks) {
    if (c.pos > rpos) gaps.push({ at: c.pos, gap: c.pos - rpos, wrote: rpos });
    nsp.set(c.data, c.pos);
    if (c.pos + c.data.length > rpos) rpos = c.pos + c.data.length;
}
if (gaps.length) throw new Error(`Stage 2: ${gaps.length} gap(s) in SW stream, first at 0x${gaps[0].at.toString(16)}`);
log('info', `Stage 2: assembled NSP (${total.toLocaleString()} bytes, no gaps)`);

const entries = new PFS0(nsp.subarray(0, Math.min(nsp.length, 0x100000))).getFiles();
const prog = entries.filter(e => /\.nca$/i.test(e.name) && !/\.cnmt\.nca$/i.test(e.name)).sort((a, b) => b.size - a.size)[0];
if (!prog) throw new Error('Stage 2: no Program NCA in produced NSP');
const producedNca = nsp.subarray(prog.offset, prog.offset + prog.size);
log('info', `Stage 2: program member "${prog.name}" (${prog.size.toLocaleString()} bytes)`);

// Determinism: update()'s Pass-1 contentId is embedded in the PFS0 program
// name; it must equal the sha256 of the NCA actually written in Pass 2.
// (NB: update() runs the exefs through the ACID filter, so its contentId
// differs from the Stage-1 direct compute — that is expected; each stage checks
// internal determinism: Pass-1-hash == Pass-2-bytes.)
const psha = sha256(producedNca);
if (!prog.name.toLowerCase().startsWith(psha.slice(0, 32))) {
    throw new Error(`Stage 2: program name contentId ${prog.name.slice(0, 32)} != sha256(NCA) prefix ${psha.slice(0, 32)}`);
}
log('info', `Stage 2: produced NCA sha256 == Pass-1 contentId (${psha.slice(0, 32)}…, determinism OK)`);

// Stage 2 merge equality.
{
    const ours = await mergeRomFS(
        { headerRaw: baseHeaderRaw, source: { read: async () => new Uint8Array(0) } },
        { headerRaw: producedNca.subarray(0, 0xC00), source: BufferRangeSource(producedNca) },
        { keys, log }
    );
    const d = firstDiff(ours.mergedData, mergedRef, 'Stage 2 merged');
    if (d) throw new Error(d);
    log('info', `Stage 2 PASS: update()-produced Program NCA merge == real update merge (${dataLevelSize.toLocaleString()} bytes byte-identical)`);
}

baseReader.close();
updateReader.close();
console.log('\nPASS: own-BKTR packer (Stardew NSZ) — structure, determinism and full byte-equality.');