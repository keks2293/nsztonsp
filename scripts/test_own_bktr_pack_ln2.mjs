// Own-BKTR packer on LOLLIPOP-level data (Little Nightmares II NSZ — merged
// RomFS ~5.2 GiB, the original SW crash case: the update's single BKTR section
// exceeds the platform ArrayBuffer ceiling, so the whole section can never be
// materialized).
//
// This test computes the own-BKTR layout and contentId (streams; no section
// buffer), then runs the Pass-2 writer against a counting adapter that DROPS the
// data region but captures the header, ExeFS hash table and the encrypted
// reloc/sub tables. Structural checks verify:
//   - own FsHeader (version=2, fs/hash/crypto types, superblock verbatim,
//     PatchInfo placement, gen/secv);
//   - key-area-slot-2 titlekey round-trips out of our header;
//   - reloc table: 8+ buckets, entry count == real update, virtual offsets and
//     totalSize preserved (incl. the pre-dataStart window), all isPatch=1,
//     output phys inside [0, dataRegionSize), 16-aligned;
//   - sub table: single subsection [0, dataRegionSize) with ctrVal=0;
//   - virtual coverage: the reader's emit window [dataLevelOffset,
//     dataLevelOffset+dataLevelSize) fits inside [0, totalSize).
//
// No full-length buffer is ever allocated. Run from scripts/:
//   node test_own_bktr_pack_ln2.mjs

import fs from 'fs';
import { KeysParser } from '../keys.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { NczStreamSource } from '../fs/range-source.js';
import { AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import {
    decryptNcaHeaderBytes, fsHeaderAt, deriveTitlekeyFromKeyArea, reversedSectionCtr,
    FS_HDR, SECTION_FS_TYPE, SECTION_CRYPTO_TYPE, NCA_HDR,
} from '../fs/nca-utils.js';
import { parseBktrHeader, decryptBktrTableData, parseRelocationBlock, parseSubsectionBlock } from '../fs/bktr.js';
import { resolveBktrMeta, readBktrTables } from '../fs/bktr-merge.js';
import { readLeU32, readLeU64 } from '../fs/bytes.js';
import { extractExefsStream } from '../fs/nca-pack.js';
import { computeOwnBktrContentId, writeOwnBktrProgramNca } from '../fs/bktr-pack.js';

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const basePath = `${DIR}/Little Nightmares II [010097100EDD6000][v0] (4.99 GB).nsz`;
const updatePath = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`;

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const log = (level, msg) => console.log(`[${level.toUpperCase()}] ${msg}`);
const progress = () => {};

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

const updateHdr = decryptNcaHeader(updateHeaderRaw, keys);
const bktrIdx = updateHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
if (bktrIdx < 0) throw new Error('update has no BKTR romfs section');
const updateDec = decryptNcaHeaderBytes(updateHeaderRaw, keys);
const updFh = fsHeaderAt(updateDec, bktrIdx);
const exefsIdx = updateHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.PFS0);
const updExefsFh = fsHeaderAt(updateDec, exefsIdx);
const exefsSize = readLeU64(updExefsFh, FS_HDR.PFS0_SIZE);
const titleId = decryptNcaHeader(baseHeaderRaw, keys).titleId.toLowerCase();
const dataLevelOffset = readLeU64(updFh, 0x18 + 5 * 0x18);
const dataLevelSize = readLeU64(updFh, 0x18 + 5 * 0x18 + 8);
log('info', `LN2: exefs=0x${exefsSize.toString(16)} dataLevel offset=0x${dataLevelOffset.toString(16)} size=0x${dataLevelSize.toString(16)}`);

const updateCtx = { headerRaw: updateHeaderRaw, source: null, reader: updateNcz, parsed: updateParsed, streamable: true };
const makeUpdateSource = (ranges, onProgress, opts = {}) => {
    const src = new NczStreamSource(updateCtx.reader, updateCtx.parsed, log, onProgress);
    if (opts.register !== false) for (const r of ranges) src.registerRange(r.off, r.len);
    return src;
};
const makeBaseSource = () => new NczStreamSource(baseNcz, baseParsed, log);
// ExeFS streams from its own one-shot NCZ pass registered with just the ExeFS
// range (mirrors updateSource in update.js two-pass NCZ branch).
const exefsSec = updateHdr.sections[exefsIdx];
const makeStreamExefs = () => {
    const src = new NczStreamSource(updateNcz, updateParsed, log);
    src.registerRange(exefsSec.offset, exefsSec.endOffset - exefsSec.offset);
    return src;
};
const streamExefs = (emit) => extractExefsStream({ headerRaw: updateHeaderRaw, source: makeStreamExefs() }, keys, updateTik, emit);

// Real tables for comparison.
let realRelocEntries, realTotalSize, realSubEntries;
{
    const metaR = await resolveBktrMeta({ headerRaw: baseHeaderRaw }, { headerRaw: updateHeaderRaw }, { keys, baseTik, updateTik });
    const tableRanges = [
        { off: metaR.relocAbsOffset, len: metaR.relocHeader.size },
        { off: metaR.subAbsOffset, len: metaR.subHeader.size },
    ].sort((a, b) => a.off - b.off);
    const { relocBlock: rb, subBlock: sb } = await readBktrTables(makeUpdateSource(tableRanges), metaR);
    realRelocEntries = rb.entries;
    realTotalSize = rb.totalSize;
    realSubEntries = sb.entries;
}
log('info', `real: reloc totalSize=0x${realTotalSize.toString(16)} entries=${realRelocEntries.length}, sub=${realSubEntries.length}`);

const t0 = performance.now();
const { size: ownSize, contentId, meta } = await computeOwnBktrContentId({
    baseNcaData: { headerRaw: baseHeaderRaw }, updateNcaData: { headerRaw: updateHeaderRaw },
    makeUpdateSource, makeBaseSource,
    keys, baseTik, updateTik,
    titleId, exefsSize,
    streamExefs,
    log, progress,
});
log('info', `[timing] compute: ${((performance.now() - t0) / 1000).toFixed(1)}s — ncaSize=0x${ownSize.toString(16)} (${(ownSize / 2 ** 30).toFixed(2)} GiB), contentId=${contentId}`);
if (ownSize !== meta.L.ncaSize) throw new Error('size mismatch');
if (ownSize > 2 ** 31) log('info', 'NB: own NCA exceeds 2 GiB — exactly the case no SW section buffer can hold; the writer streams it.');

// Pass-2 writer with a counting adapter that captures header/htable/tables and
// drops the data region (never materializes it).
const L = meta.L;
const captures = {}; // absPos -> bytes for selected ranges
let totalWritten = 0;
const adapter = {
    write: async (pos, data) => {
        const len = data.byteLength;
        totalWritten += len;
        const abs = pos; // ncaOffset=0
        const keep =
              (abs === 0 && len === 0xC00)                                   // enc header
            || (abs >= 0xC00 && abs + len <= L.sec0Start + L.exeHtableSize && len <= 0x30000) // htable
            || (abs >= L.sec1Start + L.relocOff && abs + len <= L.sec1Start + L.relocOff + L.relocBlockSize) // relocEnc
            || (abs >= L.sec1Start + L.subOff && abs + len <= L.sec1Start + L.subOff + L.subBlockSize);   // subEnc
        if (keep) captures[abs] = data.slice(0);
    },
};
const t1 = performance.now();
await writeOwnBktrProgramNca({
    meta, adapter, ncaOffset: 0, contentId,
    streamExefs, makeUpdateSource, makeBaseSource,
    log, progress,
});
log('info', `[timing] write: ${((performance.now() - t1) / 1000).toFixed(1)}s — ${totalWritten.toLocaleString()} bytes sequential, data region NOT buffered`);
if (totalWritten !== ownSize) throw new Error(`write total ${totalWritten} != ncaSize ${ownSize}`);

// ── Structural verification ──────────────────────────────────────────────────
const encHeader = captures[0];
if (!encHeader || encHeader.length !== 0xC00) throw new Error('header capture missing');
const ownDec = decryptNcaHeaderBytes(encHeader, keys);
const ownHdr = decryptNcaHeader(encHeader, keys);
const ownBktrIdx = ownHdr.sections.findIndex(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
if (ownBktrIdx !== 1) throw new Error(`BKTR section index ${ownBktrIdx}, expected 1`);
const ownFh = fsHeaderAt(ownDec, ownBktrIdx);
const v = new DataView(ownFh.buffer, ownFh.byteOffset, ownFh.byteLength);
if (v.getUint16(0, true) !== 2) throw new Error('fsHeader version != 2');
if (ownFh[0x02] !== 0x00 || ownFh[0x03] !== 0x03 || ownFh[0x04] !== 0x04) throw new Error('fsHeader type bytes mismatch');
if (!bytesEqual(ownFh.subarray(0x08, 0xE8), updFh.subarray(0x08, 0xE8))) throw new Error('superblock [0x08:0xE8) not verbatim');
if (readLeU32(ownFh, FS_HDR.SECURE_VALUE - 4) !== 1 || readLeU32(ownFh, FS_HDR.SECURE_VALUE) !== 2) throw new Error('gen/secv mismatch');
const relocH = parseBktrHeader(ownFh, FS_HDR.PATCH_INFO);
const subH = parseBktrHeader(ownFh, FS_HDR.PATCH_INFO_AESCTREX);
if (relocH.offset !== L.relocOff || relocH.size !== L.relocBlockSize) throw new Error('reloc PatchInfo mismatch');
if (subH.offset !== L.subOff || subH.size !== L.subBlockSize) throw new Error('sub PatchInfo mismatch');

const ourTk = deriveTitlekeyFromKeyArea(ownDec, keys);
if (!ourTk || !bytesEqual(ourTk, meta.ourTitlekey)) throw new Error('deriveTitlekeyFromKeyArea != meta.ourTitlekey');
if (readLeU64(ownDec, NCA_HDR.SIZE) !== ownSize) throw new Error('NCA header size field mismatch');

const relocRaw = captures[L.sec1Start + L.relocOff];
const subRaw = captures[L.sec1Start + L.subOff];
if (!relocRaw || relocRaw.length !== L.relocBlockSize) throw new Error('reloc table capture missing');
if (!subRaw || subRaw.length !== L.subBlockSize) throw new Error('sub table capture missing');
const ourNonce = reversedSectionCtr(ownFh);
const relocPlain = await decryptBktrTableData(relocRaw, ourTk, ourNonce, L.sec1Start + L.relocOff);
const subPlain = await decryptBktrTableData(subRaw, ourTk, ourNonce, L.sec1Start + L.subOff);
const ownReloc = parseRelocationBlock(relocPlain);
const ownSub = parseSubsectionBlock(subPlain);

if (ownReloc.totalSize !== realTotalSize) throw new Error(`reloc totalSize 0x${ownReloc.totalSize.toString(16)} != real 0x${realTotalSize.toString(16)}`);
if (ownReloc.entries.length !== realRelocEntries.length) throw new Error(`reloc entries ${ownReloc.entries.length} != ${realRelocEntries.length}`);
const relocBuckets = Math.ceil(ownReloc.entries.length / 818);
if (relocBuckets < 2) throw new Error('expected multi-bucket reloc layout (LN2 has 8)');
if (L.relocBlockSize !== 0x4000 + relocBuckets * 0x4000) throw new Error('reloc block size mismatch vs bucket count');
const maxPhys = L.relocOff;
for (let i = 0; i < ownReloc.entries.length; i++) {
    const o = ownReloc.entries[i], r = realRelocEntries[i];
    if (o.virtOffset !== r.virtOffset) throw new Error(`virt[${i}] 0x${o.virtOffset.toString(16)} != 0x${r.virtOffset.toString(16)}`);
    if (!o.isPatch) throw new Error(`reloc[${i}] not isPatch`);
    if (o.physOffset >= maxPhys) throw new Error(`reloc[${i}] phys 0x${o.physOffset.toString(16)} outside data region 0x${maxPhys.toString(16)}`);
    if (o.physOffset % 16 !== 0) throw new Error(`reloc[${i}] phys 0x${o.physOffset.toString(16)} not 16-aligned`);
}
// Virtual coverage: the reader's emit window must lie inside [0, totalSize).
if (dataLevelOffset + dataLevelSize > realTotalSize) {
    throw new Error(`emit window [0x${dataLevelOffset.toString(16)}, 0x${(dataLevelOffset + dataLevelSize).toString(16)}) exceeds reloc totalSize 0x${realTotalSize.toString(16)}`);
}
if (ownSub.entries.length !== 2) throw new Error(`sub entries ${ownSub.entries.length}`);
if (ownSub.entries[0].offset !== 0 || ownSub.entries[0].ctrVal !== 0) throw new Error('sub[0] != {0,0}');
if (ownSub.entries[1].offset !== L.relocOff) throw new Error('sub[1].offset != dataRegionSize');
if (ownSub.totalSize !== L.relocOff) throw new Error('sub totalSize != dataRegionSize');

// Section entries.
if (ownHdr.sections[1].offset !== L.sec1Start || ownHdr.sections[1].size !== L.romSectionSize) throw new Error('section 1 entry mismatch');
log('info', `structure OK: reloc=${ownReloc.entries.length} (${relocBuckets} buckets), sub=2, dataRegion=0x${L.relocOff.toString(16)} (${(L.relocOff / 2 ** 30).toFixed(2)} GiB), totalSize preserved, emit window covered`);

baseReader.close();
updateReader.close();
console.log('\nPASS: LN2 own-BKTR structure — no section-sized buffer, tables/layout/coverage correct.');