// Lightweight LN2 reloc diagnostic: read ONLY the update's reloc table
// (~10 MB decompress) and check whether the base non-patch ranges are
// monotonic in virtual (reloc) order — the invariant NczStreamSource.registerRange
// enforces and mergeRomFS (virtual-order merge) relies on.
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader } from '../fs/nca.js';
import {
    decryptNcaHeaderBytes, fsHeaderAt, reversedSectionCtr, FS_HDR,
    SECTION_FS_TYPE, SECTION_CRYPTO_TYPE, NCA_HEADER_SIZE,
    extractTitlekeyFromTik, deriveTitlekeyFromKeyArea,
} from '../fs/nca-utils.js';
import { AdapterNCZReader, parseNczSections, NCZDecompressor } from '../fs/ncz.js';
import { parseBktrHeader, parseRelocationBlock, decryptBktrTableData } from '../fs/bktr.js';
import { NczStreamSource } from '../fs/range-source.js';

class FileReader {
    constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
    async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }
    close() { fs.closeSync(this.fd); }
}

async function readPlaintextNcaHeader(reader, src) {
    if (!src.name.toLowerCase().endsWith('.ncz')) {
        return { raw: await reader.read(src.offset, Math.min(src.size, NCA_HEADER_SIZE)), parsed: null };
    }
    const nczReader = new AdapterNCZReader(reader, src.offset, src.size);
    const parsed = await parseNczSections(nczReader);
    let raw;
    if (parsed.ncaHeader) {
        raw = await reader.read(src.offset, Math.min(src.size, NCA_HEADER_SIZE));
    } else {
        raw = new Uint8Array(NCA_HEADER_SIZE);
        const decomp = new NCZDecompressor(nczReader);
        await decomp.decompress(() => {}, (chunk, offset) => {
            if (offset >= NCA_HEADER_SIZE) return;
            const end = Math.min(offset + chunk.length, NCA_HEADER_SIZE);
            raw.set(chunk.subarray(0, end - offset), offset);
        }, parsed);
    }
    return { raw, parsed };
}

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));

const baseReader = new FileReader(`${DIR}/Little Nightmares II [010097100EDD6000][v0] (4.99 GB).nsz`);
const updateReader = new FileReader(`${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`);
const baseC = await openContainer({ reader: baseReader, name: 'base' });
const updateC = await openContainer({ reader: updateReader, name: 'update' });

const cands = (c, label) => c.entries
    .filter(e => /\.(nca|ncz)$/i.test(e.name) && !/\.cnmt\.(nca|ncz)$/i.test(e.name))
    .sort((a, b) => b.size - a.size);
console.log('\n-- base program candidates --');
for (const e of cands(baseC, 'base').slice(0, 4)) console.log('   ', e.name, e.size);
console.log(`-- update program candidates --`);
for (const e of cands(updateC, 'update').slice(0, 4)) console.log('   ', e.name, e.size);
// Program NCA ids from the production run log.
const baseProg = cands(baseC, 'base').find(e => e.name.toLowerCase().startsWith('00151e9246acb051b7ca0709a1ccd2ce')) || cands(baseC, 'base')[0];
const updateProg = cands(updateC, 'update').find(e => e.name.toLowerCase().startsWith('a7c01cd65310380c151f3dc7a86fe03f')) || cands(updateC, 'update')[0];
console.log('baseProg  ', baseProg.name, baseProg.size);
console.log('updateProg', updateProg.name, updateProg.size);

const baseHdr = await readPlaintextNcaHeader(baseReader, baseProg);
const updateHdr = await readPlaintextNcaHeader(updateReader, updateProg);
const baseHeaderDec = decryptNcaHeader(baseHdr.raw, keys);
const updateHeaderDec = decryptNcaHeader(updateHdr.raw, keys);
const baseDecHeader = decryptNcaHeaderBytes(baseHdr.raw, keys);
const updateDecHeader = decryptNcaHeaderBytes(updateHdr.raw, keys);

const tik = (c, reader) => { const e = c.entries.find(x => x.name.toLowerCase().endsWith('.tik')); return e ? reader.read(e.offset, e.size) : null; };
const baseTik = await tik(baseC, baseReader), updateTik = await tik(updateC, updateReader);

const baseRomfsSec = baseHeaderDec.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS);
const baseRomfsSecMeta = { offset: baseRomfsSec.offset, size: baseRomfsSec.size, secIdx: baseHeaderDec.sections.indexOf(baseRomfsSec) };
const updateRomfsSec = updateHeaderDec.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
const updateRomfsSecIdx = updateHeaderDec.sections.indexOf(updateRomfsSec);
console.log('base romfs section', '0x' + baseRomfsSecMeta.offset.toString(16), baseRomfsSecMeta.size);
console.log('update romfs section', '0x' + updateRomfsSec.offset.toString(16), updateRomfsSec.size);

const updateFsHdr = fsHeaderAt(updateDecHeader, updateRomfsSecIdx);
const relocHeader = parseBktrHeader(updateFsHdr, FS_HDR.PATCH_INFO);
const relocAbsOffset = updateRomfsSec.offset + relocHeader.offset;
console.log('reloc at', '0x' + relocAbsOffset.toString(16), 'size', relocHeader.size);

const updateTitlekey = (updateTik && extractTitlekeyFromTik(updateTik, keys, updateHeaderDec.rightsId, updateDecHeader)) || deriveTitlekeyFromKeyArea(updateDecHeader, keys);
const baseTitlekey = (baseTik && extractTitlekeyFromTik(baseTik, keys, baseHeaderDec.rightsId, baseDecHeader)) || deriveTitlekeyFromKeyArea(baseDecHeader, keys);
const updateNonce = reversedSectionCtr(updateFsHdr);
console.log('updateTitlekey', updateTitlekey && Buffer.from(updateTitlekey).toString('hex').slice(0, 16));
console.log('baseTitlekey', baseTitlekey && Buffer.from(baseTitlekey).toString('hex').slice(0, 16));

const updateSource = new NczStreamSource(new AdapterNCZReader(updateReader, updateProg.offset, updateProg.size), updateHdr.parsed, () => {});
updateSource.registerRange(relocAbsOffset, relocHeader.size);
const relocBuf = await decryptBktrTableData(await updateSource.read(relocAbsOffset, relocHeader.size), updateTitlekey, updateNonce, relocAbsOffset);
const relocBlock = parseRelocationBlock(relocBuf);
console.log('\nreloc entries:', relocBlock.entries.length, 'totalSize:', relocBlock.totalSize, '0x' + relocBlock.totalSize.toString(16));

// Exactly replicate mergeRomFS's base-range registration order + registerRange check.
const entries = relocBlock.entries.map((e, i) => ({
    ...e,
    nextVirt: i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize,
}));
let lastEnd = -1, violations = 0, firstViol = null;
let baseBytes = 0, patchBytes = 0, nonPatchCount = 0;
for (const e of entries) {
    const len = e.nextVirt - e.virtOffset;
    if (e.isPatch) { patchBytes += len; continue; }
    nonPatchCount++;
    const start = baseRomfsSecMeta.offset + e.physOffset;
    const end = start + len;
    baseBytes += len;
    if (start < lastEnd) { violations++; if (!firstViol) firstViol = { e, start, lastEnd }; }
    lastEnd = Math.max(lastEnd, end);
}
console.log(`\nnonPatch base ranges: ${nonPatchCount}  baseBytes=${baseBytes} patchBytes=${patchBytes}`);
console.log(`registerRange violations in VIRTUAL (entry) order (start < last.end): ${violations}`);

// Replicate registerBaseRanges (fs/bktr-merge.js): sort by start, merge
// overlapping/nested ranges into their union, then confirm the result is
// strictly increasing (so NczStreamSource.registerRange will not throw).
const physRanges = [];
for (const e of entries) {
    if (e.isPatch) continue;
    physRanges.push({ start: baseRomfsSecMeta.offset + e.physOffset, end: baseRomfsSecMeta.offset + e.physOffset + (e.nextVirt - e.virtOffset) });
}
physRanges.sort((a, b) => a.start - b.start);
const merged = [];
for (const r of physRanges) {
    const last = merged[merged.length - 1];
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
    else merged.push({ start: r.start, end: r.end });
}
let mergedViol = 0;
for (let i = 1; i < merged.length; i++) {
    if (merged[i].start < merged[i - 1].end) mergedViol++;
}
const mergedBytes = merged.reduce((s, r) => s + (r.end - r.start), 0);
const span = physRanges.length ? physRanges[physRanges.length - 1].end - physRanges[0].start : 0;
console.log(`  raw base ranges=${physRanges.length}  → merged (union) ranges=${merged.length}`);
console.log(`  referenced bytes (sum, overlaps counted)=${baseBytes}  merged (dedup) bytes=${mergedBytes}  physical span=${span}`);
console.log(`  registerRange violations after merge (start < prev.end): ${mergedViol}`);
console.log(mergedViol === 0
    ? '  → merged registration is strictly increasing: NczStreamSource will NOT throw ✓'
    : '  → STILL non-monotonic after merge — genuine overlapping base data ✗');
if (firstViol) {
    console.log('FIRST violation entry:', JSON.stringify({
        virt: firstViol.e.virtOffset, virtHex: '0x' + firstViol.e.virtOffset.toString(16),
        phys: firstViol.e.physOffset, physHex: '0x' + firstViol.e.physOffset.toString(16),
        runLen: firstViol.e.nextVirt - firstViol.e.virtOffset,
        rangeStart: firstViol.start, rangeStartHex: '0x' + firstViol.start.toString(16),
        lastEnd: firstViol.lastEnd, lastEndHex: '0x' + firstViol.lastEnd.toString(16),
    }));
}
console.log('\nfirst 10 non-patch ranges (virtual order):');
let n = 0;
for (const e of entries) {
    if (!e.isPatch && n < 10) {
        console.log(`  [${n}] virt=0x${e.virtOffset.toString(16).padStart(8, '0')} phys=0x${e.physOffset.toString(16).padStart(8, '0')} len=${e.nextVirt - e.virtOffset}`);
        n++;
    }
}
baseReader.close(); updateReader.close();
