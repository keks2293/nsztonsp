// Stardew reloc diagnostic: check whether the base non-patch runs are in
// PHYSICAL order in virtual (reloc/entry) order — the precondition for the
// lockstep base merge (NczStreamSource.stream). Stricter than registerRange's
// sort+merge monotonicity: consecutive base runs (entry order, patches skipped)
// must satisfy start[i+1] >= end[i] (no backward jump, no overlap/nesting), so a
// single sequential NCZ pass can feed them without seeking.
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

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));

const baseReader = new FileReader(`${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`);
const updateReader = new FileReader(`${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`);
const baseC = await openContainer({ reader: baseReader, name: 'base' });
const updateC = await openContainer({ reader: updateReader, name: 'update' });

const cands = (c) => c.entries
    .filter(e => /\.(nca|ncz)$/i.test(e.name) && !/\.cnmt\.(nca|ncz)$/i.test(e.name))
    .sort((a, b) => b.size - a.size);
const baseProg = cands(baseC)[0];
const updateProg = cands(updateC)[0];
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

const updateFsHdr = fsHeaderAt(updateDecHeader, updateRomfsSecIdx);
const relocHeader = parseBktrHeader(updateFsHdr, FS_HDR.PATCH_INFO);
const relocAbsOffset = updateRomfsSec.offset + relocHeader.offset;
console.log('reloc at', '0x' + relocAbsOffset.toString(16), 'size', relocHeader.size);

const updateTitlekey = (updateTik && extractTitlekeyFromTik(updateTik, keys, updateHeaderDec.rightsId, updateDecHeader)) || deriveTitlekeyFromKeyArea(updateDecHeader, keys);
const baseTitlekey = (baseTik && extractTitlekeyFromTik(baseTik, keys, baseHeaderDec.rightsId, baseDecHeader)) || deriveTitlekeyFromKeyArea(baseDecHeader, keys);
const updateNonce = reversedSectionCtr(updateFsHdr);

const updateSource = new NczStreamSource(new AdapterNCZReader(updateReader, updateProg.offset, updateProg.size), updateHdr.parsed, () => {});
updateSource.registerRange(relocAbsOffset, relocHeader.size);
const relocBuf = await decryptBktrTableData(await updateSource.read(relocAbsOffset, relocHeader.size), updateTitlekey, updateNonce, relocAbsOffset);
const relocBlock = parseRelocationBlock(relocBuf);
console.log('\nreloc entries:', relocBlock.entries.length, 'totalSize:', relocBlock.totalSize, '0x' + relocBlock.totalSize.toString(16));

// Base runs in ENTRY (virtual) order — what the lockstep merge would consume.
const baseRuns = [];
let patchBytes = 0, baseBytes = 0;
for (let i = 0; i < relocBlock.entries.length; i++) {
    const e = relocBlock.entries[i];
    const nextVirt = i + 1 < relocBlock.entries.length ? relocBlock.entries[i + 1].virtOffset : relocBlock.totalSize;
    const len = nextVirt - e.virtOffset;
    if (e.isPatch) { patchBytes += len; continue; }
    baseBytes += len;
    baseRuns.push({
        virtStart: e.virtOffset,
        physStart: baseRomfsSecMeta.offset + e.physOffset,
        physEnd: baseRomfsSecMeta.offset + e.physOffset + len,
    });
}
console.log(`base runs: ${baseRuns.length}  baseBytes=${baseBytes} (${(baseBytes / 1048576).toFixed(1)} MiB)  patchBytes=${patchBytes} (${(patchBytes / 1048576).toFixed(1)} MiB)`);

// Lockstep precondition: entry order == physical order, no overlap.
let violations = 0, firstViol = null, gaps = 0, gapBytes = 0;
for (let i = 1; i < baseRuns.length; i++) {
    const prev = baseRuns[i - 1], cur = baseRuns[i];
    if (cur.physStart < prev.physEnd) {
        violations++;
        if (!firstViol) firstViol = { i, prev, cur };
    } else {
        const g = cur.physStart - prev.physEnd;
        if (g > 0) { gaps++; gapBytes += g; }
    }
}
console.log(`\nentry-order lockstep violations (cur.start < prev.end): ${violations}`);
console.log(`physical gaps between consecutive base runs: ${gaps} totaling ${gapBytes} (${(gapBytes / 1048576).toFixed(1)} MiB) — skipped (consumed+discarded) in lockstep`);
if (firstViol) {
    console.log('FIRST violation:', JSON.stringify({
        i: firstViol.i,
        prev: { physStart: '0x' + firstViol.prev.physStart.toString(16), physEnd: '0x' + firstViol.prev.physEnd.toString(16) },
        cur: { physStart: '0x' + firstViol.cur.physStart.toString(16), physEnd: '0x' + firstViol.cur.physEnd.toString(16) },
    }));
}
const span = baseRuns.length ? baseRuns[baseRuns.length - 1].physEnd - baseRuns[0].physStart : 0;
console.log(`first run start 0x${baseRuns[0]?.physStart.toString(16)}  last run end 0x${baseRuns[baseRuns.length - 1]?.physEnd.toString(16)}  span=${span} (${(span / 1048576).toFixed(1)} MiB)`);
console.log(violations === 0
    ? '→ base is MONOTONIC in entry order: lockstep merge is viable ✓'
    : '→ base is NOT monotonic in entry order: lockstep must fall back to registerRange ✗');
baseReader.close(); updateReader.close();
