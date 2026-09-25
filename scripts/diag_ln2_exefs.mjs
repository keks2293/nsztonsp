// Diagnostic: reproduce Pass-1 ExeFS streaming for Little Nightmares II update.
// Opens the update container (NSP or NSZ), finds the Program NCA, and runs the
// same extractExefsStream path the two-pass update uses, printing the section
// metadata and the first bytes of the streamed ExeFS (must start with 'PFS0').
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { FileRangeSource, ViewRangeSource, SparseNcaView } from '../fs/range-source.js';
import { extractExefsStream } from '../fs/nca-pack.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import {
    fsHeaderAt, sectionMedia, FS_HDR, NCA_HEADER_SIZE, NCA_HDR,
    decryptNcaHeaderBytes, resolveTitlekey, reversedSectionCtr,
    findExefsFsHeader, findRomfsFsHeader,
    SECTION_FS_TYPE, SECTION_CRYPTO_TYPE,
} from '../fs/nca-utils.js';
import { readLeU64 } from '../fs/bytes.js';
import { AesEcb } from '../crypto/aes128.js';

class FileReader {
    constructor(path) {
        this.path = path;
        this.fd = fs.openSync(path, 'r');
        this.size = fs.statSync(path).size;
    }
    async read(offset, size) {
        const buf = Buffer.alloc(size);
        fs.readSync(this.fd, buf, 0, size, offset);
        return buf;
    }
    close() { fs.closeSync(this.fd); }
}

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const updateNsp = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsp`;
const updateNsz = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

async function listEntries(path) {
    const r = new FileReader(path);
    const magic = await r.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m !== 'PFS0') throw new Error(`not PFS0: ${m}`);
    const pfs0 = await PFS0.open(r);
    const entries = pfs0.getFiles();
    r.close();
    return entries;
}

async function findProgramNca(path) {
    const entries = await listEntries(path);
    const r = new FileReader(path);
    let found = null;
    for (const e of entries) {
        if (!e.name.toLowerCase().endsWith('.nca') || e.name.toLowerCase().endsWith('.cnmt.nca')) continue;
        const raw = await r.read(e.offset, Math.min(e.size, NCA_HEADER_SIZE));
        let h;
        try { h = decryptNcaHeader(raw, keys); } catch (_) { h = null; }
        if (!h || h.contentType !== 0) continue;
        found = { entry: e, header: h, reader: r, pfs0Raw: null };
        break;
    }
    if (!found) { r.close(); throw new Error('no Program NCA found'); }
    return found;
}

async function findTik(path) {
    const entries = await listEntries(path);
    const r = new FileReader(path);
    let tik = null;
    for (const e of entries) {
        if (e.name.toLowerCase().endsWith('.tik')) {
            tik = await r.read(e.offset, e.size);
            break;
        }
    }
    r.close();
    return tik;
}

function dumpSectionMeta(decHeader, label) {
    console.log(`\n--- ${label}: section info from decrypted header ---`);
    for (let i = 0; i < 4; i++) {
        const fh = fsHeaderAt(decHeader, i);
        const ht = fh[FS_HDR.HASH_TYPE];
        if (ht === 0) continue;
        const ct = fh[FS_HDR.CRYPTO_TYPE];
        const { mediaOffset, mediaEnd } = sectionMedia(decHeader, i);
        console.log(
            `  sec[${i}] hash_type=${ht} (${ht === SECTION_FS_TYPE.PFS0 ? 'PFS0' : ht === SECTION_FS_TYPE.ROMFS ? 'ROMFS' : '?'})` +
            ` crypto_type=${ct} (${ct === SECTION_CRYPTO_TYPE.NONE ? 'NONE' : ct === SECTION_CRYPTO_TYPE.AES_CTR ? 'AES_CTR' : ct === SECTION_CRYPTO_TYPE.BKTR ? 'BKTR' : '?'})` +
            ` media=0x${(mediaOffset * 0x200).toString(16)}..0x${(mediaEnd * 0x200).toString(16)}` +
            ` pfs0Offset=0x${readLeU64(fh, FS_HDR.PFS0_OFFSET).toString(16)} pfs0Size=0x${readLeU64(fh, FS_HDR.PFS0_SIZE).toString(16)}` +
            ` ctr(rev)=${Buffer.from(reversedSectionCtr(fh)).toString('hex')}`);
    }
}

// Stream ExeFS via the same parseExefsSectionMeta logic; print first chunk bytes.
async function streamExefsAndShow(updateInput, tikData, label) {
    const chunk0 = Buffer.from('(empty)');
    let firstChunk = null;
    try {
        await extractExefsStream(updateInput, keys, tikData, (chunk, off) => {
            if (firstChunk === null && off === 0) {
                firstChunk = Buffer.from(chunk.subarray(0, Math.min(chunk.length, 0x40)));
            }
        });
    } catch (e) {
        console.log(`  [${label}] extractExefsStream ERROR: ${e.message}`);
        return;
    }
    const magic = firstChunk ? firstChunk.toString('ascii', 0, 4) : '(no chunk)';
    console.log(`  [${label}] first chunk magic: ${JSON.stringify(magic)} first bytes: ${firstChunk ? firstChunk.toString('hex', 0, 16) : ''}`);
}

function showTitlekeys(decHeader, tikData, label) {
    const rightsIdRaw = decHeader.subarray(NCA_HDR.RIGHTS_ID, NCA_HDR.RIGHTS_ID + 0x10);
    const rightsId = Buffer.from(rightsIdRaw).toString('hex');
    console.log(`  [${label}] rightsId=${rightsId}`);
    if (tikData) {
        const tk = resolveTitlekey(tikData, decHeader, keys);
        const tikRid = Buffer.from(tikData.subarray(0x2A0, 0x2B0)).toString('hex');
        console.log(`  [${label}] tik rightsId=${tikRid} titlekey=${tk ? Buffer.from(tk).toString('hex') : 'N/A'}`);
        if (tikRid.toLowerCase() !== rightsId.toLowerCase()) {
            console.log(`  [${label}] !! tik rightsId MISMATCH header rightsId`);
        }
    } else {
        console.log(`  [${label}] no .tik found`);
        const tk = resolveTitlekey(null, decHeader, keys);
        console.log(`  [${label}] key-area titlekey=${tk ? Buffer.from(tk).toString('hex') : 'N/A'}`);
    }
}

// Direct decrypt test: read raw ciphertext of the ExeFS section media start,
// decrypt AES-CTR with titlekey / ctr, and show the first bytes.
async function directDecryptTest(entry, reader, decHeader, tikData, label) {
    const fh = fsHeaderAt(decHeader, 0); // ExeFS is section 0 in this NCA
    const { mediaOffset } = sectionMedia(decHeader, 0);
    const sectionOffset = mediaOffset * 0x200;
    const sectionStart = readLeU64(fh, FS_HDR.PFS0_OFFSET);
    const ctrRev = reversedSectionCtr(fh);
    const titlekey = resolveTitlekey(tikData, decHeader, keys);
    console.log(`  [${label}] ExeFS sec[0]: media=0x${sectionOffset.toString(16)} pfs0Data=0x${(sectionOffset + sectionStart).toString(16)} ctr(rev)=${Buffer.from(ctrRev).toString('hex')} titlekey=${titlekey ? Buffer.from(titlekey).toString('hex') : 'N/A'}`);

    // Raw ciphertext at the PFS0 data offset (absolute NCA offset).
    const rawOff = sectionOffset + sectionStart;
    const raw = await reader.read(entry.offset + rawOff, 0x20);
    console.log(`  [${label}] raw ciphertext @$0x${rawOff.toString(16)}: ${raw.toString('hex')} ascii=${JSON.stringify(raw.toString('ascii', 0, 4))}`);

    // Decrypt with AesCtr seeked at the PFS0 data offset (same as streamNcaSection).
    const c = new AesCtr(titlekey, ctrRev);
    c.seek(rawOff);
    const dec = await c.decrypt(raw);
    console.log(`  [${label}] decrypted @0x${rawOff.toString(16)}: ${Buffer.from(dec).toString('hex')} magic=${JSON.stringify(Buffer.from(dec).toString('ascii', 0, 4))}`);

    // Try decrypting from section start (zero offset) for comparison.
    const c2 = new AesCtr(titlekey, ctrRev);
    c2.seek(sectionOffset);
    const dec2 = await c2.decrypt(raw);
    console.log(`  [${label}] decrypted @secStart 0x${sectionOffset.toString(16)}: ${Buffer.from(dec2).toString('hex')} magic=${JSON.stringify(Buffer.from(dec2).toString('ascii', 0, 4))}`);

    // AES-CTR-EX: 16-byte counter = head (from FsHeader) + block index BE64.
    // head[0:8] = reversed section_ctr (as AesCtr would take it); try variants.
    const headRev = ctrRev;
    const headRaw = reversedSectionCtr0(fh);
    for (const [hname, head] of [['revCtr', headRev], ['rawCtr', headRaw]]) {
        for (const base of [rawOff, sectionOffset]) {
            const out = new Uint8Array(0x20);
            const counter = new Uint8Array(16);
            counter.set(head, 0);
            const aes = new AesEcb(titlekey);
            for (let pos = 0; pos < 0x20; pos += 16) {
                let tmp = (base + pos) / 16;
                for (let j = 15; j >= 8; j--) { counter[j] = tmp & 0xFF; tmp >>= 8; }
                const ks = aes.encryptBlock(counter);
                for (let i = 0; i < 16; i++) out[pos + i] = raw[pos + i] ^ ks[i];
            }
            const mag = Buffer.from(out).toString('ascii', 0, 4);
            console.log(`  [${label}] AES-CTR-EX head=${hname} base=0x${base.toString(16)}: ${Buffer.from(out).toString('hex')} magic=${JSON.stringify(mag)}`);
        }
    }
}

function reversedSectionCtr0(fsHdr) {
    const raw = fsHdr.subarray(FS_HDR.SECTION_CTR, FS_HDR.SECTION_CTR + 8);
    return new Uint8Array(raw); // non-reversed
}

console.log('========== UPDATE NSP path ==========');
{
    const { entry, header, reader } = await findProgramNca(updateNsp);
    console.log(`Program NCA: ${entry.name} offset=0x${entry.offset.toString(16)} size=0x${entry.size.toString(16)}`);
    const rawHeader = await reader.read(entry.offset, NCA_HEADER_SIZE);
    const decHeader = decryptNcaHeaderBytes(rawHeader, keys);
    dumpSectionMeta(decHeader, 'update NSP');
    const tikData = await findTik(updateNsp);
    showTitlekeys(decHeader, tikData, 'update NSP');
    await directDecryptTest(entry, reader, decHeader, tikData, 'update NSP');
    const updateInput = { headerRaw: rawHeader, source: FileRangeSource(reader, entry.offset, entry.size) };
    await streamExefsAndShow(updateInput, tikData, 'NSP FileRangeSource');
    reader.close();
}

console.log('\n========== UPDATE NSZ path ==========');
{
    const entries = await listEntries(updateNsz);
    const prog = entries.find(e => e.name.toLowerCase().endsWith('.ncz'));
    if (!prog) throw new Error('no .ncz in update NSZ');
    console.log(`Program NCZ: ${prog.name} offset=0x${prog.offset.toString(16)} size=0x${prog.size.toString(16)}`);
    const reader = new FileReader(updateNsz);
    const nczReader = new AdapterNCZReader(reader, prog.offset, prog.size);
    const parsed = await parseNczSections(nczReader);
    console.log(`NCZ ncaSize=0x${parsed.ncaSize.toString(16)} sections=${parsed.sections.length}`);

    // Reuse the same header read + section layout as update.js two-pass path.
    const uHdr = await (async () => {
        if (parsed.ncaHeader) {
            return { raw: await reader.read(prog.offset, Math.min(prog.size, NCA_HEADER_SIZE)), parsed };
        }
        throw new Error('legacy NCZ layout not handled in diag');
    })();
    const rawHeader = uHdr.raw;
    const updateHeaderDec = decryptNcaHeader(rawHeader, keys);
    dumpSectionMeta(decryptNcaHeaderBytes(rawHeader, keys), 'update NSZ');

    const romfsSec = updateHeaderDec.sections.find(s => s.fsType === SECTION_FS_TYPE.ROMFS && s.cryptoType === SECTION_CRYPTO_TYPE.BKTR);
    const exefsSec = updateHeaderDec.sections.find(s => s.fsType === SECTION_FS_TYPE.PFS0);
    if (!exefsSec) throw new Error('no ExeFS section');
    const updRanges = [];
    if (romfsSec) updRanges.push({ offset: romfsSec.offset, size: romfsSec.endOffset - romfsSec.offset });
    updRanges.push({ offset: exefsSec.offset, size: exefsSec.endOffset - exefsSec.offset });
    console.log(`extracting sections: ${updRanges.map(r => `[0x${r.offset.toString(16)}..0x${(r.offset + r.size).toString(16)})`).join(', ')}`);

    // extractNcaSections equivalent (NCZ is sequential; one pass for all ranges)
    const buffers = updRanges.map(r => new Uint8Array(r.size));
    const filled = updRanges.map(() => 0);
    const decomp = new NCZDecompressor(nczReader);
    try {
        await decomp.decompress(
            () => {},
            (chunk, offset) => {
                const lastEnd = updRanges[updRanges.length - 1].offset + updRanges[updRanges.length - 1].size;
                if (offset >= lastEnd) throw new Error('SECTIONS_COMPLETE');
                for (let i = 0; i < updRanges.length; i++) {
                    const r = updRanges[i];
                    const chunkEnd = offset + chunk.length;
                    if (chunkEnd <= r.offset) continue;
                    if (offset >= r.offset + r.size) continue;
                    const startInChunk = Math.max(0, r.offset - offset);
                    const endInChunk = Math.min(chunk.length, r.offset + r.size - offset);
                    const data = chunk.subarray(startInChunk, endInChunk);
                    const target = offset - r.offset + startInChunk;
                    buffers[i].set(data, target);
                    filled[i] += data.length;
                }
            },
            parsed,
        );
    } catch (e) {
        if (e.message !== 'SECTIONS_COMPLETE') throw e;
    }
    for (let i = 0; i < updRanges.length; i++) {
        console.log(`  section[${i}] filled ${filled[i]}/${updRanges[i].size}`);
    }

    const updateSections = [];
    let u = 0;
    if (romfsSec) updateSections.push({ offset: romfsSec.offset, data: buffers[u++] });
    updateSections.push({ offset: exefsSec.offset, data: buffers[u++] });
    const view = new SparseNcaView(rawHeader, updateSections);
    const updateInput = { headerRaw: rawHeader, source: ViewRangeSource(view) };
    const tikData = await findTik(updateNsz);
    await streamExefsAndShow(updateInput, tikData, 'NSZ SparseNcaView');
}

console.log('\ndone');