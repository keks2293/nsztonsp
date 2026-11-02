// XCI→XCZ compression test (fs/compress.js compressXCItoXCZ).
//
// Builds a fully synthetic XCI in memory (no real .xci fixture is available):
//   secure: aaaa PROGRAM NCA (CTR+NONE sections, compressible),
//           bbbb CONTROL NCA (copied), cccc DATA NCA (delta — dropped w/o keep)
//   normal: dddd PROGRAM NCA (compressible — processed only with keep=true)
//   update: empty 0x200 HFS0 stub
//   logo:   empty 0x200 HFS0 stub
// then verifies the XCZ output layout byte-for-byte against the python nsz
// v5 blockCompressXci/XciStream semantics:
//   * [0,0x200) verbatim input header (STALE validDataEndOffset & co)
//   * [0x200,0xF000) zeros
//   * root HFS0 at 0xF000 (actual size, unpadded)
//   * partitions from 0x17000, each size = actualSize + align0x200(actualSize)
//   * keep=false: only "secure" is processed (normal/update/logo → 0x200 stubs)
//   * keep=true:  all partitions processed (delta kept, normal NCA compressed)
// and round-trips the output through decompressXCZ (NCZ→NCA decompression)
// comparing every member byte-for-byte with the original XCI.
//
// Usage: node scripts/test_compress_xci.mjs
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { KeysParser } from '../keys.js';
import { AesEcb, AesXts } from '../crypto/aes128.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { toKeyBytes, deriveTitlekeyFromKeyArea } from '../fs/nca-utils.js';
import { compressXCItoXCZ } from '../fs/compress.js';
import { decompressXCZ } from '../fs/xcz-decompress.js';
import { XCIReader } from '../fs/xci.js';
import { HFS0Reader } from '../fs/hfs0.js';

let passed = 0, failed = 0;
function check(name, ok, detail = '') {
    if (ok) { passed++; console.log(`  ok   ${name}${detail ? ` — ${detail}` : ''}`); }
    else { failed++; console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`); }
}

const sha256 = (u8) => createHash('sha256').update(u8).digest('hex');
const pattern = (len, seed) => { const b = new Uint8Array(len); for (let i = 0; i < len; i++) b[i] = (seed + i * 31 + (i >> 8) * 7) & 0xFF; return b; };

const keys = KeysParser.parse(readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));

// ── Synthetic NCA builders ───────────────────────────────────────────────────
// All headers follow the real layout: signature [0x000,0x200), NCAHeader struct
// at 0x200 (magic@0x200, contentType@0x205, cryptoType@0x206, size@0x208,
// titleId@0x210, cryptoType2@0x220, rightsId@0x224, sections@0x240, key area
// @0x300, FsHeaders @0x400/0x600/0x800/0xA00, counter @FsHeader+0x140 LE).

// PROGRAM NCA, 0xC000: section 0 = PFS0/CTR [0x4000,0x8000) (encrypted with the
// key-area titlekey + fs counter), section 1 = ROMFS/NONE [0x8000,0xC000)
// (plaintext). Non-rights-managed → titlekey comes from the (zero) key area.
async function buildProgramNca(titleIdHex, counterDisk) {
    const ncaSize = 0xC000;
    const h = new Uint8Array(ncaSize);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = 0x00; // PROGRAM
    h[0x206] = 0x01; // NCA crypto type NONE (python numbering) → master key 0
    const dv = new DataView(h.buffer);
    dv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from(titleIdHex, 'hex'), 0x210);
    h[0x220] = 0x00; // cryptoType2
    // Section table (media offsets ×0x200): [0x4000,0x8000) and [0x8000,0xC000)
    dv.setUint32(0x240, 0x20, true); dv.setUint32(0x244, 0x40, true);
    dv.setUint32(0x250, 0x40, true); dv.setUint32(0x254, 0x60, true);
    // FsHeader 0 @0x400: PFS0(2)/CTR(3), counter at +0x140 (8B LE on disk)
    h[0x403] = 0x02; h[0x404] = 0x03;
    h.set(counterDisk, 0x540);
    // FsHeader 1 @0x600: ROMFS(3)/NONE(1)
    h[0x603] = 0x03; h[0x604] = 0x01;
    // Key area @0x300: zero (deterministic derived titlekey)

    const decHeader = h.slice(0, 0x4000);
    const titlekey = deriveTitlekeyFromKeyArea(decHeader, keys);
    const encHeader = new AesXts(toKeyBytes(keys.header_key)).encrypt(h.subarray(0, 0x4000), 0);

    const plain0 = pattern(0x4000, 0x11);
    const plain1 = pattern(0x4000, 0x22);
    // CTR counter head = the 8 disk bytes REVERSED (NCAHeader.parse reverses).
    const ctr16 = new Uint8Array(16);
    for (let i = 0; i < 8; i++) ctr16[i] = counterDisk[7 - i];
    const aesCtr = new AesCtr(titlekey, ctr16, 0);
    aesCtr.seek(0x4000);
    const cipher0 = await aesCtr.encrypt(plain0);

    const nca = new Uint8Array(ncaSize);
    nca.set(encHeader, 0);
    nca.set(cipher0, 0x4000);
    nca.set(plain1, 0x8000);
    return { nca, titlekey, ctr16 };
}

// CONTROL NCA, 0x8000, valid header, no sections → copied verbatim.
function buildControlNca(titleIdHex) {
    const ncaSize = 0x8000;
    const h = new Uint8Array(ncaSize);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = 0x02; // CONTROL
    h[0x206] = 0x01;
    const dv = new DataView(h.buffer);
    dv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from(titleIdHex, 'hex'), 0x210);
    const encHeader = new AesXts(toKeyBytes(keys.header_key)).encrypt(h.subarray(0, 0xC00), 0);
    const nca = new Uint8Array(ncaSize);
    nca.set(encHeader, 0);
    nca.set(pattern(ncaSize - 0xC00, 0x33), 0xC00);
    return nca;
}

// DATA (delta) NCA, 0xC00, header-only → dropped without keep.
function buildDataNca() {
    const ncaSize = 0xC00;
    const h = new Uint8Array(ncaSize);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = 0x04; // DATA
    h[0x206] = 0x01;
    const dv = new DataView(h.buffer);
    dv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from('0100E65002BB8000', 'hex'), 0x210);
    return new AesXts(toKeyBytes(keys.header_key)).encrypt(h, 0);
}

// Rights-managed PROGRAM NCA (rightsId != 0, CTR section) → needs a titlekey
// from a ticket; no ticket in the container → compression must FAIL.
async function buildRightsNca(titleIdHex, rightsIdHex, counterDisk) {
    const ncaSize = 0xC000;
    const h = new Uint8Array(ncaSize);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = 0x00;
    h[0x206] = 0x01;
    const dv = new DataView(h.buffer);
    dv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from(titleIdHex, 'hex'), 0x210);
    h.set(Buffer.from(rightsIdHex, 'hex'), 0x224);
    // Section table (media offsets ×0x200): [0x4000,0x8000) and [0x8000,0xC000)
    dv.setUint32(0x240, 0x20, true); dv.setUint32(0x244, 0x40, true);
    dv.setUint32(0x250, 0x40, true); dv.setUint32(0x254, 0x60, true);
    h[0x403] = 0x02; h[0x404] = 0x03;
    h.set(counterDisk, 0x540);
    h[0x603] = 0x03; h[0x604] = 0x01;
    const encHeader = new AesXts(toKeyBytes(keys.header_key)).encrypt(h.subarray(0, 0x4000), 0);
    const nca = new Uint8Array(ncaSize);
    nca.set(encHeader, 0);
    nca.set(pattern(0x8000, 0x44), 0x4000);
    return nca;
}

// ── Synthetic XCI builders ───────────────────────────────────────────────────
// Input partition: HFS0 header (actual size) at the start, files at
// partition-relative 0x8000; on-disk entry offsets are relative to the header
// end (python Hfs0Stream.getHeader: offset - actualHeaderSize).
function buildInputPartition(entries) {
    // entries: [{ name, data: Uint8Array }]
    const strtab = new TextEncoder().encode(entries.map(e => e.name).join('\0') + '\0');
    const headerSize = 0x10 + entries.length * 0x40 + strtab.length;
    const total = 0x8000 + entries.reduce((s, e) => s + e.data.length, 0);
    const buf = new Uint8Array(total);
    buf.set([0x48, 0x46, 0x53, 0x30], 0);
    const dv = new DataView(buf.buffer);
    dv.setUint32(4, entries.length, true);
    dv.setUint32(8, strtab.length, true);
    let sOff = 0, filePos = 0;
    entries.forEach((e, i) => {
        const pos = 0x10 + i * 0x40;
        dv.setBigUint64(pos, BigInt(0x8000 + filePos - headerSize), true);
        dv.setBigUint64(pos + 8, BigInt(e.data.length), true);
        dv.setUint32(pos + 16, sOff, true);
        sOff += e.name.length + 1;
        filePos += e.data.length;
    });
    buf.set(strtab, 0x10 + entries.length * 0x40);
    let off = 0x8000;
    for (const e of entries) { buf.set(e.data, off); off += e.data.length; }
    return buf;
}

function buildInputRoot(partitionNames, partitionSizes) {
    const strtab = new TextEncoder().encode(partitionNames.join('\0') + '\0');
    const headerSize = 0x10 + partitionNames.length * 0x40 + strtab.length;
    const buf = new Uint8Array(0x8000);
    buf.set([0x48, 0x46, 0x53, 0x30], 0);
    const dv = new DataView(buf.buffer);
    dv.setUint32(4, partitionNames.length, true);
    dv.setUint32(8, strtab.length, true);
    let sOff = 0, cum = 0;
    partitionNames.forEach((name, i) => {
        const pos = 0x10 + i * 0x40;
        dv.setBigUint64(pos, BigInt(0x8000 + cum - headerSize), true);
        dv.setBigUint64(pos + 8, BigInt(partitionSizes[i]), true);
        dv.setUint32(pos + 16, sOff, true);
        sOff += name.length + 1;
        cum += partitionSizes[i];
    });
    buf.set(strtab, 0x10 + partitionNames.length * 0x40);
    return buf;
}

// XCI header [0,0x200): recognizable pattern (so the verbatim-copy check is
// meaningful), HEAD @0x100, hfs0Offset=0xF000, hfs0HeaderSize=0x8000,
// validDataEndOffset left STALE (0x1234) — the compressor must NOT fix it.
function buildXciHeader(hfs0Offset = 0xF000) {
    const h = new Uint8Array(0x200);
    for (let i = 0; i < 0x200; i++) h[i] = (0xA5 + (i * 7) & 0xFF);
    h.set([0x48, 0x45, 0x41, 0x44], 0x100);
    const dv = new DataView(h.buffer);
    dv.setUint32(0x104, 0x17000, true);          // secureOffset
    dv.setUint32(0x108, 0, true);                // backupOffset
    dv.setUint8(0x10C, 0);                        // titleKekIndex
    dv.setUint8(0x10D, 3);                        // gamecardSize
    dv.setUint8(0x10E, 2);                        // gamecardHeaderVersion
    dv.setBigUint64(0x110, 0x0100E65002BB8000n, true); // packageId
    dv.setUint32(0x118, 0x1234, true);            // validDataEndOffset (STALE on purpose)
    dv.setBigUint64(0x130, BigInt(hfs0Offset), true);  // hfs0Offset
    dv.setBigUint64(0x138, 0x8000n, true);        // hfs0HeaderSize
    return h;
}

function assembleXci(partitionSpecs, { hfs0Offset = 0xF000, partBase = hfs0Offset + 0x8000 } = {}) {
    // partitionSpecs: [{ name, entries: [{name, data}] }]
    const parts = partitionSpecs.map(spec => buildInputPartition(spec.entries));
    const root = buildInputRoot(partitionSpecs.map(s => s.name), parts.map(p => p.length));
    const total = partBase + parts.reduce((s, p) => s + p.length, 0);
    const xci = new Uint8Array(total);
    xci.set(buildXciHeader(hfs0Offset), 0);
    xci.set(root, hfs0Offset);
    let off = partBase;
    for (const p of parts) { xci.set(p, off); off += p.length; }
    return xci;
}

const memReader = (blob) => ({ read: async (off, size) => blob.subarray(off, off + size) });
const align0x200 = (n) => 0x200 - (n % 0x200);

// ── Build the fixture ────────────────────────────────────────────────────────
const counterA = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
const counterD = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const aaaa = (await buildProgramNca('0100E65002BB8000', counterA));
const dddd = (await buildProgramNca('0100E65002BB9000', counterD));
const bbbb = buildControlNca('0100E65002BB8000');
const cccc = buildDataNca();

const NAME_AAAA = 'aaaa0000000000000000000000000001.nca';
const NAME_BBBB = 'bbbb0000000000000000000000000002.nca';
const NAME_CCCC = 'cccc0000000000000000000000000003.nca';
const NAME_DDDD = 'dddd0000000000000000000000000004.nca';

const xciIn = assembleXci([
    { name: 'secure', entries: [
        { name: NAME_AAAA, data: aaaa.nca },
        { name: NAME_BBBB, data: bbbb },
        { name: NAME_CCCC, data: cccc },
    ]},
    { name: 'normal', entries: [{ name: NAME_DDDD, data: dddd.nca }] },
    { name: 'update', entries: [] },
    { name: 'logo', entries: [] },
]);

// ── keep=false: only "secure" is processed ──────────────────────────────────
console.log('compressXCItoXCZ keep=false');
{
    const logs = [];
    const res = await compressXCItoXCZ(memReader(xciIn), { memory: true }, {
        keys, keep: false, log: (lvl, msg) => logs.push(msg), progress: () => {},
    });
    const blob = new Uint8Array(await res.blob.arrayBuffer());

    // Expected layout.
    const nczASize = res.memberCount >= 2 ? 0 : 0; // filled in below from the output HFS0
    const secureStart = 0x17000;
    const outXci = new XCIReader(memReader(blob));
    await outXci.parse();
    check('output parses as XCI (HEAD @0x100, root @0xF000)', outXci.headOffset === 0x100 && outXci.hfs0Offset === 0xF000);

    const parts = outXci.getPartitions();
    check('4 partitions, input order', parts.length === 4 && parts.map(p => p.name).join(',') === 'secure,normal,update,logo', parts.map(p => p.name).join(','));

    const secure = parts[0];
    const secureHfs0 = await outXci.readPartitionFiles(secure);
    const secureFiles = secureHfs0.getFiles();
    check('secure: 2 files (delta dropped)', secureFiles.length === 2 && secureFiles[0].name === NAME_AAAA.slice(0, -3) + 'ncz' && secureFiles[1].name === NAME_BBBB,
        secureFiles.map(f => `${f.name}(${f.size})`).join(', '));
    const nczASizeReal = secureFiles[0].size;
    const nczBSize = secureFiles[1].size;

    check('secure: first file at partition-relative 0x8000', secureFiles[0].offset === secure.offset + 0x8000, `0x${secureFiles[0].offset.toString(16)} vs 0x${(secure.offset + 0x8000).toString(16)}`);
    check('secure: files packed contiguously', secureFiles[1].offset === secureFiles[0].offset + nczASizeReal);
    check('secure: copied NCA keeps size', nczBSize === bbbb.length, `${nczBSize} vs ${bbbb.length}`);

    // Partition sizes = actualSize + align0x200(actualSize).
    const secureActual = 0x8000 + nczASizeReal + nczBSize;
    check('secure: root entry size = actualSize + align0x200', secure.size === secureActual + align0x200(secureActual),
        `entry=0x${secure.size.toString(16)} actual=0x${secureActual.toString(16)}`);
    check('secure: partition size 0x200-aligned', secure.size % 0x200 === 0);

    // Stubs: normal/update/logo → 0x200 with a 0-file HFS0 header.
    for (const name of ['normal', 'update', 'logo']) {
        const p = parts.find(x => x.name === name);
        check(`${name}: 0x200 stub`, p.size === 0x200, `0x${p.size.toString(16)}`);
        const stubHfs0 = new HFS0Reader(blob.subarray(p.offset, p.offset + 0x200), p.offset);
        check(`${name}: stub HFS0 has 0 files`, stubHfs0.getFiles().length === 0);
    }

    // normal partition content was DROPPED (python: only secure without keep).
    const skipLog = logs.find(l => l.includes('[SKIP-PARTITION] normal'));
    check('normal: drop logged', !!skipLog, skipLog || 'no log line');

    // Prefix verbatim + zero regions.
    let prefixOk = true;
    for (let i = 0; i < 0x200; i++) if (blob[i] !== xciIn[i]) { prefixOk = false; break; }
    check('[0,0x200) verbatim input header (incl. STALE validDataEndOffset)', prefixOk && blob[0x118] === 0x34 && blob[0x119] === 0x12);
    let zeroGap = true;
    for (let i = 0x200; i < 0xF000; i++) if (blob[i]) { zeroGap = false; break; }
    check('[0x200,0xF000) zeros', zeroGap);

    // Root HFS0: actual size (4 entries + strtab), rest of the region zeros.
    const rootHdr = new HFS0Reader(blob.subarray(0xF000, 0x17000), 0xF000);
    check('root: 4 entries', rootHdr.getFiles().length === 4);
    const expectedRootActual = 0x10 + 4 * 0x40 + 'secure\0normal\0update\0logo\0'.length;
    let rootTailZero = true;
    for (let i = expectedRootActual; i < 0x8000; i++) if (blob[0xF000 + i]) { rootTailZero = false; break; }
    check('root: header unpadded, region zeros to 0x17000', rootTailZero, `actual=0x${expectedRootActual.toString(16)}`);

    // Partition data starts at 0x17000 (root HFS0 attr headerSize = 0x8000).
    check('first partition at 0x17000', secure.offset === 0x17000, `0x${secure.offset.toString(16)}`);

    // Total size.
    const expectedTotal = 0x17000 + secure.size + 0x200 * 3;
    check('total size', res.size === expectedTotal && blob.length === expectedTotal, `res=${res.size} blob=${blob.length} expected=${expectedTotal}`);

    // NCZ section table of the compressed member (NONE-key semantics in XCZ).
    const ncz = blob.subarray(secureFiles[0].offset, secureFiles[0].offset + nczASizeReal);
    check('NCZ: 0x4000 raw header preserved', ncz.subarray(0, 0x4000).every((b, i) => b === aaaa.nca[i]));
    const sectn = ncz.subarray(0x4000);
    check('NCZ: NCZSECTN magic + 2 sections', String.fromCharCode(sectn[0], sectn[1], sectn[2], sectn[3], sectn[4], sectn[5], sectn[6], sectn[7]) === 'NCZSECTN' && Number(new DataView(sectn.buffer, sectn.byteOffset).getBigUint64(8, true)) === 2);
    const dvS = new DataView(sectn.buffer, sectn.byteOffset);
    const e0off = 16, e1off = 16 + 64;
    check('NCZ: entry0 CTR @0x4000/0x4000', Number(dvS.getBigUint64(e0off, true)) === 0x4000 && Number(dvS.getBigUint64(e0off + 8, true)) === 0x4000 && Number(dvS.getBigUint64(e0off + 16, true)) === 3);
    check('NCZ: entry0 key = key-area titlekey', Buffer.from(sectn.subarray(e0off + 32, e0off + 48)).toString('hex') === Buffer.from(aaaa.titlekey).toString('hex'));
    check('NCZ: entry0 counter = [reversed head][00*8]', Buffer.from(sectn.subarray(e0off + 48, e0off + 64)).toString('hex') === Buffer.from(aaaa.ctr16).toString('hex'));
    check('NCZ: entry1 NONE @0x8000/0x4000', Number(dvS.getBigUint64(e1off, true)) === 0x8000 && Number(dvS.getBigUint64(e1off + 8, true)) === 0x4000 && Number(dvS.getBigUint64(e1off + 16, true)) === 1);
    check('NCZ: entry1 (NONE) key = titlekey too', Buffer.from(sectn.subarray(e1off + 32, e1off + 48)).toString('hex') === Buffer.from(aaaa.titlekey).toString('hex'));

    // Round-trip: XCZ → XCI via decompressXCZ, every member byte-identical.
    const back = await decompressXCZ(memReader(blob), { memory: true }, { log: () => {}, progress: () => {}, createHash: () => { const h = createHash('sha256'); return { update: (d) => h.update(d), hex: () => h.digest('hex') }; } });
    const backBlob = new Uint8Array(await back.blob.arrayBuffer());
    const backXci = new XCIReader(memReader(backBlob));
    await backXci.parse();
    const backSecure = backXci.getPartitions().find(p => p.name === 'secure');
    const backSecureHfs0 = await backXci.readPartitionFiles(backSecure);
    const backFiles = backSecureHfs0.getFiles();
    check('round-trip: secure has 2 files (ncz decompressed to nca)', backFiles.length === 2 && backFiles[0].name === NAME_AAAA && backFiles[1].name === NAME_BBBB,
        backFiles.map(f => f.name).join(', '));
    const rtA = backBlob.subarray(backFiles[0].offset, backFiles[0].offset + backFiles[0].size);
    const rtB = backBlob.subarray(backFiles[1].offset, backFiles[1].offset + backFiles[1].size);
    check('round-trip: aaaa byte-identical', sha256(rtA) === sha256(aaaa.nca), sha256(rtA).slice(0, 16) + '…');
    check('round-trip: bbbb byte-identical', sha256(rtB) === sha256(bbbb));
    for (const name of ['normal', 'update', 'logo']) {
        const p = backXci.getPartitions().find(x => x.name === name);
        const h = await backXci.readPartitionFiles(p);
        check(`round-trip: ${name} empty`, h.getFiles().length === 0);
    }
}

// ── keep=true: all partitions processed, delta kept ─────────────────────────
console.log('compressXCItoXCZ keep=true');
{
    const logs = [];
    const res = await compressXCItoXCZ(memReader(xciIn), { memory: true }, {
        keys, keep: true, log: (lvl, msg) => logs.push(msg), progress: () => {},
    });
    const blob = new Uint8Array(await res.blob.arrayBuffer());
    const outXci = new XCIReader(memReader(blob));
    await outXci.parse();
    const parts = outXci.getPartitions();

    const secure = parts.find(p => p.name === 'secure');
    const secureHfs0 = await outXci.readPartitionFiles(secure);
    const secureFiles = secureHfs0.getFiles();
    check('keep: secure has 3 files (delta kept)', secureFiles.length === 3 && secureFiles[2].name === NAME_CCCC,
        secureFiles.map(f => f.name).join(', '));

    const normal = parts.find(p => p.name === 'normal');
    const normalHfs0 = await outXci.readPartitionFiles(normal);
    const normalFiles = normalHfs0.getFiles();
    check('keep: normal processed (dddd → ncz)', normalFiles.length === 1 && normalFiles[0].name === NAME_DDDD.slice(0, -3) + 'ncz',
        normalFiles.map(f => `${f.name}(${f.size})`).join(', '));

    // Round-trip: all 4 NCAs back.
    const back = await decompressXCZ(memReader(blob), { memory: true }, { log: () => {}, progress: () => {} });
    const backBlob = new Uint8Array(await back.blob.arrayBuffer());
    const backXci = new XCIReader(memReader(backBlob));
    await backXci.parse();
    const byName = {};
    for (const p of backXci.getPartitions()) {
        const h = await backXci.readPartitionFiles(p);
        for (const f of h.getFiles()) byName[f.name] = backBlob.subarray(f.offset, f.offset + f.size);
    }
    check('round-trip keep: aaaa identical', byName[NAME_AAAA] && sha256(byName[NAME_AAAA]) === sha256(aaaa.nca));
    check('round-trip keep: bbbb identical', byName[NAME_BBBB] && sha256(byName[NAME_BBBB]) === sha256(bbbb));
    check('round-trip keep: cccc identical', byName[NAME_CCCC] && sha256(byName[NAME_CCCC]) === sha256(cccc));
    check('round-trip keep: dddd identical', byName[NAME_DDDD] && sha256(byName[NAME_DDDD]) === sha256(dddd.nca));
}

// ── Error paths ──────────────────────────────────────────────────────────────
console.log('error paths');
{
    // Rights-managed NCA without a matching ticket → fail loudly.
    const eeee = await buildRightsNca('0100E65002BB9100', 'DEADBEEF000000000000000000000001', counterA);
    const xciRights = assembleXci([
        { name: 'secure', entries: [{ name: 'eeee0000000000000000000000000005.nca', data: eeee }] },
        { name: 'normal', entries: [] },
        { name: 'update', entries: [] },
        { name: 'logo', entries: [] },
    ]);
    let threw = null;
    try {
        await compressXCItoXCZ(memReader(xciRights), { memory: true }, { keys, keep: false, log: () => {}, progress: () => {} });
    } catch (e) { threw = e; }
    check('missing titlekey (rights-managed, no .tik) → throws', threw && /Missing title key/.test(threw.message), threw && threw.message);

    // Non-standard layout (root HFS0 at 0x10000, hfs0Offset=0x10000 — a fully
    // parseable input) → throw (python would emit a broken file; we refuse).
    const xciBad = assembleXci([
        { name: 'secure', entries: [{ name: 'eeee0000000000000000000000000005.nca', data: eeee }] },
        { name: 'normal', entries: [] },
        { name: 'update', entries: [] },
        { name: 'logo', entries: [] },
    ], { hfs0Offset: 0x10000 });
    let threw2 = null;
    try {
        await compressXCItoXCZ(memReader(xciBad), { memory: true }, { keys, keep: false, log: () => {}, progress: () => {} });
    } catch (e) { threw2 = e; }
    check('non-standard layout (hfs0Offset=0x10000) → throws', threw2 && /Unsupported XCI layout/.test(threw2.message), threw2 && threw2.message);
}

console.log('');
if (failed > 0) { console.log(`${failed} CHECK(S) FAILED`); process.exit(1); }
console.log('ALL CHECKS PASSED');
