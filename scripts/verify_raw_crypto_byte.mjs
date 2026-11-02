// Empirical check: what is the RAW crypto byte at FsHeader+0x04 for real NCAs?
// Decrypts the base program NCA header (Stardew NSP) and the update NCA header
// (from update.nsz), prints NCA-level crypto types + all 4 fs-header crypto bytes.
//
// Usage: node scripts/verify_raw_crypto_byte.mjs
import { openSync, readSync, fstatSync, closeSync, readFileSync } from 'node:fs';
import { PFS0 } from '../fs/pfs0.js';
import { decryptNcaHeaderBytes, NCA_HDR, FS_HDR, SECTION_FS_TYPE } from '../fs/nca-utils.js';
import { KeysParser } from '../keys.js';
import { readLeU64, readLeU32 } from '../fs/bytes.js';

const keys = KeysParser.parse(readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));

function fdReader(fd) {
    return {
        read: (off, size) => {
            const b = Buffer.alloc(size);
            readSync(fd, b, 0, size, off);
            return new Uint8Array(b);
        },
    };
}

const FS_NAMES = { 0: 'NONE', 2: 'ExeFS', 3: 'RomFS' };

async function dumpDecHeader(label, raw0xC00) {
    const dec = decryptNcaHeaderBytes(raw0xC00, keys);
    console.log(`\n=== ${label} ===`);
    const size = readLeU64(dec, NCA_HDR.SIZE);
    console.log(`  NCA-level: crypto_type=${dec[NCA_HDR.CRYPTO_TYPE]} crypto_type2=${dec[NCA_HDR.CRYPTO_TYPE2]} kaek=${dec[NCA_HDR.KAEK_IND]} size=0x${size.toString(16)}`);
    const view = new DataView(dec.buffer, dec.byteOffset, dec.byteLength);
    const ct = view.getUint8(NCA_HDR.CONTENT_TYPE);
    console.log(`  content_type=${ct} (0=PROGRAM 1=META 2=CONTROL 3=MANUAL 4=DATA 5=PUBLIC_DATA)`);
    // Media table at 0x240 gives the REAL section offsets (0x200 blocks).
    const { sectionMedia } = await import('../fs/nca-utils.js');
    for (let i = 0; i < 4; i++) {
        const fh = dec.subarray(NCA_HDR.FS_HEADERS + i * 0x200, NCA_HDR.FS_HEADERS + (i + 1) * 0x200);
        const fsType = fh[FS_HDR.HASH_TYPE];
        const cryptoByte = fh[FS_HDR.CRYPTO_TYPE];
        const secCtr = fh.subarray(FS_HDR.SECTION_CTR, FS_HDR.SECTION_CTR + 8);
        const secCtrHex = Buffer.from(secCtr).toString('hex');
        const { mediaOffset, mediaEnd } = sectionMedia(dec, i);
        const off = mediaOffset * 0x200;
        const end = mediaEnd * 0x200;
        const sz = end - off;
        console.log(`  section[${i}] ${FS_NAMES[fsType] ?? `fsType=${fsType}`}: RAW_CRYPTO_BYTE=${cryptoByte} offset=0x${off.toString(16)} size=0x${sz.toString(16)} section_ctr(LE)=${secCtrHex}`);
    }
    // Contiguity check (python isNcaPacked): sections with fsType!=0, sorted by offset
    const secList = [];
    for (let i = 0; i < 4; i++) {
        const fh = dec.subarray(NCA_HDR.FS_HEADERS + i * 0x200, NCA_HDR.FS_HEADERS + (i + 1) * 0x200);
        const { mediaOffset, mediaEnd } = sectionMedia(dec, i);
        const off = mediaOffset * 0x200;
        const sz = (mediaEnd - mediaOffset) * 0x200;
        if (fh[FS_HDR.HASH_TYPE] !== 0) secList.push({ off, sz });
    }
    secList.sort((a, b) => a.off - b.off);
    let next = secList.length ? secList[0].off : 0;
    let packed = true;
    for (const s of secList) { if (s.off !== next) { packed = false; break; } next = s.off + s.sz; }
    if (next !== Number(readLeU64(dec, NCA_HDR.SIZE))) packed = false;
    console.log(`  isNcaPacked=${packed} (sorted offsets: ${secList.map(s => '0x' + s.off.toString(16)).join(', ')})`);
    return dec;
}

// ── NSP: all members ──────────────────────────────────────────────────
{
    const path = '.playwright-mcp/Stardew-Valley-0100E65002BB8000-v0-0-87-GB-merged.nsp';
    const fd = openSync(path, 'r');
    const reader = fdReader(fd);
    const pfs0 = await PFS0.open(reader);
    for (const f of pfs0.getFiles()) {
        if (!f.name.toLowerCase().endsWith('.nca')) {
            console.log(`\n=== member ${f.name}: not an NCA (skipping) ===`);
            continue;
        }
        const raw = reader.read(f.offset, 0xC00);
        await dumpDecHeader(`NSP member ${f.name}`, raw);
    }
    closeSync(fd);
}

// ── NCZ: update NCA header (BKTR) ─────────────────────────────────────
{
    const path = '.playwright-mcp/update.nsz';
    const fd = openSync(path, 'r');
    const reader = fdReader(fd);
    const pfs0 = await PFS0.open(reader);
    for (const f of pfs0.getFiles()) {
        if (!f.name.toLowerCase().endsWith('.ncz')) continue;
        const raw = reader.read(f.offset, 0xC00);
        await dumpDecHeader(`NCZ member ${f.name}`, raw);
    }
    closeSync(fd);
}
