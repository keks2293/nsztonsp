// Brute-force the AES_CTR_EX section counter scheme for the LN2 update NCA.
// Reads the raw ciphertext of the ExeFS section PFS0 data start and tries a
// matrix of counter-head × block-index constructions, checking for 'PFS0'.
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';
import { AesEcb } from '../crypto/aes128.js';
import {
    FS_HDR, NCA_HDR, sectionMedia, fsHeaderAt, reversedSectionCtr, resolveTitlekey,
} from '../fs/nca-utils.js';
import { readLeU32, readLeU64, bytesToHex } from '../fs/bytes.js';
import { decryptNcaHeaderBytes } from '../fs/nca-utils.js';
import { PFS0 } from '../fs/pfs0.js';

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const nsp = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsp`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const fd = fs.openSync(nsp, 'r');
function readAt(fd, offset, size) {
    const buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, offset);
    return buf;
}

// Find program NCA entry in the NSP PFS0.
const pfs0 = await PFS0.open({
    read: (offset, size) => readAt(fd, offset, size),
    get length() { return fs.fstatSync(fd).size; },
});
console.log('NSP files:', pfs0.getFiles().map(f => `${f.name} (0x${f.size.toString(16)})`).join('\n  '));
let entry = null;
let tikEntry = null;
for (const f of pfs0.getFiles()) {
    if (!entry && f.name.toLowerCase().endsWith('.nca') && !f.name.toLowerCase().endsWith('.cnmt.nca')) {
        entry = { name: f.name, off: f.offset, size: f.size };
    }
    if (!tikEntry && f.name.toLowerCase().endsWith('.tik')) {
        tikEntry = { name: f.name, off: f.offset, size: f.size };
    }
}
if (!entry) { console.error('no NCA found'); process.exit(1); }
console.log('Program NCA:', entry.name, 'off=0x' + entry.off.toString(16), 'size=0x' + entry.size.toString(16));

const rawHdr = readAt(fd, entry.off, 0xC00);
const decHeaderArr = decryptNcaHeaderBytes(rawHdr, keys);

// Section 0 = ExeFS (PFS0). sectionMeta
const fh = fsHeaderAt(decHeaderArr, 0);
const ctType = fh[FS_HDR.CRYPTO_TYPE];
const htType = fh[FS_HDR.HASH_TYPE];
console.log('sec[0] hash_type=', htType, 'crypto_type=', ctType);
const { mediaOffset } = sectionMedia(decHeaderArr, 0);
const sectionOffset = mediaOffset * 0x200;
const pfs0DataOff = sectionOffset + readLeU64(fh, FS_HDR.PFS0_OFFSET);
const pfs0Size = readLeU64(fh, FS_HDR.PFS0_SIZE);
console.log('sectionOffset=0x' + sectionOffset.toString(16), 'pfs0DataOff=0x' + pfs0DataOff.toString(16), 'pfs0Size=0x' + pfs0Size.toString(16));

// FsHeader counter region raw bytes
const ctrRaw = Buffer.from(fh.subarray(0x140, 0x148));
const ctrRev = Buffer.from(reversedSectionCtr(fh));
const secValRaw = Buffer.from(fh.subarray(0x144, 0x148));
const secVal = readLeU32(fh, 0x144);
console.log('ctrRaw(140:148)=', ctrRaw.toString('hex'), 'ctrRev=', ctrRev.toString('hex'),
    'secVal(u32 LE @144)=0x' + secVal.toString(16), 'raw148:150=', Buffer.from(fh.subarray(0x148, 0x150)).toString('hex'));

// titlekey from tik in the update NSP
let tikData = null;
if (tikEntry) tikData = readAt(fd, tikEntry.off, tikEntry.size || 0x400);
const titlekey = resolveTitlekey(tikData, decHeaderArr, keys);
console.log('titlekey=', titlekey ? Buffer.from(titlekey).toString('hex') : 'N/A');

// Read ciphertext at pfs0DataOff
const cipher = readAt(fd, entry.off + pfs0DataOff, 0x40);
console.log('cipher=', cipher.toString('hex'));

const expectMagic = 'PFS0';

// Counter-head candidates (8 bytes placed at counter[0:8])
const heads = {
    revCtr: ctrRev,
    rawCtr: ctrRaw,
    revCtrSwapped: Uint8Array.from([ctrRev[4], ctrRev[5], ctrRev[6], ctrRev[7], ctrRev[0], ctrRev[1], ctrRev[2], ctrRev[3]]),
    secureValRevCtr: (() => { const b = new Uint8Array(8); b[0]=(secVal>>24)&0xff; b[1]=(secVal>>16)&0xff; b[2]=(secVal>>8)&0xff; b[3]=secVal&0xff; for (let i=0;i<4;i++) b[4+i]=ctrRev[i]; return b; })(),
    zeros: new Uint8Array(8),
};

// Block-index base candidates applied to counter[8:16] (divisor 16) or sector (0x200)
const bases = {
    absDiv16: pfs0DataOff,
    secDiv16: sectionOffset,
    absDiv200: pfs0DataOff / 0x200,
    secDiv200: sectionOffset / 0x200,
    relDiv16: pfs0DataOff - sectionOffset,
    relDiv200: (pfs0DataOff - sectionOffset) / 0x200,
    zero: 0,
};

// Placement modes for constructing the full 16-byte counter from head+index
function buildCounter(head, index, mode) {
    const ctr = new Uint8Array(16);
    const idx = new Uint8Array(8);
    let tmp = Math.floor(index);
    for (let j = 7; j >= 0; j--) { idx[j] = tmp & 0xFF; tmp = Math.floor(tmp / 256); }
    if (mode === 'headLoIdxHi') {
        ctr.set(head.subarray(0, 8), 0);
        ctr.set(idx, 8);
    } else if (mode === 'idxLoHeadHi') {
        ctr.set(head.subarray(0, 8), 8);
        ctr.set(idx, 0);
    }
    return ctr;
}

function decryptBlock(cipher, titlekey, ctr) {
    // keystream = AES-ECB(ctr); xor
    const aes = new AesEcb(titlekey);
    const ks = aes.encryptBlock(ctr);
    const out = new Uint8Array(16);
    for (let b = 0; b < 16; b++) out[b] = cipher[b] ^ ks[b];
    return Buffer.from(out);
}

// Also try normal AesCtr with head as nonce (counter = nonce||idx, per-block increment)
// We'll emulate the first 16-byte block with counter = nonce[0:8] + idx in [8:16].
let found = [];
for (const [hname, h] of Object.entries(heads)) {
    for (const [bname, base] of Object.entries(bases)) {
        const idx = Number.isInteger(base) ? base : Math.floor(base);
        for (const mode of ['headLoIdxHi', 'idxLoHeadHi']) {
            const ctr = buildCounter(h, idx, mode);
            const out = decryptBlock(cipher, titlekey, ctr);
            const mag = out.toString('ascii', 0, 4);
            const tag = `${hname}/${bname}/${mode}: ${out.toString('hex')} magic=${JSON.stringify(mag)}`;
            if (mag === expectMagic) { found.push('MATCH ' + tag); }
            else if (/^P/.test(mag)) found.push('?P? ' + tag);
        }
    }
}
console.log('\nresults:');
console.log(found.length ? found.join('\n') : '(no PFS0 match in matrix)');

// Report a couple plausible ones for inspection — the first candidates that give
// non-random printable output on the first bytes.
console.log('\n--- first-16 printable candidates ---');
const aes = new AesEcb(titlekey);
for (const [hname, h] of Object.entries(heads)) {
    for (const [bname, base] of Object.entries(bases)) {
        const idx = Number.isInteger(base) ? base : Math.floor(base);
        const ctr = buildCounter(h, idx, 'headLoIdxHi');
        const out = decryptBlock(cipher, titlekey, ctr);
        const mag = out.toString('ascii', 0, 4);
        if (/^[Pp]/.test(mag) || out.toString('hex').startsWith('50')) {
            console.log(`${hname}/${bname} -> ${out.toString('hex')} ascii=${JSON.stringify(out.toString('ascii'))} magic=${JSON.stringify(mag)}`);
        }
    }
}