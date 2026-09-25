// Scratch: verify the XOR-invariance hypothesis.
// dec(NCZ-output, K) should equal PFS0, where K = AesCtr(c0f2ce05..., revCtr).seek(absDataOff).
// i.e. NCZ output = dec(plaintext, K), and extractExefsStream re-applies the same K.
import fs from 'fs';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { AesEcb } from '../crypto/aes128.js';
import { resolveTitlekey, NCA_HDR, NCA_HEADER_SIZE } from '../fs/nca-utils.js';

class FileReader {
    constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
    async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return buf; }
    close() { fs.closeSync(this.fd); }
}

const DIR = '/Users/rmitkov/Downloads/Little Nightmares 2 [NSZ]';
const updateNsz = `${DIR}/Little Nightmares II [010097100EDD6800][v262144] (1.56 GB).nsz`;
const keys = KeysParser.parse(fs.readFileSync('../static/prod.keys', 'utf8'));

const reader = new FileReader(updateNsz);
const entries = (await PFS0.open(reader)).getFiles();
const prog = entries.find(e => e.name.toLowerCase().endsWith('.ncz'));
const nczReader = new AdapterNCZReader(reader, prog.offset, prog.size);
const parsed = await parseNczSections(nczReader);

const rawHeader = await reader.read(prog.offset, NCA_HEADER_SIZE);
const decHeader = new Uint8Array(rawHeader);
// decryptNcaHeaderBytes: XTS decrypt of raw header
const { decryptNcaHeaderBytes } = await import('../fs/nca-utils.js');
const dec = decryptNcaHeaderBytes(rawHeader, keys);
const rightsId = Buffer.from(dec.subarray(NCA_HDR.RIGHTS_ID, NCA_HDR.RIGHTS_ID + 0x10)).toString('hex');
console.log(`rightsId=${rightsId}`);

const tikEntry = entries.find(e => e.name.toLowerCase().endsWith('.tik'));
const tikData = tikEntry ? await reader.read(tikEntry.offset, tikEntry.size) : null;
const titlekey = resolveTitlekey(tikData, dec, keys);
console.log(`titlekey=${titlekey ? Buffer.from(titlekey).toString('hex') : 'N/A'}`);

// ExeFS data offset = section media start + PFS0_OFFSET(0x8000), same as diag.
const dataOff = 0x608dd200;
const nczOut = Buffer.alloc(0x20);
const filled = { n: 0 };
{
    const exefsSec = { offset: 0x608d5200, endOffset: 0x63f7d200 };
    const decomp = new NCZDecompressor(nczReader);
    try {
        await decomp.decompress(
            () => {},
            (chunk, offset) => {
                if (filled.n >= 0x20) throw new Error('DONE');
                if (offset + chunk.length <= exefsSec.offset) return;
                const startIn = Math.max(0, exefsSec.offset - offset);
                const src = chunk.subarray(startIn, startIn + Math.min(0x20 - filled.n, chunk.length - startIn));
                nczOut.set(src, filled.n);
                filled.n += src.length;
            },
            parsed,
        );
    } catch (e) { if (e.message !== 'DONE') throw e; }
}
console.log(`NCZDecompressor output[0:0x20]: ${nczOut.toString('hex')}`);

// Re-apply the SAME keystream (this is what streamNcaSection does now).
const c = new AesCtr(titlekey, Buffer.from('0000000100000003', 'hex'));
c.seek(dataOff);
const roundTrip = await c.decrypt(nczOut);
console.log(`round-trip[0:16]: ${Buffer.from(roundTrip).toString('hex')} magic=${JSON.stringify(Buffer.from(roundTrip).toString('ascii', 0, 4))}`);

// Direct keystream check: ciphertext from NSP ^ PFS0 should equal keystream; NCZ-out ^ keystream should equal PFS0.
const pfs0Magic = Buffer.from('50465330050000003800000000000000', 'hex');
const c2 = new AesCtr(titlekey, Buffer.from('0000000100000003', 'hex'));
c2.seek(dataOff);
const ks = Buffer.from(await c2.decrypt(Buffer.alloc(16))); // decrypt of zeros = keystream
console.log(`keystream[0:16]: ${ks.toString('hex')}`);
console.log(`NCZ-out ^ KS == PFS0?: ${Buffer.from(nczOut.subarray(0,16).map((b,i)=>b^ks[i])).equals(pfs0Magic)}`);
reader.close();