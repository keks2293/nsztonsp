// Diagnostic: are the NCA offsets (ncaPos) delivered to NczStreamSource.stream()
// consume callbacks always 16-byte aligned? They accumulate from node:zlib /
// WASM decompressed chunk lengths, which are arbitrary — so mid-stream chunk
// starts are expected to be unaligned. This matters because AesCtr (node
// backend) requires a 16-aligned seek() offset. The lockstep merge must not
// assume aligned ncaPos.
//
// Streams the program NCZ from a real .nsz, records ncaPos % 16 for every
// consume callback until the RomFS end, then stops.
//
//   node diag_ncz_nca_pos_alignment.mjs path.nsz

import { openSync, fstatSync, readSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PFS0 } from '../fs/pfs0.js';
import { AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { NczStreamSource, STOP_STREAM } from '../fs/range-source.js';
import { decryptNcaHeaderBytes, findRomfsFsHeader, sectionMedia, NCA_HEADER_SIZE } from '../fs/nca-utils.js';
import { KeysParser } from '../keys.js';

const [,, NSZ_PATH] = process.argv;
if (!NSZ_PATH) { console.error('usage: node diag_ncz_nca_pos_alignment.mjs path.nsz'); process.exit(1); }

const fd = openSync(NSZ_PATH, 'r');
async function read(offset, size) {
    const buf = Buffer.alloc(size);
    readSync(fd, buf, 0, size, offset);
    return new Uint8Array(buf);
}
const stat = { read };
const keys = KeysParser.parse(readFileSync(fileURLToPath(new URL('../static/prod.keys', import.meta.url)), 'utf8'));

const pfs0 = await PFS0.open(stat);
const nczs = pfs0.getFiles().filter((f) => f.name.toLowerCase().endsWith('.ncz'));
const prog = nczs.slice().sort((a, b) => b.size - a.size)[0];
console.log(`[NCZ] ${prog.name} (${prog.size.toLocaleString()} bytes)`);

const reader = new AdapterNCZReader(stat, prog.offset, prog.size);
const parsed = await parseNczSections(reader);
let headerRaw = parsed.ncaHeader ? parsed.ncaHeader.subarray(0, NCA_HEADER_SIZE) : null;
if (!headerRaw) {
    const tmp = new NczStreamSource(reader, parsed);
    tmp.registerRange(0, NCA_HEADER_SIZE);
    headerRaw = await tmp.read(0, NCA_HEADER_SIZE);
}
const decHeader = decryptNcaHeaderBytes(headerRaw, keys);
const { idx: romfsIdx } = findRomfsFsHeader(decHeader, 'base');
const { mediaOffset, mediaEnd } = sectionMedia(decHeader, romfsIdx);
const romfsStart = mediaOffset * 0x200;
const romfsEnd = romfsStart + (mediaEnd - mediaOffset) * 0x200;
console.log(`[ROMFS] [0x${romfsStart.toString(16)}, 0x${romfsEnd.toString(16)})`);

let calls = 0, unaligned = 0, bytes = 0;
const firstUnaligned = [];
const src = new NczStreamSource(reader, parsed);
await src.stream(async (chunk, ncaPos) => {
    calls++;
    bytes += chunk.length;
    const rem = ncaPos & 15;
    if (rem !== 0) {
        unaligned++;
        if (firstUnaligned.length < 5) firstUnaligned.push(`0x${ncaPos.toString(16)} (rem ${rem}) len=${chunk.length}`);
    }
    if (ncaPos + chunk.length >= romfsEnd) throw new Error(STOP_STREAM);
});
console.log(`consume callbacks up to RomFS end: ${calls}, bytes=${bytes}`);
console.log(`UNALIGNED (ncaPos % 16 != 0): ${unaligned} of ${calls} (${calls ? (100 * unaligned / calls).toFixed(2) : 0}%)`);
for (const f of firstUnaligned) console.log(`  e.g. ${f}`);
console.log(unaligned > 0
    ? '→ ncaPos is NOT guaranteed 16-aligned: the lockstep merge must handle unaligned chunk starts (head-keystream / aligned re-slicing).'
    : '→ all ncaPos were aligned in this run (but do NOT rely on it: chunk sizes are decoder-dependent).');
