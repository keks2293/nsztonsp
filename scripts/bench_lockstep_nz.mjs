// Lockstep vs pre-allocated NczStreamSource, measured on a real .nsz.
//
// Compares two ways of reading the program NCA's RomFS section out of its NCZ
// (one decompression pass either way, same bytes, same checksum):
//   prealloc  — registerRange(romfs) + read() in 16 MiB chunks (current pipeline
//               behavior: the full registered buffer stays alive for the pass)
//   lockstep  — NczStreamSource.stream(consume): chunks delivered in physical
//               order, no range buffers, consumer paces the pump, early stop at
//               the RomFS end via the STOP_STREAM sentinel
//
// Both consume the exact same RomFS bytes in the same order and print a
// 256-lane XOR checksum — the values MUST match (correctness guard).
//
// Run ONE mode per process so /usr/bin/time -l maxrss reflects that mode alone:
//   /usr/bin/time -l node bench_lockstep_nz.mjs path.nsz prealloc [runs]
//   /usr/bin/time -l node bench_lockstep_nz.mjs path.nsz lockstep [runs]
//
// Note: registering the WHOLE RomFS as one range is the pre-alloc worst case —
// the real BKTR merge registers only the base runs (a subset), so the real
// pipeline's pre-alloc is <= what is measured here. Decompression work is the
// same either way (NCZ is one stream; nothing is skippable).

import { openSync, fstatSync, readSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PFS0 } from '../fs/pfs0.js';
import { NCZDecompressor, AdapterNCZReader, parseNczSections } from '../fs/ncz.js';
import { NczStreamSource, STOP_STREAM } from '../fs/range-source.js';
import { decryptNcaHeaderBytes, findRomfsFsHeader, sectionMedia, NCA_HEADER_SIZE } from '../fs/nca-utils.js';
import { KeysParser } from '../keys.js';
import { CHUNK_16MB } from '../fs/bytes.js';

const [,, NSZ_PATH, MODE, RUNS_ARG] = process.argv;
const RUNS = Number(RUNS_ARG || 3);
if (!NSZ_PATH || (MODE !== 'prealloc' && MODE !== 'lockstep')) {
    console.error('usage: node bench_lockstep_nz.mjs path.nsz prealloc|lockstep [runs]');
    process.exit(1);
}

// ── Setup: open the NSZ, pick the program NCZ (largest member), find the RomFS ──
const fd = openSync(NSZ_PATH, 'r');
const fstat = fstatSync(fd);
const stat = { read };
async function read(offset, size) {
    const buf = Buffer.alloc(size);
    readSync(fd, buf, 0, size, offset);
    return new Uint8Array(buf);
}

const keys = KeysParser.parse(readFileSync(fileURLToPath(new URL('../static/prod.keys', import.meta.url)), 'utf8'));

const pfs0 = await PFS0.open(stat);
const files = pfs0.getFiles();
const nczs = files.filter((f) => f.name.toLowerCase().endsWith('.ncz'));
if (!nczs.length) { console.error('no NCZ found'); process.exit(1); }
const prog = nczs.slice().sort((a, b) => b.size - a.size)[0];
console.log(`[NSZ] ${NSZ_PATH}`);
console.log(`[NCZ] program member: ${prog.name} (${prog.size.toLocaleString()} bytes compressed)`);

const reader = new AdapterNCZReader(stat, prog.offset, prog.size);
const parsed = await parseNczSections(reader);

// RomFS section range inside the NCA (from the decrypted NCA header).
let headerRaw = parsed.ncaHeader ? parsed.ncaHeader.subarray(0, NCA_HEADER_SIZE) : null;
if (!headerRaw) {
    // NCZ without the 0x4000 uncompressed header: grab it with a throwaway source.
    const tmp = new NczStreamSource(reader, parsed);
    tmp.registerRange(0, NCA_HEADER_SIZE);
    headerRaw = await tmp.read(0, NCA_HEADER_SIZE);
}
const decHeader = decryptNcaHeaderBytes(headerRaw, keys);
const { idx: romfsIdx } = findRomfsFsHeader(decHeader, 'base');
const { mediaOffset, mediaEnd } = sectionMedia(decHeader, romfsIdx);
const romfsStart = mediaOffset * 0x200;
const romfsSize = (mediaEnd - mediaOffset) * 0x200;
const romfsEnd = romfsStart + romfsSize;
console.log(`[ROMFS] section ${romfsIdx}: [0x${romfsStart.toString(16)}, 0x${romfsEnd.toString(16)}) = ${(romfsSize / (1024 * 1024)).toFixed(1)} MiB`);
console.log(`[mode] ${MODE}, ${RUNS} runs (best-of-N)`);

// ── Checksum: 256-lane XOR over the RomFS bytes in order ──────────────────────
function xorInto(h, data, ncaPos) {
    let lane = ncaPos & 255;
    for (let i = 0; i < data.length; i++) {
        h[lane] ^= data[i];
        lane = (lane + 1) & 255;
    }
}
function checksumHex(h) {
    let s = '';
    for (let i = 0; i < h.length; i++) s += h[i].toString(16).padStart(2, '0');
    return s;
}

let keepAlive = null; // hold the last source's buffers until process exit

for (let run = 0; run < RUNS; run++) {
    const h = new Uint8Array(256);
    const st = process.hrtime.bigint();
    if (MODE === 'prealloc') {
        // Current behavior: one range buffer for the whole RomFS, read in 16 MiB chunks.
        const src = new NczStreamSource(reader, parsed);
        src.registerRange(romfsStart, romfsSize);
        let off = romfsStart;
        while (off < romfsEnd) {
            const len = Math.min(CHUNK_16MB, romfsEnd - off);
            const data = await src.read(off, len);
            xorInto(h, data, off);
            off += len;
        }
        keepAlive = src;
    } else {
        // Lockstep: chunks delivered in physical order, no range buffers.
        const src = new NczStreamSource(reader, parsed);
        await src.stream(async (chunk, ncaPos) => {
            const a = Math.max(ncaPos, romfsStart);
            const b = Math.min(ncaPos + chunk.length, romfsEnd);
            if (b > a) {
                xorInto(h, chunk.subarray(a - ncaPos, b - ncaPos), a);
                if (b === romfsEnd) throw new Error(STOP_STREAM);
            }
        });
        keepAlive = null;
    }
    const ms = Number(process.hrtime.bigint() - st) / 1e6;
    const mib = romfsSize / (1024 * 1024);
    console.log(`run ${run + 1}: ${mib.toFixed(1)} MiB in ${ms.toFixed(0)} ms → ${(mib / (ms / 1000)).toFixed(1)} MiB/s  checksum=${checksumHex(h)}`);
}

const mu = process.memoryUsage();
console.log(`[mem] end-of-process: rss=${(mu.rss / (1024 * 1024)).toFixed(1)} MiB heapUsed=${(mu.heapUsed / (1024 * 1024)).toFixed(1)} MiB (maxrss from /usr/bin/time -l is the peak)`);
