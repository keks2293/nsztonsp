// Re-compression test (.nsz/.xcz as --compress input — our extension, Python
// nsz never re-compresses):
//
// 1. Synthetic NSP (one CTR PROGRAM NCA, 0x64000, titlekey in the key area)
//    → NSZ (block mode, defaults).
// 2. Re-compress that NSZ with: defaults, solid, level 3 + bs 14 — every
//    variant must round-trip (NCZDecompressor → original NCA bytes) and keep
//    the NCZSECTN table byte-identical (options change only the payload).
// 3. Solid NSZ → block re-compression (the solid-input path: the frame is
//    re-fed from its start after the backward seek).
// 4. NSZ with a DATA (delta fragment) .ncz member: dropped without keep,
//    copied verbatim with keep.
// 2b. Output naming (compressedOutputName): <stem>_blockcomp /
//     <stem>_solidcomp, idempotent per mode, extension swap on fresh inputs.
// 5. CLI end-to-end: in-place writes <stem>_blockcomp.nsz next to the input
//    (round-trips); a self-named *_blockcomp.nsz input is refused (backstop);
//    -o + level 3, -o + solid (-S → in_solidcomp.nsz) and a fresh .nsp all
//    round-trip; foreign extensions are refused.
// 6. Real file: base.nsz (920 MiB, solid, BKTR program NCA) re-compressed to
//    block mode — per-member payload SHA-256 must match the original exactly.
//
// Usage: node scripts/test_recompress_nsz.mjs
import { openSync, closeSync, readSync, fstatSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createHash } from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { compressNSPtoNSZ, compressNcaToBuffer, compressedOutputName } from '../fs/compress.js';
import { NCZDecompressor, AdapterNCZReader } from '../fs/ncz.js';
import { AesXts, AesEcb } from '../crypto/aes128.js';
import { AesCtr } from '../crypto/aes-ops.mjs';
import { toKeyBytes } from '../fs/nca-utils.js';

const BASE_NSZ = '.playwright-mcp/base.nsz';
const REPO = join(tmpdir(), `recompress_test_${process.pid}`);

let failures = 0;
function check(name, cond, detail = '') {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
    if (!cond) failures++;
}
const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const sha256 = (u8) => createHash('sha256').update(u8).digest('hex');

const keys = KeysParser.parse(readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));

// ── Synthetic NCA builder (same geometry as test_compress_nsp 0c) ──────────
// ncaSize 0x64000: raw 0x4000 header + one 0x60000 CTR section; non-rights
// (titlekey in the key area). `contentType` and `payload` are parameters so
// the same geometry serves a DATA (delta) NCA with random (incompressible)
// payload — which also exercises the raw-stored block path.
async function buildNca({ contentType, payload }) {
    const ncaSize = 0x64000;
    const payloadSize = ncaSize - 0x4000;
    const titlekey = new Uint8Array(16).map((_, i) => i + 1);
    const head8 = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    const counter16 = new Uint8Array(16);
    counter16.set(head8);

    const h = new Uint8Array(0xC00);
    const hv = new DataView(h.buffer);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = contentType;
    hv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from('0100E65002BB8000', 'hex'), 0x210);
    hv.setUint32(0x218, 1, true);
    hv.setUint32(0x240, 0x20, true);
    hv.setUint32(0x244, 0x320, true);
    const plainKeyArea = new Uint8Array(0x40);
    plainKeyArea.set(titlekey, 0x20);
    h.set(new AesEcb(toKeyBytes(keys.keyAreaKeys[0][0])).encrypt(plainKeyArea), 0x300);
    h[0x402] = 2; h[0x403] = 2; h[0x404] = 3;
    hv.setBigUint64(0x448, BigInt(payloadSize), true);
    h.set(Buffer.from(head8).reverse(), 0x540);

    const cipherPayload = new Uint8Array(await new AesCtr(titlekey, counter16, 0x4000).encrypt(payload));
    const nca = new Uint8Array(ncaSize);
    nca.set(new Uint8Array(new AesXts(toKeyBytes(keys.header_key)).encrypt(h, 0)), 0);
    nca.set(cipherPayload, 0x4000);
    return { nca, ncaSize, payloadSize, titlekey, head8, counter16 };
}

// PFS0 container with the given [name, bytes] members.
function buildPfs0(members) {
    const strtab = members.map(m => m.name + '\0').join('');
    const headerSize = 0x10 + members.length * 0x18 + strtab.length;
    const total = headerSize + members.reduce((s, m) => s + m.bytes.length, 0);
    const buf = new Uint8Array(total);
    const dv = new DataView(buf.buffer);
    buf.set([0x50, 0x46, 0x53, 0x30], 0);
    dv.setUint32(4, members.length, true);
    dv.setUint32(8, strtab.length, true);
    let off = headerSize;
    let eo = 0x10;
    let no = 0;
    for (const m of members) {
        dv.setBigUint64(eo, BigInt(off - headerSize), true);
        dv.setBigUint64(eo + 8, BigInt(m.bytes.length), true);
        dv.setUint32(eo + 16, no, true);
        eo += 0x18;
        buf.set(m.bytes, off);
        off += m.bytes.length;
        no += m.name.length + 1;
    }
    buf.set(new TextEncoder().encode(strtab), 0x10 + members.length * 0x18);
    return buf;
}

function memReader(u8) { return { read: async (off, size) => u8.subarray(off, off + size), length: u8.length }; }
async function openMembers(u8) {
    const pfs0 = await PFS0.open(memReader(u8));
    return pfs0.getFiles();
}
async function decompressNczMember(u8, name) {
    const f = (await openMembers(u8)).find(m => m.name === name);
    if (!f) return null;
    return new NCZDecompressor(u8.subarray(f.offset, f.offset + f.size)).decompress();
}
// NCZSECTN table bytes of a .ncz member (1 section → 80 bytes).
async function nczTable(u8, name) {
    const f = (await openMembers(u8)).find(m => m.name === name);
    return u8.subarray(f.offset + 0x4000, f.offset + 0x4000 + 80);
}

// ── 1. Synthetic NSP → NSZ (the re-compression input) ───────────────────────
const program = await buildNca({
    contentType: 0, // PROGRAM
    payload: (() => { const p = new Uint8Array(0x60000); for (let i = 0; i < p.length; i++) p[i] = (i * 7 + (i >> 8) * 3) & 0xFF; return p; })(),
});
const nsp = buildPfs0([{ name: '1650ab6235ae16751ca5e220b414c3f1.nca', bytes: program.nca }]);

async function compressInput(input, opts = {}) {
    const res = await compressNSPtoNSZ(memReader(input), { memory: true }, {
        keys, keep: false, log: () => {}, progress: () => {}, ...opts,
    });
    return new Uint8Array(await res.blob.arrayBuffer());
}

const nsz1 = await compressInput(nsp);
let files1 = await openMembers(nsz1);
check('1. NSP→NSZ: one .ncz member', files1.length === 1 && files1[0].name.endsWith('.ncz'), files1.map(f => f.name).join(', '));
check('1. NSZ round-trips to the original NCA', sameBytes(await decompressNczMember(nsz1, files1[0].name), program.nca));

// ── 2. Re-compress NSZ: option matrix ───────────────────────────────────────
// Every variant: member name stays .ncz, round-trips to the original NCA,
// and the NCZSECTN table is byte-identical to the first compression's.
const table1 = Buffer.from(await nczTable(nsz1, files1[0].name));
const variants = [
    [{}, 'default (block level 18, 1 MiB)'],
    [{ mode: 'solid' }, 'solid'],
    [{ level: 3, blockSizeExponent: 14 }, 'block level 3, bs 14'],
];
for (const [opts, label] of variants) {
    const out = await compressInput(nsz1, opts);
    const members = await openMembers(out);
    const ncz = members.find(m => m.name.endsWith('.ncz'));
    check(`2. re-compress ${label}: .ncz member kept, name unchanged`,
        members.length === 1 && ncz && ncz.name === files1[0].name, members.map(f => f.name).join(', '));
    check(`2. re-compress ${label}: round-trip identical to the original NCA`,
        sameBytes(await decompressNczMember(out, ncz.name), program.nca));
    check(`2. re-compress ${label}: NCZSECTN table byte-identical`,
        Buffer.from(await nczTable(out, ncz.name)).equals(table1));
    if (opts.mode !== 'solid') {
        const bh = out.subarray(ncz.offset + 0x4000 + 80, ncz.offset + 0x4000 + 80 + 24);
        const bdv = new DataView(bh.buffer, bh.byteOffset);
        check(`2. re-compress ${label}: NCZBLOCK header valid`,
            String.fromCharCode(bh[0], bh[1], bh[2], bh[3]) === 'NCZB'
            && bh[11] === (opts.blockSizeExponent ?? 20)
            && Number(bdv.getBigUint64(16, true)) === program.payloadSize,
            `exp=${bh[11]} blocks=${bdv.getUint32(12, true)}`);
    } else {
        const f4 = out.subarray(ncz.offset + 0x4000 + 80, ncz.offset + 0x4000 + 80 + 4);
        check(`2. re-compress ${label}: zstd frame after the table (magic 0xFD2FB528 LE)`,
            f4[0] === 0x28 && f4[1] === 0xB5 && f4[2] === 0x2F && f4[3] === 0xFD,
            [f4[0], f4[1], f4[2], f4[3]].map(b => '0x' + b.toString(16)).join(' '));
    }
}

// ── 2b. Output naming (compressedOutputName) ───────────────────────────────
// Every compression output is <stem>_blockcomp<ext> / <stem>_solidcomp<ext>:
// idempotent per mode on .nsz/.xcz inputs, extension swap on .nsp/.xci.
{
    check('2b. naming: fresh .nsp → game_blockcomp.nsz', compressedOutputName('game.nsp', 'block', '.nsz') === 'game_blockcomp.nsz');
    check('2b. naming: fresh .xci + solid → game_solidcomp.xcz', compressedOutputName('game.xci', 'solid', '.xcz') === 'game_solidcomp.xcz');
    check('2b. naming: re-compress .nsz + block → game_blockcomp.nsz', compressedOutputName('game.nsz', 'block') === 'game_blockcomp.nsz');
    check('2b. naming: idempotent per mode (block → block)', compressedOutputName('game_blockcomp.nsz', 'block') === 'game_blockcomp.nsz');
    check('2b. naming: idempotent per mode (solid → solid)', compressedOutputName('game_solidcomp.xcz', 'solid', '.xcz') === 'game_solidcomp.xcz');
    check('2b. naming: mode switch block → solid', compressedOutputName('game_blockcomp.nsz', 'solid') === 'game_solidcomp.nsz');
    check('2b. naming: extension case preserved', compressedOutputName('GAME.NSZ', 'block') === 'GAME_blockcomp.NSZ');
    check('2b. naming: coincidental stem on .nsp kept', compressedOutputName('game_blockcomp.nsp', 'block', '.nsz') === 'game_blockcomp_blockcomp.nsz');
}

// ── 3. Solid input → block re-compression ───────────────────────────────────
// The solid frame is re-fed from its start after the backward seek (here the
// read pattern is header + walk; the BKTR deep read is covered by the real
// file below).
{
    const solid = await compressInput(nsz1, { mode: 'solid' });
    const out = await compressInput(solid); // default = block
    const members = await openMembers(out);
    const ncz = members.find(m => m.name.endsWith('.ncz'));
    check('3. solid→block: round-trip identical', sameBytes(await decompressNczMember(out, ncz.name), program.nca));
    check('3. solid→block: table byte-identical', Buffer.from(await nczTable(out, ncz.name)).equals(table1));
    const bh = out.subarray(ncz.offset + 0x4000 + 80, ncz.offset + 0x4000 + 80 + 24);
    check('3. solid→block: NCZBLOCK header (exp=20)', bh[11] === 20 && String.fromCharCode(bh[0], bh[1], bh[2], bh[3]) === 'NCZB');
}

// ── 4. DATA (delta) .ncz member: dropped without keep, kept with ────────────
// A DATA NCA is never compressed by the plan — but a .ncz wrapper for one can
// exist (built here by running the per-NCA writer directly with the section
// geometry; the random payload also stores a RAW block).
{
    const data = await buildNca({ contentType: 4, payload: new Uint8Array(randomBytes(0x60000)) });
    const analysis = { titlekey: data.titlekey, sections: [{ offset: 0x4000, size: data.payloadSize, cryptoType: 3, cryptoCounter: data.head8 }] };
    const dataNcz = await compressNcaToBuffer(memReader(data.nca), data.ncaSize, analysis, { level: 18, blockSizeExponent: 20 });
    const programNczFile = (await openMembers(nsz1))[0];
    const nszDelta = buildPfs0([
        { name: '1650ab6235ae16751ca5e220b414c3f1.ncz', bytes: nsz1.subarray(programNczFile.offset, programNczFile.offset + programNczFile.size) },
        { name: 'abcdef0123456789abcdef0123456789.ncz', bytes: dataNcz },
    ]);

    const outDrop = await compressInput(nszDelta, { keep: false });
    const dropMembers = await openMembers(outDrop);
    check('4. delta .ncz dropped without keep', dropMembers.length === 1 && dropMembers[0].name.endsWith('1650ab6235ae16751ca5e220b414c3f1.ncz'),
        dropMembers.map(f => f.name).join(', '));
    check('4. program still round-trips after the delta drop',
        sameBytes(await decompressNczMember(outDrop, dropMembers[0].name), program.nca));

    const outKeep = await compressInput(nszDelta, { keep: true });
    const keepMembers = await openMembers(outKeep);
    check('4. delta .ncz kept with keep=true (2 members)', keepMembers.length === 2, keepMembers.map(f => f.name).join(', '));
    const kept = keepMembers.find(m => m.name === 'abcdef0123456789abcdef0123456789.ncz');
    check('4. kept delta .ncz copied verbatim (byte-identical)',
        kept && sameBytes(outKeep.subarray(kept.offset, kept.offset + kept.size), dataNcz));
    check('4. kept program round-trips', sameBytes(await decompressNczMember(outKeep, '1650ab6235ae16751ca5e220b414c3f1.ncz'), program.nca));
}

// ── 5. CLI end-to-end ───────────────────────────────────────────────────────
{
    const cwd = new URL('..', import.meta.url).pathname;
    const runCli = (args, timeout = 120000) => execFileSync('node', ['nsz-cli.js', ...args], { cwd, stdio: 'pipe', timeout });
    mkdirSync(REPO, { recursive: true });
    const inPath = join(REPO, 'in.nsz');
    writeFileSync(inPath, nsz1);
    const memberName = '1650ab6235ae16751ca5e220b414c3f1.ncz';

    // 5a. In-place (no -o): the output is <stem>_blockcomp.nsz NEXT TO the
    // input — safe, and it round-trips.
    try {
        runCli(['--compress', inPath]);
        const outBytes = new Uint8Array(readFileSync(join(REPO, 'in_blockcomp.nsz')));
        check('5a. CLI: in-place re-compress → in_blockcomp.nsz (round-trip identical)',
            sameBytes(await decompressNczMember(outBytes, memberName), program.nca));
    } catch (e) {
        check('5a. CLI: in-place re-compress → in_blockcomp.nsz', false,
            `${e.message}\n${e.stderr ? e.stderr.toString().slice(-300) : ''}`);
    }

    // 5a2. Backstop: an input already named with the block suffix maps onto
    // itself — refused (in place would truncate the input).
    const selfPath = join(REPO, 'self_blockcomp.nsz');
    writeFileSync(selfPath, nsz1);
    let refused = null;
    try {
        runCli(['--compress', selfPath]);
    } catch (e) { refused = e; }
    check('5a2. CLI: self-named (*_blockcomp.nsz) input refused',
        refused && refused.status === 1 && /would overwrite the input/.test(refused.stderr.toString()),
        refused ? `exit=${refused.status} ${refused.stderr.toString().trim().split('\n').pop().slice(0, 80)}` : 'no error');

    // 5b. -o <dir> + level 3 → <dir>/in_blockcomp.nsz, round-trips.
    const outDir = join(REPO, 'out');
    mkdirSync(outDir, { recursive: true });
    try {
        runCli(['--compress', inPath, '-o', outDir, '-l', '3']);
        const outBytes = new Uint8Array(readFileSync(join(outDir, 'in_blockcomp.nsz')));
        check('5b. CLI: --compress in.nsz -o out -l 3 → in_blockcomp.nsz round-trips',
            sameBytes(await decompressNczMember(outBytes, memberName), program.nca));
    } catch (e) {
        check('5b. CLI: --compress in.nsz -o out -l 3', false,
            `${e.message}\n${e.stderr ? e.stderr.toString().slice(-300) : ''}`);
    }

    // 5b2. -o <dir> + solid → in_solidcomp.nsz (a different name for a
    // different layout), round-trips.
    const outDir2 = join(REPO, 'out2');
    mkdirSync(outDir2, { recursive: true });
    try {
        runCli(['--compress', inPath, '-o', outDir2, '-S']);
        const outBytes = new Uint8Array(readFileSync(join(outDir2, 'in_solidcomp.nsz')));
        check('5b2. CLI: --compress in.nsz -o out2 -S → in_solidcomp.nsz round-trips',
            sameBytes(await decompressNczMember(outBytes, memberName), program.nca));
    } catch (e) {
        check('5b2. CLI: --compress in.nsz -o out2 -S', false,
            `${e.message}\n${e.stderr ? e.stderr.toString().slice(-300) : ''}`);
    }

    // 5b3. Fresh .nsp input → <dir>/in_blockcomp.nsz too (uniform naming).
    const nspPath = join(REPO, 'in.nsp');
    writeFileSync(nspPath, nsp);
    const outDir3 = join(REPO, 'out3');
    mkdirSync(outDir3, { recursive: true });
    try {
        runCli(['--compress', nspPath, '-o', outDir3, '-l', '3']);
        const outBytes = new Uint8Array(readFileSync(join(outDir3, 'in_blockcomp.nsz')));
        check('5b3. CLI: fresh in.nsp -o out3 → in_blockcomp.nsz (uniform naming) round-trips',
            sameBytes(await decompressNczMember(outBytes, memberName), program.nca));
    } catch (e) {
        check('5b3. CLI: fresh in.nsp -o out3', false,
            `${e.message}\n${e.stderr ? e.stderr.toString().slice(-300) : ''}`);
    }

    // 5c. Foreign extension refused.
    const badPath = join(REPO, 'bad.txt');
    writeFileSync(badPath, 'x');
    let refused2 = null;
    try {
        runCli(['--compress', badPath]);
    } catch (e) { refused2 = e; }
    check('5c. CLI: foreign extension refused', refused2 && refused2.status === 1 && /supports/.test(refused2.stderr.toString()));
}

// ── 6. Real file: base.nsz (solid, BKTR program) → block re-compression ────
{
    let fd = null;
    try {
        fd = openSync(BASE_NSZ, 'r');
    } catch {
        console.log(`  SKIP 6. real file: ${BASE_NSZ} not present`);
        fd = null;
    }
    if (fd !== null) {
        const size = fstatSync(fd).size;
        const reader = {
            read: (off, sz) => { const b = Buffer.alloc(sz); readSync(fd, b, 0, sz, off); return new Uint8Array(b); },
            length: size,
        };
        const origFiles = (await PFS0.open(reader)).getFiles();

        // Per-member reference hashes: .ncz members → payload [0x4000, ncaSize)
        // (sections decrypted per the NCZSECTN table); others → whole file.
        const ref = new Map();
        for (const f of origFiles) {
            if (f.name.toLowerCase().endsWith('.ncz')) {
                const nczd = new NCZDecompressor(new AdapterNCZReader(reader, f.offset, f.size));
                const h = createHash('sha256');
                let bytes = 0;
                await nczd.decompress(null, async (chunk, pos) => { if (pos >= 0x4000) { h.update(chunk); bytes += chunk.length; } });
                ref.set(f.name, { sha: h.digest('hex'), bytes });
            } else {
                const b = Buffer.alloc(f.size);
                readSync(fd, b, 0, f.size, f.offset);
                ref.set(f.name, { sha: createHash('sha256').update(b).digest('hex'), bytes: f.size });
            }
        }

        const t0 = performance.now();
        const res = await compressNSPtoNSZ(reader, { memory: true }, {
            keys, keep: false, level: 3, mode: 'block',
            log: (lvl, msg) => console.log(`  [${lvl}] ${msg}`),
            progress: () => {},
        });
        closeSync(fd);
        const blob = new Uint8Array(await res.blob.arrayBuffer());
        console.log(`  re-compressed ${size} → ${res.size} bytes, ${res.memberCount} members, ${((performance.now() - t0) / 1000).toFixed(1)}s`);

        check('6. real: member count preserved', res.memberCount === origFiles.length, `${res.memberCount} vs ${origFiles.length}`);
        const outFiles = (await PFS0.open(memReader(blob))).getFiles();
        for (const of of outFiles) {
            const r = ref.get(of.name);
            if (!r) { check(`6. real: ${of.name} present in input`, false); continue; }
            if (of.name.toLowerCase().endsWith('.ncz')) {
                const nczd = new NCZDecompressor(blob.subarray(of.offset, of.offset + of.size));
                const h = createHash('sha256');
                let bytes = 0;
                await nczd.decompress(null, async (chunk, pos) => { if (pos >= 0x4000) { h.update(chunk); bytes += chunk.length; } });
                const hex = h.digest('hex');
                check(`6. real: ${of.name} payload sha256 identical (${bytes} bytes)`,
                    hex === r.sha && bytes === r.bytes,
                    hex === r.sha ? '' : `got ${hex}, want ${r.sha}`);
            } else {
                check(`6. real: ${of.name} copied verbatim`, sha256(blob.subarray(of.offset, of.offset + of.size)) === r.sha);
            }
        }
    }
}

rmSync(REPO, { recursive: true, force: true });
console.log(failures === 0 ? '\nALL PASSED' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
