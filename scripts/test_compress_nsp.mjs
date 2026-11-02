// Round-trip test for NSP→NSZ compression (fs/compress.js).
//
// 1. Compress the merged Stardew NSP (2 PROGRAM NCAs: base + BKTR update) to
//    an in-memory NSZ via compressNSPtoNSZ.
// 2. Verify the compression plan (only the 2 PROGRAM NCAs compress; everything
//    else copies verbatim).
// 3. Byte-compare the generated NCZSECTN tables against the REAL Python-nsz
//    base.nsz / update.nsz tables (offsets, sizes, cryptoTypes, keys, counters).
// 4. Decompress the generated NSZ back to NSP via decompressNSZ (fd output).
// 5. Compare per-member SHA-256 of the original vs. regenerated NSP.
//
// Usage: node scripts/test_compress_nsp.mjs
import { openSync, closeSync, readSync, fstatSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { KeysParser } from '../keys.js';
import { PFS0 } from '../fs/pfs0.js';
import { compressNSPtoNSZ } from '../fs/compress.js';
import { decompressNSZ } from '../fs/nsz-decompress.js';

const NSP_PATH = '.playwright-mcp/Stardew-Valley-0100E65002BB8000-v0-0-87-GB-merged.nsp';
const BASE_NSZ = '.playwright-mcp/base.nsz';
const UPDATE_NSZ = '.playwright-mcp/update.nsz';
const BASE_ID = '1650ab6235ae16751ca5e220b414c3f1';
const UPDATE_ID = 'd11817aed845099f66eac23f95545d78';

let failures = 0;
function check(name, cond, detail = '') {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
    if (!cond) failures++;
}

function fdReader(fd) {
    return {
        read: (off, size) => {
            const b = Buffer.alloc(size);
            readSync(fd, b, 0, size, off);
            return new Uint8Array(b);
        },
    };
}

const keys = KeysParser.parse(readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const nspSize = fstatSync(openSync(NSP_PATH, 'r')).size;

// ── 0b. Gap test: synthetic NSP with a delta (DATA) NCA ─────────────────────
// Python Pfs0Stream writes the first member at the INPUT's firstFileOffset.
// Dropping a delta shrinks the output header (fewer entries) → a zero gap
// remains after the output header. Exercises the full path: delta drop +
// explicit gap zero-write + PFS0Writer.firstOffset + totalSize.
{
    const { AesXts } = await import('../crypto/aes128.js');
    const { toKeyBytes } = await import('../fs/nca-utils.js');

    const deltaName = 'abcdef0123456789abcdef0123456789.nca';
    const binName = 'data.bin';
    const binSize = 0x100;
    const ncaSize = 0xC00;

    // Minimal valid NCA header for a DATA (delta fragment) NCA: the NCAHeader
    // struct starts at 0x200 (0x000-0x200 is the signature region) — 'NCA3'
    // magic @0x200, contentType=DATA @0x205, everything else zero, the whole
    // 0xC00 XTS-encrypted with header_key.
    const h = new Uint8Array(ncaSize);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);
    h[0x205] = 0x04; // DATA
    h[0x206] = 0x01; // crypto type NONE (python numbering)
    new DataView(h.buffer).setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from('0100E65002BB8000', 'hex'), 0x210);
    h[0x220] = 0x01;
    const encHeader = new AesXts(toKeyBytes(keys.header_key)).encrypt(h, 0);

    const bin = new Uint8Array(binSize);
    for (let i = 0; i < binSize; i++) bin[i] = (i * 7) & 0xFF;

    // PFS0 entry offsets are RELATIVE to the header end. The input header is
    // deliberately left UN-padded (strtab = exact length) so its firstFileOffset
    // (0x6E) is not 0x10-aligned — the output header (fewer members after the
    // delta drop) is even smaller, which is what creates the zero gap.
    const strtab = deltaName + '\0' + binName + '\0';
    const inputHeaderSize = 0x10 + 2 * 0x18 + strtab.length; // 0x6E
    const inputFirstFileOffset = inputHeaderSize;
    const nsp = new Uint8Array(inputFirstFileOffset + ncaSize + binSize);
    const dv = new DataView(nsp.buffer);
    nsp.set([0x50, 0x46, 0x53, 0x30], 0);
    dv.setUint32(4, 2, true);
    dv.setUint32(8, strtab.length, true);
    let eo = 0x10;
    dv.setBigUint64(eo, 0n, true);
    dv.setBigUint64(eo + 8, BigInt(ncaSize), true);
    dv.setUint32(eo + 16, 0, true);
    eo += 0x18;
    dv.setBigUint64(eo, BigInt(ncaSize), true);
    dv.setBigUint64(eo + 8, BigInt(binSize), true);
    dv.setUint32(eo + 16, deltaName.length + 1, true);
    nsp.set(new TextEncoder().encode(strtab), 0x10 + 2 * 0x18);
    nsp.set(encHeader, inputFirstFileOffset);
    nsp.set(bin, inputFirstFileOffset + ncaSize);

    const memReader = { read: async (off, size) => nsp.subarray(off, off + size) };

    for (const keepFlag of [false, true]) {
        const res = await compressNSPtoNSZ(memReader, { memory: true }, { keys, keep: keepFlag, log: () => {}, progress: () => {} });
        const blob = new Uint8Array(await res.blob.arrayBuffer());
        const outPfs0 = await PFS0.open({ read: async (off, size) => blob.subarray(off, off + size) });
        const outFiles = outPfs0.getFiles();
        const outHeaderSize = outPfs0.headerSize;
        const gap = inputFirstFileOffset - outHeaderSize;
        const tag = keepFlag ? 'keep=true' : 'keep=false';

        if (!keepFlag) {
            check(`gap (${tag}): delta dropped, 1 member left`, outFiles.length === 1 && outFiles[0].name === binName, outFiles.map(f => f.name).join(', '));
            check(`gap (${tag}): gap > 0`, gap > 0, `gap=${gap}`);
            check(`gap (${tag}): first member at input firstFileOffset`, outFiles[0].offset === inputFirstFileOffset,
                `0x${outFiles[0].offset.toString(16)} vs 0x${inputFirstFileOffset.toString(16)}`);
            let zero = true;
            for (let i = outHeaderSize; i < inputFirstFileOffset; i++) if (blob[i]) { zero = false; break; }
            check(`gap (${tag}): gap bytes are zero`, zero);
            check(`gap (${tag}): data intact`, Buffer.from(blob.subarray(outFiles[0].offset, outFiles[0].offset + binSize)).equals(Buffer.from(bin)));
            check(`gap (${tag}): total size`, res.size === inputFirstFileOffset + binSize, `${res.size} vs ${inputFirstFileOffset + binSize}`);
        } else {
            check(`gap (${tag}): 2 members kept`, outFiles.length === 2, outFiles.map(f => f.name).join(', '));
            check(`gap (${tag}): first member at input firstFileOffset`, outFiles[0].offset === inputFirstFileOffset,
                `0x${outFiles[0].offset.toString(16)} vs 0x${inputFirstFileOffset.toString(16)}`);
            if (gap > 0) {
                let zero = true;
                for (let i = outHeaderSize; i < inputFirstFileOffset; i++) if (blob[i]) { zero = false; break; }
                check(`gap (${tag}): gap bytes are zero (gap=${gap})`, zero);
            }
        }
    }
}

// ── 0. Memory adapter: overlap-safe writes (defensive path) ─────────────────
// The compressor no longer double-writes (size list is written once, at the end),
// but the adapter must still keep _chunks sorted AND disjoint when an incoming
// write overlaps existing ones (last write wins). collectBlob concatenates
// chunks in place, so any hole/overlap would silently corrupt the blob.
{
    const { buildAdapter, collectBlob } = await import('../fs/adapter.js');
    const enc = (s) => new TextEncoder().encode(s);
    const blobOf = async (target, size) => new Uint8Array(await collectBlob(target, size).arrayBuffer());
    const asciiOf = (u8) => Buffer.from(u8).toString('latin1');

    // Partial overlap at the tail: 5..10 overwrites 'fghij'.
    const t1 = { memory: true };
    const a1 = await buildAdapter(t1, () => {}, {});
    a1.write(0, enc('abcdefghij'));
    a1.write(5, enc('WORLD'));
    check('adapter: tail overlap (last write wins)', asciiOf(await blobOf(t1, 10)) === 'abcdeWORLD', asciiOf(await blobOf(t1, 10)));

    // Middle overlap: 4..8 overwrites '4567' and splits the first chunk into 0..4 and 8..10.
    const t2 = { memory: true };
    const a2 = await buildAdapter(t2, () => {}, {});
    a2.write(0, enc('0123456789'));
    a2.write(4, enc('WXYZ'));
    a2.write(10, enc('END'));
    check('adapter: middle overlap splits chunks', asciiOf(await blobOf(t2, 13)) === '0123WXYZ89END', asciiOf(await blobOf(t2, 13)));

    // Containment: a new write fully covers earlier chunks.
    const t3 = { memory: true };
    const a3 = await buildAdapter(t3, () => {}, {});
    a3.write(0, enc('abc'));
    a3.write(2, enc('de'));
    a3.write(0, enc('A'.repeat(20)));
    check('adapter: containment drops covered chunks', asciiOf(await blobOf(t3, 20)) === 'A'.repeat(20), asciiOf(await blobOf(t3, 20)).slice(0, 8) + '…');

    // Out-of-order writes (seek-back pattern: data first, header last) must stay
    // sorted in the blob, and the unwritten hole [3,16) is materialized as
    // zeros at collect time (sparse-file semantics — the blob extends past
    // totalSize to the last written byte).
    const t4 = { memory: true };
    const a4 = await buildAdapter(t4, () => {}, {});
    a4.write(16, enc('DATA-REGION'));
    a4.write(0, enc('HDR'));
    const b4 = await blobOf(t4, 14);
    check('adapter: out-of-order writes stay sorted, hole zero-filled',
        b4.length === 27 && asciiOf(b4) === 'HDR' + '\u0000'.repeat(13) + 'DATA-REGION',
        b4.length + 'B: ' + asciiOf(b4).replace(/\u0000/g, '·'));

    // Interior + tail holes: chunks [0,4), [5,7), [12,16) with totalSize 20 →
    // zeros fill [4,5), [7,12) and pad the tail to 20.
    const t5 = { memory: true };
    const a5 = await buildAdapter(t5, () => {}, {});
    a5.write(0, enc('abcd'));
    a5.write(5, enc('XY'));
    a5.write(12, enc('tail'));
    const b5 = await blobOf(t5, 20);
    check('adapter: interior hole + tail padded to totalSize',
        b5.length === 20 && asciiOf(b5) === 'abcd\u0000XY' + '\u0000'.repeat(5) + 'tail' + '\u0000'.repeat(4),
        b5.length + 'B: ' + asciiOf(b5).replace(/\u0000/g, '·'));
}

// ── 0c. Compression options on a synthetic CTR NCA ──────────────────────────
// Builds a small PROGRAM NCA (0x64000: raw 0x4000 header + one 0x60000 CTR
// section) in a 1-member PFS0 NSP and exercises the python-nsz option set:
//   - level + blockSizeExponent (block mode), solid (one zstd frame), ldm
// Every variant must round-trip (NCZDecompressor → original NCA bytes), and the
// NCZSECTN table must be byte-identical across variants — options change only
// the payload layout, never the table.
{
    const { AesXts, AesEcb } = await import('../crypto/aes128.js');
    const { AesCtr } = await import('../crypto/aes-ops.mjs');
    const { toKeyBytes } = await import('../fs/nca-utils.js');
    const { NCZDecompressor } = await import('../fs/ncz.js');

    const ncaSize = 0x64000;
    const payloadSize = ncaSize - 0x4000;        // 0x60000 → 24 blocks at 2^14
    const titlekey = new Uint8Array(16).map((_, i) => i + 1);
    const head8 = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    const counter16 = new Uint8Array(16);
    counter16.set(head8);                          // low 8B filled by AesCtr.seek(offset)

    // Decrypted NCA header (XTS-encrypted below).
    const h = new Uint8Array(0xC00);
    const hv = new DataView(h.buffer);
    h.set([0x4E, 0x43, 0x41, 0x33], 0x200);        // 'NCA3'
    h[0x205] = 0x00;                               // PROGRAM
    h[0x206] = 0x00;                               // cryptoType 0 → master key 0
    h[0x207] = 0x00;                               // kaekInd 0
    hv.setBigUint64(0x208, BigInt(ncaSize), true);
    h.set(Buffer.from('0100E65002BB8000', 'hex'), 0x210);
    hv.setUint32(0x218, 1, true);                  // contentIndex
    hv.setUint32(0x240, 0x20, true);               // section 0: 0x20 × 0x200 = 0x4000
    hv.setUint32(0x244, 0x320, true);              // end: 0x320 × 0x200 = 0x64000
    // Key area slot 2 = titlekey, ECB-encrypted with key_area_keys[0][0]
    // (deriveTitlekeyFromKeyArea inverts exactly this).
    const plainKeyArea = new Uint8Array(0x40);
    plainKeyArea.set(titlekey, 0x20);
    h.set(new AesEcb(toKeyBytes(keys.keyAreaKeys[0][0])).encrypt(plainKeyArea), 0x300);
    // FsHeader[0]: PFS0 section (fsType from 0x03!), CTR_EX crypto, and the
    // section counter head stored REVERSED at 0x140 (SectionHeader reverses).
    h[0x402] = 2; h[0x403] = 2; h[0x404] = 3;
    hv.setBigUint64(0x448, BigInt(payloadSize), true);
    h.set(Buffer.from(head8).reverse(), 0x540);

    // Payload: CTR-encrypted from 0x4000 with counter = head8 || (offset/16) LE —
    // the exact keystream fillPlaintextBlock / the NCZ decompressor re-apply.
    const plain = new Uint8Array(payloadSize);
    for (let i = 0; i < payloadSize; i++) plain[i] = (i * 7 + (i >> 8) * 3) & 0xFF;
    const cipherPayload = new Uint8Array(await new AesCtr(titlekey, counter16, 0x4000).encrypt(plain));

    const nca = new Uint8Array(ncaSize);
    nca.set(new Uint8Array(new AesXts(toKeyBytes(keys.header_key)).encrypt(h, 0)), 0);
    nca.set(cipherPayload, 0x4000);

    // 1-member PFS0 NSP wrapping the NCA.
    const ncaName = '0100e65002bb8000.nca';
    const strtab = ncaName + '\0';
    const firstFileOffset = 0x10 + 0x18 + strtab.length;
    const nsp = new Uint8Array(firstFileOffset + ncaSize);
    const ndv = new DataView(nsp.buffer);
    nsp.set([0x50, 0x46, 0x53, 0x30], 0);
    ndv.setUint32(4, 1, true);
    ndv.setUint32(8, strtab.length, true);
    ndv.setBigUint64(0x10, 0n, true);
    ndv.setBigUint64(0x18, BigInt(ncaSize), true);
    ndv.setUint32(0x20, 0, true);
    nsp.set(new TextEncoder().encode(strtab), 0x28);
    nsp.set(nca, firstFileOffset);

    const memReader = { read: async (off, size) => nsp.subarray(off, off + size) };

    async function compressNsp(opts = {}) {
        const res = await compressNSPtoNSZ(memReader, { memory: true }, {
            keys, keep: false, log: () => {}, progress: () => {}, ...opts,
        });
        const blob = new Uint8Array(await res.blob.arrayBuffer());
        const pfs0 = await PFS0.open({ read: async (off, size) => blob.subarray(off, off + size) });
        const files = pfs0.getFiles();
        const nczFile = files.find(f => f.name.toLowerCase().endsWith('.ncz'));
        return { res, blob, files, nczFile };
    }
    async function roundTrip(nczFile, blob) {
        const nczBytes = blob.subarray(nczFile.offset, nczFile.offset + nczFile.size);
        return new NCZDecompressor(nczBytes).decompress();
    }
    // One section → table = 16 + 1×64 bytes at 0x4000.
    const tableOf = (blob, nczFile) =>
        Buffer.from(blob.subarray(nczFile.offset + 0x4000, nczFile.offset + 0x4000 + 80));
    const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
    const blockHdr = (blob, nczFile) =>
        blob.subarray(nczFile.offset + 0x4000 + 80, nczFile.offset + 0x4000 + 80 + 24);

    // 1. Default: block mode, level 18, 1 MiB blocks (single block).
    const dflt = await compressNsp();
    check('opt default: NCA compressed to .ncz', dflt.files.length === 1 && !!dflt.nczFile,
        dflt.files.map(f => f.name).join(', '));
    let bh = blockHdr(dflt.blob, dflt.nczFile);
    let bdv = new DataView(bh.buffer, bh.byteOffset);
    check('opt default: NCZBLOCK exp=20, 1 block, decomp=0x60000',
        String.fromCharCode(bh[0], bh[1], bh[2], bh[3], bh[4], bh[5], bh[6], bh[7]) === 'NCZBLOCK'
        && bh[11] === 20 && bdv.getUint32(12, true) === 1
        && Number(bdv.getBigUint64(16, true)) === payloadSize,
        `magic=${String.fromCharCode(bh[0], bh[1], bh[2], bh[3])} exp=${bh[11]}`);
    check('opt default: round-trip identical', sameBytes(await roundTrip(dflt.nczFile, dflt.blob), nca));

    // 2. Solid: ONE zstd frame right after the table, no NCZBLOCK header.
    // Frame magic = 0xFD2FB528, stored little-endian → bytes 28 B5 2F FD.
    const solid = await compressNsp({ mode: 'solid' });
    bh = blockHdr(solid.blob, solid.nczFile);
    check('opt solid: zstd frame after the table (magic 0xFD2FB528 LE)',
        bh[0] === 0x28 && bh[1] === 0xB5 && bh[2] === 0x2F && bh[3] === 0xFD,
        [bh[0], bh[1], bh[2], bh[3]].map(b => '0x' + b.toString(16)).join(' '));
    check('opt solid: round-trip identical', sameBytes(await roundTrip(solid.nczFile, solid.blob), nca));
    check('opt solid: table identical to default',
        tableOf(solid.blob, solid.nczFile).equals(tableOf(dflt.blob, dflt.nczFile)));

    // 3. level 3 + bsExp 14 (16 KiB blocks → 24 blocks).
    const small = await compressNsp({ level: 3, blockSizeExponent: 14 });
    bh = blockHdr(small.blob, small.nczFile);
    bdv = new DataView(bh.buffer, bh.byteOffset);
    check('opt level3/bs14: NCZBLOCK exp=14, 24 blocks, decomp=0x60000',
        bh[11] === 14 && bdv.getUint32(12, true) === 24
        && Number(bdv.getBigUint64(16, true)) === payloadSize,
        `exp=${bh[11]} blocks=${bdv.getUint32(12, true)}`);
    check('opt level3/bs14: round-trip identical', sameBytes(await roundTrip(small.nczFile, small.blob), nca));
    check('opt level3/bs14: table identical to default',
        tableOf(small.blob, small.nczFile).equals(tableOf(dflt.blob, dflt.nczFile)));

    // 4. ldm (block mode, long-distance matching).
    const ldm = await compressNsp({ ldm: true });
    check('opt ldm: round-trip identical', sameBytes(await roundTrip(ldm.nczFile, ldm.blob), nca));

    // 5. Invalid options are rejected (before any payload work).
    for (const [opts, label] of [
        [{ level: 0 }, 'level 0'],
        [{ level: 23 }, 'level 23'],
        [{ level: '18' }, 'level "18"'],
        [{ blockSizeExponent: 13 }, 'bsExp 13'],
        [{ blockSizeExponent: 33 }, 'bsExp 33'],
        [{ mode: 'bogus' }, 'mode "bogus"'],
    ]) {
        let threw = false;
        try { await compressNsp(opts); } catch (e) { threw = /Invalid/.test(e.message); }
        check(`opt validation: ${label} rejected`, threw);
    }
}

// ── 1. Compress ─────────────────────────────────────────────────────────────
{
    const fd = openSync(NSP_PATH, 'r');
    const reader = fdReader(fd);
    const t0 = performance.now();
    const res = await compressNSPtoNSZ(reader, { memory: true }, {
        keys,
        log: (lvl, msg) => console.log(`  [${lvl}] ${msg}`),
        progress: () => {},
    });
    closeSync(fd);
    console.log(`\nNSZ built: ${res.size} bytes, ${res.memberCount} members, ${((performance.now() - t0) / 1000).toFixed(1)}s`);

    // ── 2. Plan verification ────────────────────────────────────────────────
    const nspPfs0 = await PFS0.open(fdReader(openSync(NSP_PATH, 'r')));
    const nspByName = new Map(nspPfs0.getFiles().map(f => [f.name, f]));

    const nszBlob = res.blob;
    const nszReader = {
        read: async (off, size) => new Uint8Array(await nszBlob.slice(off, off + size).arrayBuffer()),
        length: nszBlob.size,
    };
    const nszPfs0 = await PFS0.open(nszReader);
    const nszFiles = nszPfs0.getFiles();

    const compressed = new Map();
    for (const f of nszFiles) {
        if (f.name.toLowerCase().endsWith('.ncz')) {
            compressed.set(f.name.replace(/\.ncz$/i, ''), f);
        }
    }
    check('exactly 2 NCAs compressed', compressed.size === 2, [...compressed.keys()].map(k => k.slice(0, 8)).join(', '));
    check('base NCA compressed', compressed.has(BASE_ID));
    check('update NCA compressed', compressed.has(UPDATE_ID));

    // All other members copied with the same size + name.
    let copyOk = true, copyDetail = '';
    for (const f of nszFiles) {
        if (f.name.toLowerCase().endsWith('.ncz')) continue;
        const orig = nspByName.get(f.name);
        if (!orig || orig.size !== f.size) { copyOk = false; copyDetail = f.name; break; }
    }
    check('all non-NCA members copied (name+size)', copyOk, copyDetail);

    // Python Pfs0Stream places the FIRST member at the input's firstFileOffset
    // (f.seek(headerSize) with headerSize = container.getFirstFileOffset()): if
    // the output header is smaller, a zero gap remains after it.
    const nspFirstOffset = nspPfs0.getFiles()[0].offset;
    check('first member offset == input firstFileOffset', nszFiles[0].offset === nspFirstOffset,
        `0x${nszFiles[0].offset.toString(16)} vs 0x${nspFirstOffset.toString(16)}`);
    {
        const gapStart = nszPfs0.headerSize;
        if (gapStart < nszFiles[0].offset) {
            const gapBuf = await nszReader.read(gapStart, nszFiles[0].offset - gapStart);
            let allZero = true;
            for (const b of gapBuf) { if (b) { allZero = false; break; } }
            check('gap after output header is zero', allZero, `${gapBuf.length} bytes (0x${gapStart.toString(16)}..0x${nszFiles[0].offset.toString(16)})`);
        } else {
            check('no gap (output header >= firstFileOffset)', gapStart >= nszFiles[0].offset, `header=0x${gapStart.toString(16)}`);
        }
    }

    // Compression actually shrank the big NCAs.
    for (const [id, f] of compressed) {
        const orig = nspByName.get(id + '.nca');
        const ratio = (f.size / orig.size * 100).toFixed(1);
        check(`${id.slice(0, 8)}… shrank`, f.size < orig.size, `${(orig.size / 1048576).toFixed(0)} MB → ${(f.size / 1048576).toFixed(0)} MB (${ratio}%)`);
    }

    // ── 3. NCZSECTN table byte-compare vs real Python NCZ ──────────────────
    async function readNczTable(file, offset) {
        const fd = openSync(file, 'r');
        const r = fdReader(fd);
        const head = await r.read(offset + 0x4000, 16);
        const magic = String.fromCharCode(head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);
        if (magic !== 'NCZSECTN') { closeSync(fd); throw new Error(`no NCZSECTN in ${file}: got '${magic}'`); }
        const count = Number(new DataView(head.buffer, head.byteOffset).getBigUint64(8, true));
        const table = await r.read(offset + 0x4000, 16 + count * 64);
        closeSync(fd);
        return { table: Buffer.from(table), count };
    }
    async function readGeneratedNczTable(id) {
        const f = nszFiles.find(x => x.name.toLowerCase() === id + '.ncz');
        const head = await nszReader.read(f.offset + 0x4000, 16);
        const magic = String.fromCharCode(head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);
        if (magic !== 'NCZSECTN') throw new Error(`no NCZSECTN in generated ${id}.ncz: got '${magic}'`);
        const count = Number(new DataView(head.buffer, head.byteOffset).getBigUint64(8, true));
        return { table: Buffer.from(await nszReader.read(f.offset + 0x4000, 16 + count * 64)), count };
    }

    function checkTable(label, real, gen) {
        check(`${label} NCZ table: same section count`, gen.count === real.count, `${gen.count} vs ${real.count}`);
        if (gen.count === real.count && !gen.table.equals(real.table)) {
            for (let i = 0; i < gen.count; i++) {
                const a = real.table.subarray(16 + i * 64, 16 + (i + 1) * 64);
                const b = gen.table.subarray(16 + i * 64, 16 + (i + 1) * 64);
                if (!a.equals(b)) {
                    check(`${label} NCZ table: bytes identical`, false,
                        `first diff at entry ${i}:\n     real=${a.toString('hex')}\n     gen =${b.toString('hex')}`);
                    return;
                }
            }
        }
        check(`${label} NCZ table: bytes identical`, gen.table.equals(real.table));
    }

    const baseRefPfs0 = await PFS0.open(fdReader(openSync(BASE_NSZ, 'r')));
    const realBase = await readNczTable(BASE_NSZ, baseRefPfs0.getFiles().find(x => x.name.startsWith(BASE_ID)).offset);
    const genBase = await readGeneratedNczTable(BASE_ID);
    checkTable('base', realBase, genBase);

    const updPfs0 = await PFS0.open(fdReader(openSync(UPDATE_NSZ, 'r')));
    const realUpd = await readNczTable(UPDATE_NSZ, updPfs0.getFiles().find(x => x.name.startsWith(UPDATE_ID)).offset);
    const genUpd = await readGeneratedNczTable(UPDATE_ID);
    checkTable('update', realUpd, genUpd);

    // NCZBLOCK header sanity.
    {
        const f = nszFiles.find(x => x.name.toLowerCase() === BASE_ID + '.ncz');
        const sectnLen = 16 + genBase.count * 64;
        const bh = await nszReader.read(f.offset + 0x4000 + sectnLen, 24);
        const magic = String.fromCharCode(bh[0], bh[1], bh[2], bh[3], bh[4], bh[5], bh[6], bh[7]);
        const v = new DataView(bh.buffer, bh.byteOffset);
        const exp = bh[11];
        const nblocks = v.getUint32(12, true);
        const decomp = Number(v.getBigUint64(16, true));
        const origNcaSize = nspByName.get(BASE_ID + '.nca').size;
        check('base NCZBLOCK header', magic === 'NCZBLOCK' && exp === 20 && nblocks > 0 && decomp === origNcaSize - 0x4000,
            `${magic} exp=${exp} blocks=${nblocks} decomp=0x${decomp.toString(16)}`);
    }

    // ── 4. Decompress the generated NSZ ─────────────────────────────────────
    const scratch = mkdtempSync(join(tmpdir(), 'nsz-compress-test-'));
    const outPath = join(scratch, 'roundtrip.nsp');
    const outFd = openSync(outPath, 'w');
    try {
        const t1 = performance.now();
        const res2 = await decompressNSZ(nszReader, { fd: outFd }, {
            log: (lvl, msg) => { if (!msg.startsWith('[timing]')) console.log(`  [${lvl}] ${msg}`); },
            progress: () => {},
        });
        console.log(`\nNSZ→NSP done: ${res2.size} bytes, ${((performance.now() - t1) / 1000).toFixed(1)}s`);
        check('regenerated NSP size == original', res2.size === nspSize, `${res2.size} vs ${nspSize}`);

        // ── 5. Per-member SHA-256 comparison ────────────────────────────────
        async function hashMembers(containerPath, pfs0) {
            const fd = openSync(containerPath, 'r');
            const r = fdReader(fd);
            const out = new Map();
            for (const f of pfs0.getFiles()) {
                const h = createHash('sha256');
                for (let pos = 0; pos < f.size; pos += 16 * 1048576) {
                    const n = Math.min(16 * 1048576, f.size - pos);
                    h.update(await r.read(f.offset + pos, n));
                }
                out.set(f.name, h.digest('hex'));
            }
            closeSync(fd);
            return out;
        }
        const t2 = performance.now();
        const origHashes = await hashMembers(NSP_PATH, nspPfs0);
        const newPfs0 = await PFS0.open(fdReader(openSync(outPath, 'r')));
        const newHashes = await hashMembers(outPath, newPfs0);
        console.log(`  (hashed ${origHashes.size} + ${newHashes.size} members, ${((performance.now() - t2) / 1000).toFixed(1)}s)`);

        check('same member count', origHashes.size === newHashes.size, `${origHashes.size} vs ${newHashes.size}`);
        let allMatch = true;
        for (const [name, hash] of origHashes) {
            if (newHashes.get(name) !== hash) {
                allMatch = false;
                console.log(`  mismatch ${name}: orig=${hash.slice(0, 16)}… new=${(newHashes.get(name) || 'missing').slice(0, 16)}…`);
            }
        }
        check('all member SHA-256 identical', allMatch);
    } finally {
        closeSync(outFd);
        rmSync(scratch, { recursive: true, force: true });
    }
}

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
