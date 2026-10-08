#!/usr/bin/env node
// Truncated-container diagnostics: openContainer must reject a PFS0 whose
// entries point past the end of the file (instead of letting the NCA decoder
// later report a cryptic "bad magic ''"), and decryptNcaHeader must report a
// short read instead of XTS-decrypting empty input.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { KeysParser } from '../keys.js';
import { openContainer } from '../fs/container.js';
import { decryptNcaHeader } from '../fs/nca.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let failures = 0;

function check(name, cond, detail = '') {
    if (cond) {
        console.log(`  PASS ${name}`);
    } else {
        failures++;
        console.log(`  FAIL ${name} ${detail}`);
    }
}

// Minimal PFS0: one entry + string table + data.
function makePfs0(entryOffset, entrySize, dataLen) {
    const name = 'aabbccdd.nca\0';
    const strtabLen = name.length;
    const headerSize = 0x10 + 0x18 + strtabLen;
    const buf = new Uint8Array(headerSize + dataLen);
    const view = new DataView(buf.buffer);
    buf.set([0x50, 0x46, 0x53, 0x30], 0);        // PFS0
    view.setUint32(4, 1, true);                   // fileCount
    view.setUint32(8, strtabLen, true);           // stringTableSize
    view.setBigUint64(0x10, BigInt(entryOffset), true);
    view.setBigUint64(0x18, BigInt(entrySize), true);
    view.setUint32(0x20, 0, true);                // nameOffset
    for (let i = 0; i < name.length; i++) buf[0x28 + i] = name.charCodeAt(i);
    for (let i = 0; i < dataLen; i++) buf[headerSize + i] = i & 0xff;
    return buf;
}

function bufReader(buf, withLength = true) {
    return {
        async read(offset, size) { return buf.subarray(offset, offset + size); },
        get length() { if (!withLength) throw new Error('abstract'); return buf.length; },
    };
}

async function expectThrow(fn) {
    try { await fn(); return null; } catch (e) { return e; }
}

console.log('=== truncated container diagnostics ===');

// 1. Well-formed PFS0 still opens.
{
    const buf = makePfs0(0, 64, 64);
    const { entries } = await openContainer({ reader: bufReader(buf), name: 'ok.nsp' });
    check('valid PFS0 opens', entries.length === 1 && entries[0].name === 'aabbccdd.nca'
        && entries[0].offset === 0x10 + 0x18 + 13 && entries[0].size === 64,
        JSON.stringify(entries));
}

// 2. Entry past EOF → clear truncation error (the LOLLIPOP base .nsz case:
//    header claims a 7.1 GB program member inside a 2.85 GB file).
{
    const buf = makePfs0(0, 7144714070, 64);
    const err = await expectThrow(() => openContainer({ reader: bufReader(buf), name: 'LOLLIPOP CHAINSAW RePOP [0100DD301A686000][v0] (7.10 GB).nsz' }));
    check('truncated PFS0 rejected', !!err, 'no error thrown');
    check('error names the file', !!err && err.message.includes('LOLLIPOP'), err && err.message);
    check('error names the member', !!err && err.message.includes('aabbccdd.nca'), err && err.message);
    check('error says truncated', !!err && /truncated/i.test(err.message), err && err.message);
    check('error reports sizes', !!err && err.message.includes('7144714070'), err && err.message);
}

// 3. Reader without a usable length → check is skipped (no false positive).
{
    const buf = makePfs0(0, 7144714070, 64);
    const err = await expectThrow(() => openContainer({ reader: bufReader(buf, false), name: 'unknown-length.nsp' }));
    check('unknown length skips the bounds check', err === null, err && err.message);
}

// 4. decryptNcaHeader: empty/short input → explicit short-read error, not
//    "Failed to decrypt NCA header: bad magic ''".
{
    const keys = KeysParser.parse(fs.readFileSync(path.join(__dirname, '../static/prod.keys'), 'utf8'));
    const empty = await expectThrow(() => decryptNcaHeader(new Uint8Array(0), keys));
    check('empty header read rejected', !!empty && /short: got 0 bytes/.test(empty.message), empty && empty.message);
    check('empty header read is not a magic error', !!empty && !/bad magic/.test(empty.message), empty && empty.message);

    const short = await expectThrow(() => decryptNcaHeader(new Uint8Array(0x400), keys));
    check('0x400-byte header read rejected', !!short && /got 1024 bytes/.test(short.message), short && short.message);

    // Full-size garbage still fails the way it always did (bad magic), so a
    // genuinely wrong header_key is not masked by the new check.
    const garbage = await expectThrow(() => decryptNcaHeader(new Uint8Array(0xC00), keys));
    check('full-size garbage keeps the bad-magic error', !!garbage && /bad magic/.test(garbage.message), garbage && garbage.message);
}

console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
