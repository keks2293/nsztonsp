#!/usr/bin/env node
// Check whether candidate member offsets contain decryptable NCA headers,
// and locate "<?xml" / "PFS0" markers near the file tail.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { KeysParser } from '../keys.js';
import { decryptNcaHeader } from '../fs/nca.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keys = KeysParser.parse(fs.readFileSync(path.join(__dirname, '../static/prod.keys'), 'utf8'));

function readAt(fd, off, n) {
    const b = Buffer.alloc(n);
    const got = fs.readSync(fd, b, 0, n, off);
    return new Uint8Array(b.buffer, b.byteOffset, got);
}

function checkNca(fd, off, label) {
    try {
        const h = decryptNcaHeader(readAt(fd, off, 0xC00), keys);
        console.log(`  ${label} off=${off} (0x${off.toString(16)}): OK magic=${h.magic} titleId=${h.titleId} contentType=${h.contentType} size=${h.size}`);
        return true;
    } catch (e) {
        console.log(`  ${label} off=${off} (0x${off.toString(16)}): FAIL ${e.message}`);
        return false;
    }
}

function scan(fd, from, to, needle) {
    const hits = [];
    const chunkSize = 1 << 20;
    const nb = Buffer.from(needle, 'latin1');
    let prev = Buffer.alloc(nb.length - 1);
    for (let off = from; off < to; off += chunkSize - nb.length + 1) {
        const n = Math.min(chunkSize, to - off);
        const b = Buffer.alloc(n);
        const got = fs.readSync(fd, b, 0, n, off);
        const buf = Buffer.concat([prev, b.subarray(0, got)]);
        let idx = buf.indexOf(nb);
        while (idx !== -1) {
            hits.push(off + idx - prev.length);
            idx = buf.indexOf(nb, idx + 1);
        }
        prev = buf.subarray(buf.length - nb.length + 1);
        if (got < n) break;
    }
    return hits;
}

const file = process.argv[2];
const offsets = process.argv.slice(3).map(s => parseInt(s, 0));
const size = fs.statSync(file).size;
const fd = fs.openSync(file, 'r');
console.log(`${file}  size=${size}`);
for (const off of offsets) checkNca(fd, off, 'member');
// markers near tail
const tailFrom = Math.max(0, size - (1 << 20));
console.log('  "<?xml" near tail:', scan(fd, tailFrom, size, '<?xml').slice(-5));
console.log('  "PFS0" near tail:', scan(fd, tailFrom, size, 'PFS0').slice(-5));
fs.closeSync(fd);
