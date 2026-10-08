#!/usr/bin/env node
// Probe NSZ entry bytes: name, offset, size, first 16 raw bytes, magic guesses.
import fs from 'fs';
import { PFS0 } from '../fs/pfs0.js';

class FdReader {
    constructor(fd, size) { this.fd = fd; this._length = size; }
    get length() { return this._length; }
    async read(offset, size) {
        const buf = Buffer.allocUnsafe(size);
        const n = fs.readSync(this.fd, buf, 0, size, offset);
        return new Uint8Array(buf.buffer, buf.byteOffset, n);
    }
}

const hex = (b) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

function ascii(b, n = 8) {
    return Array.from(b.subarray(0, n)).map(c => (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.').join('');
}

async function probe(filePath) {
    const size = fs.statSync(filePath).size;
    const fd = fs.openSync(filePath, 'r');
    const reader = new FdReader(fd, size);
    console.log(`\n===== ${filePath} (${size} bytes) =====`);
    const pfs0 = await PFS0.open(reader);
    const files = pfs0.getFiles();
    for (const f of files) {
        const head = await reader.read(f.offset, 16);
        console.log(`  ${f.name}  off=0x${f.offset.toString(16)} size=${f.size}  head=${hex(head)} '${ascii(head)}'`);
        // Also peek just before/at the end of the member
        const tailOff = Math.max(f.offset, f.offset + f.size - 16);
        const tail = await reader.read(tailOff, 16);
        console.log(`      tail@0x${tailOff.toString(16)}=${hex(tail)} '${ascii(tail)}'`);
    }
    fs.closeSync(fd);
}

for (const f of process.argv.slice(2)) await probe(f);
