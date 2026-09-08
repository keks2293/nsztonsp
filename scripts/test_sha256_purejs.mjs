// Byte-identity verification for the pure-JS SHA256 class against node:crypto.
// Covers: known vectors, various sizes, multi-update, clone, alignments, strings.
import { createHash } from 'node:crypto';
import { SHA256 } from '../crypto/sha256.js';

const known = [
    '',
    'a',
    'abc',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
    'message digest',
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
];

let pass = 0, fail = 0;

function check(label, ref, ours) {
    if (ref === ours) { pass++; }
    else { fail++; console.log(`FAIL ${label}: ref=${ref} ours=${ours}`); }
}

// Known vectors
for (const s of known) {
    const ref = createHash('sha256').update(s).digest('hex');
    const h = new SHA256(); h.update(s);
    check(`known:${s.slice(0,20)}`, ref, h.hex());
}

// Multi-byte-per-update: various sizes around block boundary
for (const size of [1, 3, 55, 56, 57, 63, 64, 65, 127, 128, 129, 512, 4096, 65536, 1048576]) {
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = (i * 137 + 43) & 0xff;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256(); h.update(data);
    check(`size:${size}`, ref, h.hex());
}

// Byte-by-byte
for (const size of [1, 55, 64, 65, 128, 1000]) {
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = (i * 53 + 11) & 0xff;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256();
    for (let i = 0; i < size; i++) h.update(new Uint8Array([data[i]]));
    check(`b2b:${size}`, ref, h.hex());
}

// Various chunk sizes
for (const chunkSize of [3, 7, 15, 17, 31, 32, 33, 63, 65, 100, 511, 512, 513, 1024, 4096]) {
    const size = 10000;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = (i * 97 + 7) & 0xff;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256();
    for (let off = 0; off < size; off += chunkSize) {
        h.update(data.subarray(off, Math.min(off + chunkSize, size)));
    }
    check(`chunk:${chunkSize}`, ref, h.hex());
}

// String input
for (const s of ['hello', 'αβγδ', '\u0000\u00ff', 'a'.repeat(200)]) {
    const ref = createHash('sha256').update(s, 'utf8').digest('hex');
    const h = new SHA256(); h.update(s);
    check(`str:${JSON.stringify(s).slice(0,20)}`, ref, h.hex());
}

// Clone mid-stream
{
    const size = 2000;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = (i * 113 + 29) & 0xff;
    const mid = 999;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256(); h.update(data.subarray(0, mid));
    const c = h.clone();
    h.update(data.subarray(mid));
    c.update(data.subarray(mid));
    check('clone:full', ref, h.hex());
    check('clone:cloned', ref, c.hex());
}

// Clone at block boundary
{
    const size = 128;
    const data = new Uint8Array(size);
    for (let i = 0; i < size; i++) data[i] = (i * 41 + 3) & 0xff;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256(); h.update(data.subarray(0, 64));
    const c = h.clone();
    h.update(data.subarray(64));
    c.update(data.subarray(64));
    check('clone:block-boundary', ref, h.hex());
    check('clone:block-boundary-cloned', ref, c.hex());
}

// Subarray with non-zero offset (tests buffer alignment handling)
{
    const base = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) base[i] = (i * 67 + 19) & 0xff;
    for (const off of [1, 3, 5, 7]) {
        const sub = base.subarray(off, off + 512);
        const ref = createHash('sha256').update(sub).digest('hex');
        const h = new SHA256(); h.update(sub);
        check(`sub:${off}`, ref, h.hex());
    }
}

// Multiple clones in chain
{
    const data = new Uint8Array(4096);
    for (let i = 0; i < 4096; i++) data[i] = (i * 79 + 11) & 0xff;
    const ref = createHash('sha256').update(data).digest('hex');
    const h = new SHA256();
    h.update(data.subarray(0, 1024));
    const c1 = h.clone();
    h.update(data.subarray(1024, 2048));
    const c2 = h.clone();
    h.update(data.subarray(2048, 3072));
    const c3 = h.clone();
    h.update(data.subarray(3072));
    c3.update(data.subarray(3072));
    c2.update(data.subarray(2048));
    c1.update(data.subarray(1024));
    check('chain:full', ref, h.hex());
    check('chain:c3', ref, c3.hex());
    check('chain:c2', ref, c2.hex());
    check('chain:c1', ref, c1.hex());
}

console.log(`SHA256 pure-JS: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
