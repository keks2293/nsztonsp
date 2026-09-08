// Micro-benchmark: pure-JS streaming SHA256 (SHA256 class) after the W64
// Int32Array schedule port. 128 MiB, 16 MiB chunks, aligned vs unaligned, best-of-5.
// Compares against node:crypto streaming (the native upper bound to know the headroom).
import { SHA256 } from '../crypto/sha256.js';
import { createHash } from 'node:crypto';

const MB = 128;
const chunkSize = 16 * 1024 * 1024;
const total = MB * 1024 * 1024;
const base = new Uint8Array(chunkSize + 1);
for (let i = 0; i < chunkSize; i += 4096) base[i] = (i * 31) & 0xff;
const aligned = base.subarray(0, chunkSize);
const unaligned = base.subarray(1, 1 + chunkSize);

function benchJs(data, runs = 5) {
    let best = Infinity;
    for (let r = 0; r < runs; r++) {
        const h = new SHA256();
        const t0 = performance.now();
        for (let fed = 0; fed < total; fed += chunkSize) h.update(data);
        h.hex();
        best = Math.min(best, performance.now() - t0);
    }
    return best;
}
function benchNative(data, runs = 5) {
    let best = Infinity;
    for (let r = 0; r < runs; r++) {
        const h = createHash('sha256');
        const t0 = performance.now();
        for (let fed = 0; fed < total; fed += chunkSize) h.update(data);
        h.digest();
        best = Math.min(best, performance.now() - t0);
    }
    return best;
}

for (const [name, data] of [['aligned', aligned], ['unaligned', unaligned]]) {
    const jsMs = benchJs(data);
    const natMs = benchNative(data);
    console.log(`pure-JS SHA256:  ${name} ${(MB / (jsMs / 1000)).toFixed(0)} MB/s`);
    console.log(`node crypto:     ${name} ${(MB / (natMs / 1000)).toFixed(0)} MB/s`);
}