import { createHash } from 'node:crypto';

const MIB = 1024 * 1024;
const SIZE = 64 * MIB;

const data = new Uint8Array(SIZE);
for (let i = 0; i < SIZE; i += 64) {
    data[i] = (i * 131) & 0xff;
}

const copyHash = () => createHash('sha256').update(Buffer.from(data)).digest();
const viewHash = () => createHash('sha256').update(Buffer.from(data.buffer, data.byteOffset, data.byteLength)).digest();

const ref = viewHash();
if (Buffer.compare(copyHash(), ref) !== 0) throw new Error('output mismatch');

function best(fn, label) {
    fn();
    const times = [];
    for (let i = 0; i < 7; i++) {
        const t0 = performance.now();
        const out = fn();
        if (Buffer.compare(out, ref) !== 0) throw new Error('mismatch');
        times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    console.log(`${label}: ${(SIZE / times[0] / 1000).toFixed(1)} MB/s (best ${times[0].toFixed(1)} ms)`);
}

best(copyHash, 'with Buffer.from copy');
best(viewHash, 'zero-copy view');
best(copyHash, 'with Buffer.from copy');
best(viewHash, 'zero-copy view');