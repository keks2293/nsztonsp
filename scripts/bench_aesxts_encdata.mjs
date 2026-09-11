import { AesEcb, AesXts } from '../crypto/aes128.js';

const MIB = 1024 * 1024;
const SIZE = 64 * MIB;

const key = new Uint8Array(32);
for (let i = 0; i < 32; i++) key[i] = (i * 7 + 3) & 0xff;

const data = new Uint8Array(SIZE);
for (let i = 0; i < SIZE; i += 4) {
    data[i] = (i * 131) & 0xff;
    data[i + 1] = (i >> 8) & 0xff;
    data[i + 2] = (i >> 16) & 0xff;
    data[i + 3] = (i >> 24) & 0xff;
}

function best(xts, label, size = SIZE, runs = 5) {
    xts.encrypt(new Uint8Array(MIB));
    const chunk = data.subarray(0, size);
    const times = [];
    for (let i = 0; i < runs; i++) {
        const t0 = performance.now();
        xts.encrypt(chunk);
        const dt = performance.now() - t0;
        if (dt > 0) times.push(dt);
    }
    times.sort((a, b) => a - b);
    const best = times[0];
    const mbps = size / best / 1000;
    console.log(`${label}: ${mbps.toFixed(1)} MB/s (best ${best.toFixed(1)} ms, ${(size / 16).toFixed(0)} blocks)`);
    return mbps;
}

const xtsNew = new AesXts(key);
best(xtsNew, 'P2 new (key schedule hoisted)');

const xtsOld = new AesXts(key);
const key1 = key.subarray(0, 16);
xtsOld._encData = (block) => new AesEcb(key1).encryptBlock(block);

const SIZE_SMALL = 1 * MIB;
const mbNew = best(xtsNew, 'P2 new (key schedule hoisted)', SIZE_SMALL, 3);
const mbOld = best(xtsOld, 'old (new AesEcb per block)', SIZE_SMALL, 3);
console.log(`\nspeedup on 1 MiB: ${(mbNew / mbOld).toFixed(0)}x`);