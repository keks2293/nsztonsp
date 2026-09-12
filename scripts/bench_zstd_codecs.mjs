#!/usr/bin/env node
// Codec-throughput microbench: decompress the FULL update NCZ (streaming mode)
// via node:zlib (native C), installed zstddec 0.2.0 (current browser decoder),
// and @bokuweb/zstd-wasm 0.0.27 (emscripten -O3 build). Output discarded,
// only wall time and MB/s reported. Best-of-3, run-once warmup per engine.
//
// Usage: node scripts/bench_zstd_codecs.mjs [--runs N]
import fs from 'node:fs';
import { performance } from 'node:perf_hooks';
import { PFS0 } from '../fs/pfs0.js';
import { parseNczSections } from '../fs/ncz.js';

const UPDATE_NSZ = '.playwright-mcp/update.nsz';
const args = process.argv.slice(2);
let RUNS = 3;
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--runs' && args[i + 1]) RUNS = parseInt(args[i + 1], 10);
}
const WARMUPS = 1;

const fileBuf = fs.readFileSync(UPDATE_NSZ);
const fsize = fileBuf.length;
const pfs0 = new PFS0(fileBuf);
const nca = pfs0.getFiles().find(f => /\.ncz$/i.test(f.name));
if (!nca) throw new Error('no .ncz member in ' + UPDATE_NSZ);
console.log(`Container: ${UPDATE_NSZ} (${(fsize / (1024 * 1024)).toFixed(1)} MB), NCZ member: ${nca.name}`);

const ncaView = fileBuf.subarray(nca.offset, nca.offset + nca.size);
const reader = { read: async (off, len) => ncaView.subarray(off, off + len), length: ncaView.length };
const parsed = await parseNczSections(reader);
const headerEnd = parsed.headerEnd;
const ncaSize = parsed.ncaSize;
const compressedBuf = ncaView.subarray(headerEnd);
const compressedMB = compressedBuf.length / (1024 * 1024);
const ncaMB = ncaSize / (1024 * 1024);
const EXPECTED = ncaSize - 0x4000; // zstd frame covers the NCA minus the raw 0x4000 header

console.log(`NCZ header end: 0x${headerEnd.toString(16)} (${headerEnd} bytes)`);
console.log(`Compressed payload: ${compressedMB.toFixed(1)} MB | Decompressed NCA: ${ncaMB.toFixed(1)} MB`);
console.log(`Runs: ${WARMUPS} warmup + ${RUNS} measured\n`);

function discardBuf(buf) {
    // force V8 to touch every page (no lazy allocation)
    let s = 0;
    for (let i = 0; i < buf.length; i += 65536) s += buf[i];
    return s;
}

async function benchNodeNative() {
    const { zstdDecompressSync } = await import('node:zlib');
    // warmup
    for (let i = 0; i < WARMUPS; i++) {
        const out = zstdDecompressSync(compressedBuf);
        discardBuf(out);
    }
    // measured
    const times = [];
    for (let i = 0; i < RUNS; i++) {
        const t0 = performance.now();
        const out = zstdDecompressSync(compressedBuf);
        const elapsed = performance.now() - t0;
        discardBuf(out);
        if (out.length !== EXPECTED) throw new Error(`node:native size mismatch: ${out.length} vs ${EXPECTED}`);
        times.push({ elapsed, size: out.length });
    }
    return times;
}

async function benchZstddecCurrent() {
    return benchZstddecModule('../static/zstddec.mjs');
}

async function benchZstddecModule(modUrl) {
    const { ZSTDDecoder } = await import(modUrl);
    const dec = new ZSTDDecoder();
    await dec.init();
    // warmup
    for (let i = 0; i < WARMUPS; i++) {
        const out = dec.decode(compressedBuf, 0);
        discardBuf(out);
    }
    // measured
    const times = [];
    for (let i = 0; i < RUNS; i++) {
        const t0 = performance.now();
        const out = dec.decode(compressedBuf, 0);
        const elapsed = performance.now() - t0;
        discardBuf(out);
        if (out.length !== EXPECTED) throw new Error(`zstddec size mismatch: ${out.length} vs ${EXPECTED}`);
        times.push({ elapsed, size: out.length });
    }
    return times;
}

async function benchBokuweb() {
    // Node's exports map blocks deep subpath imports, and the shipped ESM uses
    // extensionless relative specifiers Node won't resolve. Load a local copy of
    // dist/esm from the scratch dir with the specifiers fixed to .js.
    const BOK = '/var/folders/zj/05zh1hnd0q5ghn9wn6xnz1t00000gp/T/opencode/bok';
    const mod = await import(new URL(`${BOK}/module.js`, 'file://').href);
    const node = await import(new URL(`${BOK}/index.node.js`, 'file://').href);
    await node.init();
    const Module = mod.Module;
    const malloc = Module['_malloc'];
    const free = Module['_free'];
    const decomp = Module['_ZSTD_decompress'];
    const isError = Module['_ZSTD_isError'];
    const DST_CAP = EXPECTED * 2; // unknown-FCS frame: pick a safe upper bound

    const src = malloc(compressedBuf.byteLength);
    Module.HEAPU8.set(compressedBuf, src);
    // warmup
    for (let i = 0; i < WARMUPS; i++) {
        const heap = malloc(DST_CAP);
        const n = decomp(heap, DST_CAP, src, compressedBuf.byteLength);
        if (n < 0 || isError(n)) throw new Error(`bokuweb _ZSTD_decompress: ${n}`);
        discardHeap(Module.HEAPU8, heap, n);
        free(heap, DST_CAP);
    }
    // measured
    const times = [];
    for (let i = 0; i < RUNS; i++) {
        const t0 = performance.now();
        const heap = malloc(DST_CAP);
        const n = decomp(heap, DST_CAP, src, compressedBuf.byteLength);
        const elapsed = performance.now() - t0;
        if (n < 0 || isError(n)) throw new Error(`bokuweb _ZSTD_decompress: ${n}`);
        discardHeap(Module.HEAPU8, heap, n);
        free(heap, DST_CAP);
        if (n !== EXPECTED) throw new Error(`bokuweb size mismatch: ${n} vs ${EXPECTED}`);
        times.push({ elapsed, size: n });
    }
    return times;
}

async function benchStructuredZstd() {
    const z = await import('@structured-world/structured-zstd');
    await z.init();
    for (let i = 0; i < WARMUPS; i++) {
        const out = await z.decompress(compressedBuf);
        discardBuf(out);
    }
    const times = [];
    for (let i = 0; i < RUNS; i++) {
        const t0 = performance.now();
        const out = await z.decompress(compressedBuf);
        const elapsed = performance.now() - t0;
        discardBuf(out);
        if (out.length !== EXPECTED) throw new Error(`structured size mismatch: ${out.length} vs ${EXPECTED}`);
        times.push({ elapsed, size: out.length });
    }
    return times;
}

async function benchDisc(kind) {
    const BOK = `/var/folders/zj/05zh1hnd0q5ghn9wn6xnz1t00000gp/T/opencode/disc_out/disc${kind}.mjs`
;
    const make = (await import(new URL(`file://${BOK}`).href)).default;
    const mod = await make();
    const malloc = mod['_malloc'];
    const free = mod['_free'];
    const decomp = mod['_ZSTD_decompress'];
    const isError = mod['_ZSTD_isError'];
    const DST_CAP = EXPECTED * 2;
    const src = malloc(compressedBuf.byteLength);
    new Uint8Array(mod.memory.buffer).set(compressedBuf, src);
    const runWith = async (warmup) => {
        const heap = malloc(DST_CAP);
        const t0 = performance.now();
        const n = decomp(heap, DST_CAP, src, compressedBuf.byteLength);
        const elapsed = performance.now() - t0;
        if (n < 0 || isError(n)) throw new Error(`disc${kind}: ${n}`);
        const out = new Uint8Array(mod.memory.buffer).slice(heap, heap + n);
        discardBuf(out);
        free(heap, DST_CAP);
        if (n !== EXPECTED) throw new Error(`disc${kind} size mismatch: ${n} vs ${EXPECTED}`);
        return { elapsed, size: n };
    };
    for (let i = 0; i < WARMUPS; i++) await runWith(true);
    const times = [];
    for (let i = 0; i < RUNS; i++) times.push(await runWith(false));
    return times;
}

async function benchZ57(kind) {
    const make = (await import(`file:///var/folders/zj/05zh1hnd0q5ghn9wn6xnz1t00000gp/T/opencode/z57_out/z57_${kind}.mjs`)).default;
    const mod = await make();
    const malloc = mod['_malloc'];
    const free = mod['_free'];
    const decomp = mod['_ZSTD_decompress'];
    const isError = mod['_ZSTD_isError'];
    const DST_CAP = EXPECTED * 2;
    const src = malloc(compressedBuf.byteLength);
    new Uint8Array(mod.memory.buffer).set(compressedBuf, src);
    const runWith = async () => {
        const heap = malloc(DST_CAP);
        const t0 = performance.now();
        const n = decomp(heap, DST_CAP, src, compressedBuf.byteLength);
        const elapsed = performance.now() - t0;
        if (n < 0 || isError(n)) throw new Error(`z57${kind}: ${n}`);
        const out = new Uint8Array(mod.memory.buffer).slice(heap, heap + n);
        discardBuf(out);
        free(heap, DST_CAP);
        if (n !== EXPECTED) throw new Error(`z57${kind} size mismatch: ${n} vs ${EXPECTED}`);
        return { elapsed, size: n };
    };
    for (let i = 0; i < WARMUPS; i++) await runWith();
    const times = [];
    for (let i = 0; i < RUNS; i++) times.push(await runWith());
    return times;
}

function discardHeap(heap, off, len) {
    let s = 0;
    for (let i = 0; i < len; i += 65536) s += heap[off + i]; // touch pages
    return s;
}

function report(name, times) {
    const best = times.reduce((a, b) => a.elapsed < b.elapsed ? a : b);
    const throughput = ncaMB / (best.elapsed / 1000);
    const compressedThroughput = compressedMB / (best.elapsed / 1000);
    const allMs = times.map(t => t.elapsed.toFixed(0)).join(', ');
    console.log(`  ${name.padEnd(20)} best=${best.elapsed.toFixed(0)}ms  all=[${allMs}]ms`);
    console.log(`  ${''.padEnd(20)} decompressed=${throughput.toFixed(0)} MB/s  compressed=${compressedThroughput.toFixed(0)} MB/s`);
    return { name, bestMs: best.elapsed, throughputMBs: throughput };
}

console.log('Engine: Node native (node:zlib)');
const native = await benchNodeNative();
console.log('Engine: zstddec 0.2.0 (current browser WASM, zstd v1.5.7 -Oz)');
const zstddec = await benchZstddecCurrent();
console.log('Engine: zstddec 0.3.1 (npm latest, same -Oz build)');
const zstddec31 = await benchZstddecModule('file:///tmp/z31.mjs');
console.log('Engine: @bokuweb/zstd-wasm 0.0.27 (emscripten C zstd -O3)');
const bokuweb = await benchBokuweb();
console.log('Engine: @structured-world/structured-zstd 0.0.52 (Rust ruzstd simd128)');
const structured = await benchStructuredZstd();
console.log('Engine: discere-os zstd 1.5.6 -O3 -msimd128 (built locally)');
const discSimd = await benchDisc('');
console.log('Engine: discere-os zstd 1.5.6 -O3 (no simd)');
const discO3 = await benchDisc('_O3');
console.log('Engine: discere-os zstd 1.5.6 -Oz (baseline = zstddec flags)');
const discOz = await benchDisc('_Oz');
console.log('Engine: zstd v1.5.7 (zstddec) -O3, emcc 6.0.9, raw one-shot');
const z57O3 = await benchZ57('O3');
console.log('Engine: zstd v1.5.7 (zstddec) -Oz, emcc 6.0.9, raw one-shot');
const z57Oz = await benchZ57('Oz');
console.log('\n─── Summary ───');
const r1 = report('Node native', native);
const r2 = report('zstddec 0.2.0', zstddec);
const r2b = report('zstddec 0.3.1', zstddec31);
const r3 = report('bokuweb', bokuweb);
const r4 = report('structured', structured);
const r5 = report('disc O3+simd', discSimd);
const r6 = report('disc O3', discO3);
const r7 = report('disc Oz', discOz);
const r8 = report('z57 O3 one-shot', z57O3);
const r9 = report('z57 Oz one-shot', z57Oz);
console.log(`\nSpeedup vs zstddec (current browser):`);
console.log(`  z57 O3 (rebuild, one-shot) / zstddec = ×${(r8.throughputMBs / r2.throughputMBs).toFixed(2)}`);
console.log(`  z57 Oz (rebuild, one-shot) / zstddec = ×${(r9.throughputMBs / r2.throughputMBs).toFixed(2)}`);
console.log(`  z57 O3 / z57 Oz (flag effect) = ×${(r8.throughputMBs / r9.throughputMBs).toFixed(2)}`);
console.log(`  disc O3+simd / zstddec = ×${(r5.throughputMBs / r2.throughputMBs).toFixed(2)}`);
console.log(`  node:zlib / zstddec = ×${(r1.throughputMBs / r2.throughputMBs).toFixed(2)}`);
