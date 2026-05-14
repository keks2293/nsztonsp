#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) { console.log(`  \u2713 ${msg}`); passed++; }
  else { console.error(`  \u2717 ${msg}`); failed++; }
}

function assertEqual(actual, expected, msg) {
  if (actual === expected) { console.log(`  \u2713 ${msg}`); passed++; }
  else { console.error(`  \u2717 ${msg} (expected ${expected}, got ${actual})`); failed++; }
}

function assertBuffersEqual(a, b, msg) {
  if (a.length !== b.length) {
    console.error(`  \u2717 ${msg} (length ${a.length} !== ${b.length})`);
    failed++; return;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      console.error(`  \u2717 ${msg} (byte ${i}: ${a[i]} !== ${b[i]})`);
      failed++; return;
    }
  }
  console.log(`  \u2713 ${msg}`); passed++;
}

async function compressWithZstd(data, level = 19) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const proc = spawn('zstd', [`-${level}`, '--no-check'], { stdio: ['pipe', 'pipe', 'pipe'] });
    proc.stdout.on('data', c => chunks.push(c));
    let stderr = '';
    proc.stderr.on('data', c => stderr += c.toString());
    proc.on('exit', code => {
      if (code === 0) resolve(Buffer.concat(chunks));
      else reject(new Error(`zstd failed: ${stderr}`));
    });
    proc.on('error', reject);
    proc.stdin.end(Buffer.from(data));
  });
}

function generateTestData(size) {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    data[i] = (i * 7 + 13) & 0xFF;
  }
  return data;
}

async function testStreamingDecompression(name, testData, chunkSize) {
  console.log(`\n  --- ${name} (${(testData.length / 1024 / 1024).toFixed(2)} MB, chunk=${chunkSize})`);

  const compressed = await compressWithZstd(testData, 19);
  console.log(`    compressed: ${compressed.length} bytes (ratio ${(testData.length / compressed.length).toFixed(2)}x)`);

  const { initZstddec, decodeStream } = await import('./crypto/zstddec-stream.js');
  await initZstddec();

  let pos = 0;
  const decompChunks = [];
  for await (const chunk of decodeStream(async () => {
    if (pos >= compressed.length) return null;
    const end = Math.min(pos + chunkSize, compressed.length);
    const slice = compressed.slice(pos, end);
    pos = end;
    return new Uint8Array(slice);
  })) {
    decompChunks.push(chunk);
  }

  const totalLen = decompChunks.reduce((s, c) => s + c.length, 0);
  assertEqual(totalLen, testData.length, `decompressed size matches original (${name})`);

  const decompressed = new Uint8Array(totalLen);
  let off = 0;
  for (const c of decompChunks) { decompressed.set(c, off); off += c.length; }
  assertBuffersEqual(decompressed, testData, `decompressed data matches original (${name})`);
}

async function testOneShotVsStreamingMatch() {
  console.log('\n  --- One-shot vs streaming output match');
  const { initZstddec, decodeStream } = await import('./crypto/zstddec-stream.js');
  const { ZSTDDecoder } = await import('./static/zstddec.mjs');
  await initZstddec();

  const testData = generateTestData(500000);
  const compressed = await compressWithZstd(testData, 19);

  // One-shot decode
  const decoder = new ZSTDDecoder();
  await decoder.init();
  const oneShot = decoder.decode(new Uint8Array(compressed), 0);

  // Streaming decode
  let pos = 0;
  const decompChunks = [];
  for await (const chunk of decodeStream(async () => {
    if (pos >= compressed.length) return null;
    const end = Math.min(pos + 65536, compressed.length);
    const slice = compressed.slice(pos, end);
    pos = end;
    return new Uint8Array(slice);
  })) {
    decompChunks.push(chunk);
  }
  const totalLen = decompChunks.reduce((s, c) => s + c.length, 0);
  const streamed = new Uint8Array(totalLen);
  let off = 0;
  for (const c of decompChunks) { streamed.set(c, off); off += c.length; }

  assertBuffersEqual(streamed, oneShot, 'streaming output matches one-shot output');
}

async function testEmptyStream() {
  console.log('\n  --- Empty compressed stream');
  const { initZstddec, decodeStream } = await import('./crypto/zstddec-stream.js');
  await initZstddec();

  const chunks = [];
  for await (const c of decodeStream(async () => null)) {
    chunks.push(c);
  }
  assertEqual(chunks.length, 0, 'no chunks yielded for empty stream');
  assertEqual(chunks.reduce((s, c) => s + c.length, 0), 0, 'total size is 0');
}

async function testMultipleSizes() {
  const sizes = [0, 1, 100, 1000, 10000, 100000, 1000000, 5000000];
  for (const size of sizes) {
    if (size === 0) {
      console.log(`\n  --- Size: 0 bytes (skip - empty)`);
      continue;
    }
    const data = generateTestData(size);
    const compressed = await compressWithZstd(data, 19);
    const { decodeStream } = await import('./crypto/zstddec-stream.js');
    let pos = 0;
    const chunks = [];
    for await (const c of decodeStream(async () => {
      if (pos >= compressed.length) return null;
      const end = Math.min(pos + 16384, compressed.length);
      const s = compressed.slice(pos, end);
      pos = end;
      return new Uint8Array(s);
    })) {
      chunks.push(c);
    }
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { result.set(c, off); off += c.length; }
    assertBuffersEqual(result, data, `size ${size}`);
  }
}

async function main() {
  console.log('=== zstddec-stream.js Streaming Decompression Tests ===');

  // Test 1: Small data, small chunks
  await testStreamingDecompression('Small+small chunks', generateTestData(100000), 1024);

  // Test 2: Small data, large chunks
  await testStreamingDecompression('Small+large chunks', generateTestData(100000), 65536);

  // Test 3: Medium data (~1 MB)
  await testStreamingDecompression('Medium', generateTestData(1000000), 16384);

  // Test 4: Larger data (~5 MB) with large chunks (16 MB = single chunk)
  await testStreamingDecompression('Large single chunk', generateTestData(5000000), 16777216);

  // Test 5: Larger data with small chunks
  await testStreamingDecompression('Large small chunks', generateTestData(5000000), 8192);

  // Test 6: Output matches one-shot decoder
  await testOneShotVsStreamingMatch();

  // Test 7: Empty stream
  await testEmptyStream();

  // Test 8: Multiple sizes
  await testMultipleSizes();

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
