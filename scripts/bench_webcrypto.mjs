import { SHA256 } from '../crypto/sha256.js';
const subtle = globalThis.crypto.subtle;
const N = 37012, BS = 0x4000;

// Pure JS (browser path) one-shot per block
{
  const data = new Uint8Array(N * BS).fill(7);
  const t0 = performance.now();
  for (let i = 0; i < N; i++) { const h = new SHA256(); h.update(data.subarray(i * BS, (i + 1) * BS)); h.digest(); }
  const ms = performance.now() - t0;
  console.log(`pureJS 37012x16KB: ${ms.toFixed(0)} ms (${(N * BS / ms / 1024).toFixed(0)} MB/s)`);
}
// WebCrypto one-shot over the real NCA size (699123712 B)
{
  const big = new Uint8Array(699123712).fill(3);
  const t0 = performance.now();
  await subtle.digest('SHA-256', big);
  const ms = performance.now() - t0;
  console.log(`WC     1x699MB: ${ms.toFixed(0)} ms (${(699123712 / ms / 1024).toFixed(0)} MB/s)`);
  const t1 = performance.now();
  const h = new SHA256(); h.update(big); h.digest();
  const ms2 = performance.now() - t1;
  console.log(`pureJS 1x699MB: ${ms2.toFixed(0)} ms (${(699123712 / ms2 / 1024).toFixed(0)} MB/s)`);
}
