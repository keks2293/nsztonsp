// Real-pipeline A/B: the exact browser SW two-pass update (append-only writable,
// no seek/read-back) on the real base+update NSZ pair, output DISCARED (no disk
// writes — AGENTS.md rule). Verifies both SHA-256 backends produce byte-identical
// output (fed into a node:crypto hash as writes arrive) and reports best-of-N.
// Native node:crypto streaming is the default; --js forces the pure-JS class.
// Usage (from repo root):  node scripts/bench_real_update.mjs [--js] [--n 3]
import fs from 'fs';
import crypto from 'node:crypto';
import { KeysParser } from '../keys.js';
import { update } from '../fs/update.js';

const DIR = '/Users/rmitkov/Downloads/Stardew Valley [NSZ]';
const basePath = process.env.BASE_PATH || `${DIR}/Stardew Valley [0100E65002BB8000][v0] (0.87 GB).nsz`;
const updatePath = process.env.UPDATE_PATH || `${DIR}/Stardew Valley [0100E65002BB8800][v1310720] (0.67 GB).nsz`;
const N = parseInt(process.argv[process.argv.indexOf('--n') + 1] || '3', 10);

if (process.argv.includes('--js')) {
  const { setForceJsSha256 } = await import('../crypto/sha256.js');
  setForceJsSha256(true);
  console.log('backend: pure-JS streaming SHA256 (browser path)');
} else {
  console.log('backend: native node:crypto streaming SHA256');
}

class FileReader {
  constructor(path) { this.path = path; this.fd = fs.openSync(path, 'r'); this.size = fs.statSync(path).size; }
  async read(offset, size) { const buf = Buffer.alloc(size); fs.readSync(this.fd, buf, 0, size, offset); return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength); }
  close() { fs.closeSync(this.fd); }
}

// Hash-only output: verifies byte-identity without touching disk. Writes arrive
// at monotonically increasing positions (append-only SW path), so feeding them
// to the hash in order is exact.
class HashWriter {
  constructor() { this.h = crypto.createHash('sha256'); this.total = 0; }
  write(pos, data) { this.h.update(data); this.total += data.byteLength; }
  digest() { return this.h.digest('hex'); }
}

const keys = KeysParser.parse(fs.readFileSync(new URL('../static/prod.keys', import.meta.url), 'utf8'));
const silence = () => {};

function makeInputs() {
  const base = { name: 'base.nsp', reader: new FileReader(basePath) };
  const upd = { name: 'update.nsz', reader: new FileReader(updatePath) };
  return [base, upd];
}

const timings = [];
const log = (level, msg) => {
  if (typeof msg === 'string' && msg.includes('[timing]')) {
    const match = msg.match(/\[timing\] (Pass \d \w+ \([^)]+\)|[^:]+): ([0-9.]+)s/);
    if (match) timings.push(`${match[1]}: ${match[2]}s`);
  }
};

const runs = [];
for (let i = 0; i < N; i++) {
  const [b, u] = makeInputs();
  const out = new HashWriter();
  const t0 = performance.now();
  await update([b, u], { writable: out }, { keys, log, progress: silence, bktrMerge: true });
  const dt = (performance.now() - t0) / 1000;
  b.reader.close(); u.reader.close();
  const rec = { s: dt, sha: out.digest(), total: out.total };
  runs.push(rec);
  console.log(`run ${i + 1}: ${rec.s.toFixed(1)}s  (${(rec.total / dt / 1048576).toFixed(0)} MB/s, sha=${rec.sha.slice(0, 16)})`);
}

const best = runs.reduce((a, b) => (b.s < a.s ? b : a));
console.log(`best-of-${N}: ${best.s.toFixed(1)}s  (${(best.total / best.s / 1048576).toFixed(0)} MB/s)`);
if (timings.length) console.log('pass timings (last run):', timings.join(' · '));

const want = 'deec91cfc98a27b0bb98d64933b6306e3af6714e28709f8015d4e351a38e8497';
if (runs.some(r => r.sha !== want)) {
  console.log('ERROR: output sha does not match the regression vector', want);
  process.exit(1);
}
console.log('MATCH — output byte-identical to the regression vector');