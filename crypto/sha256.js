// The pure-JS class below is the streaming hasher: it is the only SHA-256 with
// an incremental update() AND a sync clone() (the two-pass contentId hash), so
// it stays the streaming backend everywhere — browser, Node fallback, and the
// no-WASM/no-`crypto.subtle` environments (crypto.subtle is one-shot async and
// cannot be cloned).

const HEXES = new Array(256).fill().map((_, i) => i.toString(16).padStart(2, '0'));

const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function swap32(v) {
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >>> 8) & 0xff00) | ((v >>> 24) & 0xff);
}

export class SHA256 {
    constructor() {
        this.h0 = 0x6a09e667;
        this.h1 = 0xbb67ae85;
        this.h2 = 0x3c6ef372;
        this.h3 = 0xa54ff53a;
        this.h4 = 0x510e527f;
        this.h5 = 0x9b05688c;
        this.h6 = 0x1f83d9ab;
        this.h7 = 0x5be0cd19;
        this._W = new Int32Array(64);
        this._buf = new ArrayBuffer(80);
        this._byte = new Uint8Array(this._buf);
        this._word = new Int32Array(this._buf, 0, 16);
        this._blen = 0;
        this.bytes = 0;
        this.hBytes = 0;
        this.finalized = false;
    }

    clone() {
        const c = new SHA256();
        c.h0 = this.h0; c.h1 = this.h1; c.h2 = this.h2; c.h3 = this.h3;
        c.h4 = this.h4; c.h5 = this.h5; c.h6 = this.h6; c.h7 = this.h7;
        c._byte.set(this._byte.subarray(0, this._blen));
        c._blen = this._blen;
        c.bytes = this.bytes; c.hBytes = this.hBytes;
        c.finalized = this.finalized;
        return c;
    }

    _compressWords() {
        const W = this._W;
        let a = this.h0, b = this.h1, c = this.h2, d = this.h3;
        let e = this.h4, f = this.h5, g = this.h6, h = this.h7;
        let t1, t2, s0, s1, ch, maj;

        for (let j = 16; j < 64; ++j) {
            t1 = W[j - 15];
            s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
            t1 = W[j - 2];
            s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
            W[j] = (W[j - 16] + s0 + W[j - 7] + s1) | 0;
        }

        let bc = b & c;
        for (let j = 0; j < 64; j += 4) {
            s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
            s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
            const ab = a & b;
            maj = ab ^ (a & c) ^ bc;
            ch = (e & f) ^ (~e & g);
            t1 = h + s1 + ch + K[j] + W[j];
            t2 = s0 + maj;
            h = d + t1 | 0;
            d = t1 + t2 | 0;
            s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
            s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
            const da = d & a;
            maj = da ^ (d & b) ^ ab;
            ch = (h & e) ^ (~h & f);
            t1 = g + s1 + ch + K[j + 1] + W[j + 1];
            t2 = s0 + maj;
            g = c + t1 | 0;
            c = t1 + t2 | 0;
            s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
            s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
            const cd = c & d;
            maj = cd ^ (c & a) ^ da;
            ch = (g & h) ^ (~g & e);
            t1 = f + s1 + ch + K[j + 2] + W[j + 2];
            t2 = s0 + maj;
            f = b + t1 | 0;
            b = t1 + t2 | 0;
            s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
            s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
            bc = b & c;
            maj = bc ^ (b & d) ^ cd;
            ch = (f & g) ^ (~f & h);
            t1 = e + s1 + ch + K[j + 3] + W[j + 3];
            t2 = s0 + maj;
            e = a + t1 | 0;
            a = t1 + t2 | 0;
        }

        this.h0 = (this.h0 + a) | 0;
        this.h1 = (this.h1 + b) | 0;
        this.h2 = (this.h2 + c) | 0;
        this.h3 = (this.h3 + d) | 0;
        this.h4 = (this.h4 + e) | 0;
        this.h5 = (this.h5 + f) | 0;
        this.h6 = (this.h6 + g) | 0;
        this.h7 = (this.h7 + h) | 0;
    }

    update(data) {
        if (this.finalized) return this;
        if (typeof data === 'string') data = new TextEncoder().encode(data);
        else if (data instanceof ArrayBuffer) data = new Uint8Array(data);

        const length = data.length;
        let offset = 0;

        if (this._blen > 0) {
            const take = Math.min(64 - this._blen, length);
            this._byte.set(data.subarray(0, take), this._blen);
            this._blen += take;
            offset = take;
            if (this._blen === 64) {
                const W = this._W;
                for (let i = 0; i < 16; i++) W[i] = swap32(this._word[i]);
                this._compressWords();
                this._blen = 0;
            }
        }

        if (this._blen === 0 && offset < length && length - offset >= 64 && !((data.byteOffset + offset) & 3)) {
            const full = ((length - offset) >> 6) << 6;
            const view = new Int32Array(data.buffer, data.byteOffset + offset, full >> 2);
            let wi = 0;
            const wEnd = full >> 2;
            const W = this._W;
            while (wi < wEnd) {
                for (let i = 0; i < 16; i += 4) {
                    W[i] = swap32(view[wi + i]);
                    W[i + 1] = swap32(view[wi + i + 1]);
                    W[i + 2] = swap32(view[wi + i + 2]);
                    W[i + 3] = swap32(view[wi + i + 3]);
                }
                this._compressWords();
                wi += 16;
            }
            offset += full;
        }

        while (offset < length) {
            this._byte[this._blen++] = data[offset++];
            if (this._blen === 64) {
                const W = this._W;
                for (let i = 0; i < 16; i++) W[i] = swap32(this._word[i]);
                this._compressWords();
                this._blen = 0;
            }
        }

        this.bytes += length;
        if (this.bytes > 4294967295) {
            this.hBytes += this.bytes / 4294967296 | 0;
            this.bytes = this.bytes % 4294967296;
        }
        return this;
    }

    _finalize() {
        if (this.finalized) return;
        this.finalized = true;
        const { _byte, _word, _W: W } = this;
        let i = this._blen;
        _byte[i++] = 0x80;
        while (i & 3) _byte[i++] = 0;
        let wi = i >> 2;
        if (wi > 14) {
            while (wi < 16) _word[wi++] = 0;
            for (let j = 0; j < 16; j++) W[j] = swap32(_word[j]);
            this._compressWords();
            wi = 0;
        }
        while (wi < 16) _word[wi++] = 0;
        for (let j = 0; j < 16; j++) W[j] = swap32(_word[j]);
        W[14] = ((this.hBytes << 3) | (this.bytes >>> 29)) | 0;
        W[15] = (this.bytes << 3) | 0;
        this._compressWords();
    }

    hex() {
        this._finalize();
        const h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3;
        const h4 = this.h4, h5 = this.h5, h6 = this.h6, h7 = this.h7;
        return HEXES[(h0 >>> 24) & 0xff] + HEXES[(h0 >>> 16) & 0xff] +
            HEXES[(h0 >>> 8) & 0xff] + HEXES[h0 & 0xff] +
            HEXES[(h1 >>> 24) & 0xff] + HEXES[(h1 >>> 16) & 0xff] +
            HEXES[(h1 >>> 8) & 0xff] + HEXES[h1 & 0xff] +
            HEXES[(h2 >>> 24) & 0xff] + HEXES[(h2 >>> 16) & 0xff] +
            HEXES[(h2 >>> 8) & 0xff] + HEXES[h2 & 0xff] +
            HEXES[(h3 >>> 24) & 0xff] + HEXES[(h3 >>> 16) & 0xff] +
            HEXES[(h3 >>> 8) & 0xff] + HEXES[h3 & 0xff] +
            HEXES[(h4 >>> 24) & 0xff] + HEXES[(h4 >>> 16) & 0xff] +
            HEXES[(h4 >>> 8) & 0xff] + HEXES[h4 & 0xff] +
            HEXES[(h5 >>> 24) & 0xff] + HEXES[(h5 >>> 16) & 0xff] +
            HEXES[(h5 >>> 8) & 0xff] + HEXES[h5 & 0xff] +
            HEXES[(h6 >>> 24) & 0xff] + HEXES[(h6 >>> 16) & 0xff] +
            HEXES[(h6 >>> 8) & 0xff] + HEXES[h6 & 0xff] +
            HEXES[(h7 >>> 24) & 0xff] + HEXES[(h7 >>> 16) & 0xff] +
            HEXES[(h7 >>> 8) & 0xff] + HEXES[h7 & 0xff];
    }

    digest() {
        this._finalize();
        const h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3;
        const h4 = this.h4, h5 = this.h5, h6 = this.h6, h7 = this.h7;
        return new Uint8Array([
            (h0 >>> 24) & 0xff, (h0 >>> 16) & 0xff, (h0 >>> 8) & 0xff, h0 & 0xff,
            (h1 >>> 24) & 0xff, (h1 >>> 16) & 0xff, (h1 >>> 8) & 0xff, h1 & 0xff,
            (h2 >>> 24) & 0xff, (h2 >>> 16) & 0xff, (h2 >>> 8) & 0xff, h2 & 0xff,
            (h3 >>> 24) & 0xff, (h3 >>> 16) & 0xff, (h3 >>> 8) & 0xff, h3 & 0xff,
            (h4 >>> 24) & 0xff, (h4 >>> 16) & 0xff, (h4 >>> 8) & 0xff, h4 & 0xff,
            (h5 >>> 24) & 0xff, (h5 >>> 16) & 0xff, (h5 >>> 8) & 0xff, h5 & 0xff,
            (h6 >>> 24) & 0xff, (h6 >>> 16) & 0xff, (h6 >>> 8) & 0xff, h6 & 0xff,
            (h7 >>> 24) & 0xff, (h7 >>> 16) & 0xff, (h7 >>> 8) & 0xff, h7 & 0xff
        ]);
    }
}

export function sha256(data) {
    const h = new SHA256();
    h.update(data);
    return h.hex();
}

import { isNode } from './platform.js';

// Native SHA256 digest (Uint8Array) when available, pure JS fallback.
// node:crypto — sync, ~17× faster than pure JS.
// browser crypto.subtle — async, not used here (see browser fallback).
let _nativeDigest = null;
if (isNode) {
    try {
        const { createHash } = await import('node:crypto');
        _nativeDigest = (data) => {
            if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
                return new Uint8Array(createHash('sha256').update(Buffer.from(data)).digest());
            }
            return new Uint8Array(createHash('sha256').update(data).digest());
        };
    } catch {}
}
export const digest32 = _nativeDigest || ((data) => {
    const h = new SHA256();
    h.update(data);
    return h.digest();
});

// WebCrypto one-shot digest (browser + Node, hardware-accelerated).
// crypto.subtle.digest is async and one-shot — no incremental update()/clone() —
// so it only fits hashes over INDEPENDENT blocks (IVFC levels, PFS0 tables),
// never a single big streamed hash. Null when crypto.subtle is unavailable
// (non-secure context) — callers then fall back to digest32 (node:crypto in
// Node, pure JS in browser). (The old sync sha256() WebCrypto path was dropped
// in 3a560a7 over the ~2GB one-shot ArrayBuffer concern; this batch shape
// digests 16/64 KB blocks, so that limit never applies.)
export let webcryptoDigest = null;
try {
    if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
        webcryptoDigest = (data) => crypto.subtle.digest('SHA-256', data);
    }
} catch {}

// Bounded-concurrency batcher for one-shot SHA256 digests over independent
// blocks. Each result is placed by slot, so WebCrypto completion order is
// irrelevant. Without WebCrypto, submit() degrades to a synchronous digest32
// (same behavior as the pre-WebCrypto code). drain() resolves once every
// submitted block is placed and re-arms, so one instance serves sequential
// batches (e.g. one per IVFC level).
export class BatchDigestor {
    constructor(concurrency = 32) {
        this._concurrency = concurrency;
        this._queue = [];
        this._inflight = 0;
        this._waiters = [];
    }
    submit(block, place) {
        const start = () => {
            this._inflight++;
            if (webcryptoDigest) {
                webcryptoDigest(block).then(
                    (buf) => place(new Uint8Array(buf)),
                    () => place(digest32(block)),
                ).then(() => this._settled());
            } else {
                place(digest32(block));
                this._settled();
            }
        };
        if (this._inflight < this._concurrency) start();
        else this._queue.push(start);
    }
    _settled() {
        this._inflight--;
        const next = this._queue.shift();
        if (next) next();
        if (this._inflight === 0 && this._queue.length === 0 && this._waiters.length > 0) {
            for (const r of this._waiters.splice(0)) r();
        }
    }
    drain() {
        if (this._inflight === 0 && this._queue.length === 0) return Promise.resolve();
        return new Promise((resolve) => this._waiters.push(resolve));
    }
}
