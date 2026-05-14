let _hw = null;
let _hwPromise = null;

function ensureHw() {
    if (_hw) return Promise.resolve(_hw);
    if (!_hwPromise) {
        _hwPromise = (async () => {
            try {
                const { createSHA256 } = await import('../static/hash-wasm.mjs');
                const hw = await createSHA256();
                _hw = hw;
                return hw;
            } catch (e) {
                console.warn('hash-wasm WASM failed, falling back to native SHA-256:', e.message);
                return null;
            }
        })();
    }
    return _hwPromise;
}

function nativeSha256(data) {
    if (typeof data === 'string') data = new TextEncoder().encode(data);
    return crypto.subtle.digest('SHA-256', data).then(buf => {
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    });
}

export class SHA256 {
    constructor() {
        this._chunks = [];
        this._totalLen = 0;
    }

    async update(data) {
        if (data instanceof ArrayBuffer) data = new Uint8Array(data);
        if (typeof data === 'string') data = new TextEncoder().encode(data);
        this._chunks.push(data);
        this._totalLen += data.length;
        return this;
    }

    async hexdigest() {
        const hw = await ensureHw();
        if (hw) {
            hw.init();
            for (const chunk of this._chunks) {
                hw.update(chunk);
            }
            const r = hw.digest('hex');
            this._chunks = [];
            this._totalLen = 0;
            return r;
        }
        // Native fallback
        const merged = new Uint8Array(this._totalLen);
        let offset = 0;
        for (const chunk of this._chunks) {
            merged.set(chunk, offset);
            offset += chunk.length;
        }
        this._chunks = [];
        this._totalLen = 0;
        return nativeSha256(merged);
    }

    async digest() {
        const hex = await this.hexdigest();
        const bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
}

export function sha256(data) {
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
    return ensureHw().then(hw => {
        if (hw) {
            hw.init();
            hw.update(data);
            return hw.digest('hex');
        }
        return nativeSha256(data);
    });
}
