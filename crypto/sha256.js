import { createSHA256 } from '../static/hash-wasm.mjs';

const _hw = await createSHA256();

export class SHA256 {
    constructor() {
        this._started = false;
    }

    update(data) {
        if (data instanceof ArrayBuffer) data = new Uint8Array(data);
        if (typeof data === 'string') data = new TextEncoder().encode(data);
        if (!this._started) {
            _hw.init();
            this._started = true;
        }
        _hw.update(data);
    }

    hexdigest() {
        const r = _hw.digest('hex');
        this._started = false;
        return r;
    }

    digest() {
        const r = _hw.digest('binary');
        this._started = false;
        return r;
    }
}

export function sha256(data) {
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
    _hw.init();
    _hw.update(data);
    return _hw.digest('hex');
}
