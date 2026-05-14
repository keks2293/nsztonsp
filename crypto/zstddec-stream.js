import { ZSTDDecoder } from '../static/zstddec.mjs';

let ownInstance = null;

const origInit = ZSTDDecoder.prototype._init;
ZSTDDecoder.prototype._init = function (result) {
    ownInstance = result.instance;
    return origInit.call(this, result);
};

export async function initZstddec() {
    if (ownInstance) return;
    const decoder = new ZSTDDecoder();
    await decoder.init();
}

export async function* decodeStream(readChunk) {
    if (!ownInstance) throw new Error('Call initZstddec() first');
    const $ = ownInstance.exports;
    const dctx = $.ZSTD_createDCtx();
    const outSize = $.ZSTD_DStreamOutSize();
    const outBuf = $.malloc(outSize);
    const SZ_P = 4, SZ_T = 4;
    const inP = $.malloc(SZ_P + SZ_T * 2);
    const outP = $.malloc(SZ_P + SZ_T * 2);
    let ret = 0;
    try {
        while (true) {
            const array = await readChunk();
            if (!array || !array.byteLength) break;
            const cp = $.malloc(array.byteLength);
            const h = new Uint8Array(ownInstance.exports.memory.buffer);
            h.set(array, cp);
            const v = new DataView(h.buffer);
            v.setInt32(inP, cp, true);
            v.setInt32(inP + SZ_P, array.byteLength, true);
            v.setInt32(inP + SZ_P + SZ_T, 0, true);
            while (v.getUint32(inP + SZ_P + SZ_T, true) < v.getUint32(inP + SZ_P, true)) {
                v.setInt32(outP, outBuf, true);
                v.setInt32(outP + SZ_P, outSize, true);
                v.setInt32(outP + SZ_P + SZ_T, 0, true);
                ret = $.ZSTD_decompressStream(dctx, outP, inP);
                const buf = ownInstance.exports.memory.buffer;
                const v2 = new DataView(buf);
                const outputPos = v2.getUint32(outP + SZ_P + SZ_T, true);
                yield new Uint8Array(buf, outBuf, outputPos);
            }
            $.free(cp);
        }
    } finally {
        $.ZSTD_freeDCtx(dctx);
        $.free(outBuf);
        $.free(inP);
        $.free(outP);
    }
    if (ret !== 0) throw new Error('Incomplete zstd stream, more data expected.');
}
