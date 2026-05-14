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

function memView() {
    return new DataView(ownInstance.exports.memory.buffer);
}

export async function* decodeStream(readChunk) {
    if (!ownInstance) throw new Error('Call initZstddec() first');
    const $ = ownInstance.exports;
    const dctx = $.ZSTD_createDCtx();
    const outSize = $.ZSTD_DStreamOutSize();
    const outBuf = $.malloc(outSize);
    const SZ_P = 4, SZ_T = 4, offPos = SZ_P + SZ_T, offSize = SZ_P + SZ_T * 2;
    const inP = $.malloc(offSize);
    const outP = $.malloc(offSize);
    let ret = 0;
    try {
        while (true) {
            const array = await readChunk();
            if (!array || !array.byteLength) break;
            const cp = $.malloc(array.byteLength);
            new Uint8Array(ownInstance.exports.memory.buffer).set(array, cp);
            let mv = memView();
            mv.setInt32(inP, cp, true);
            mv.setInt32(inP + SZ_P, array.byteLength, true);
            mv.setInt32(inP + offPos, 0, true);
            while (mv.getUint32(inP + offPos, true) < mv.getUint32(inP + SZ_P, true)) {
                mv.setInt32(outP, outBuf, true);
                mv.setInt32(outP + SZ_P, outSize, true);
                mv.setInt32(outP + offPos, 0, true);
                ret = $.ZSTD_decompressStream(dctx, outP, inP);
                mv = memView();
                const outputPos = mv.getUint32(outP + offPos, true);
                yield new Uint8Array(ownInstance.exports.memory.buffer, outBuf, outputPos);
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
