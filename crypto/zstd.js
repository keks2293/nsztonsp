let ready = false;
let zstddecModule = null;
let sharedDecoder = null;

class ZstdDecompressor {
    constructor() {
    }

    static async load() {
        if (ready) return;
        const module = await import('../static/zstddec.mjs');
        zstddecModule = module;
        sharedDecoder = new zstddecModule.ZSTDDecoder();
        await sharedDecoder.init();
        ready = true;
    }

    async decompress(data) {
        await ZstdDecompressor.load();
        if (!zstddecModule) throw new Error('zstddec not loaded');
        return sharedDecoder.decode(data, 0);
    }

    static async decompressBuffer(data) {
        await ZstdDecompressor.load();
        if (!zstddecModule) throw new Error('zstddec not loaded');
        return sharedDecoder.decode(data, 0);
    }

    static async decompressStreaming(data, callback) {
        await ZstdDecompressor.load();
        if (!zstddecModule) throw new Error('zstddec not loaded');
        const decompressed = sharedDecoder.decode(data, 0);
        callback(decompressed);
    }
}

export { ZstdDecompressor };
