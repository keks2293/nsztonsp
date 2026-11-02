import { AesCtr, aesBackend } from '../crypto/aes-ops.mjs';
import { decompressBlock, decompressStream } from '../crypto/zstd.js';
import { readLeU64, readLeU32, CHUNK_16MB } from './bytes.js';
// The first 0x4000 bytes of an .ncz are the raw (still encrypted) NCA header,
// verbatim — shared with the compressor (fs/compress.js).
export const UNCOMPRESSABLE_HEADER_SIZE = 0x4000;
const SECTION_CHUNK_SIZE = CHUNK_16MB; // 16MB

// NCZ container crypto_type (python nsz `Type.Crypto`), as stored in the
// .ncz section tables. DIFFERENT from the NCA-header enum (SECTION_CRYPTO_TYPE
// in nca-utils.js): here 1 = NONE/plaintext (FakeSection gap / unencrypted
// ExeFS), 2 = XTS, 3 = CTR, 4 = BKTR. Shared with the compressor
// (fs/compress.js buildSectnTable).
export const NCZ_CRYPTO_TYPE = { NONE: 1, XTS: 2, CTR: 3, BKTR: 4 };

// NCZSECTN entry — 64 bytes: offset u64, size u64, crypto_type u64,
// 8B reserved, crypto_key 16B, crypto_counter 16B. One declaration of the
// layout for both sides: written by fs/compress.js (buildSectnTable), read
// here (NCZSection).
export const NCZ_SECTN_ENTRY = {
    ENTRY_SIZE: 64,
    OFFSET: 0,
    SIZE: 8,
    CRYPTO_TYPE: 16,
    KEY: 32,
    COUNTER: 48,
};

function allocByte(n) {
    return new Uint8Array(n);
}

function bytesToAscii(bytes, start, end) {
    let str = '';
    for (let i = start; i < end; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return str;
}

function sliceBytes(bytes, start, end) {
    return bytes.subarray(start, end);
}

const READ_CHUNK_SIZE = CHUNK_16MB; // 16 MB per chunk, streaming decompressor handles any size

class DataReader {
    async read(offset, size) {
        throw new Error('abstract');
    }

    get length() {
        throw new Error('abstract');
    }
}

class AdapterNCZReader extends DataReader {
    constructor(adapter, fileOffset, fileSize) {
        super();
        this._adapter = adapter;
        this._fileOffset = fileOffset;
        this._length = fileSize;
    }
    get length() { return this._length; }
    async read(offset, size) {
        return this._adapter.read(this._fileOffset + offset, size);
    }
}

class BufferReader extends DataReader {
    constructor(buffer) {
        super();
        this.buffer = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    }

    get length() {
        return this.buffer.length;
    }

    async read(offset, size) {
        return this.buffer.subarray(offset, offset + size);
    }
}

class NCZSection {
    constructor(data, offset) {
        const E = NCZ_SECTN_ENTRY;
        this.offset = readLeU64(data, offset + E.OFFSET);
        this.size = readLeU64(data, offset + E.SIZE);
        this.cryptoType = readLeU64(data, offset + E.CRYPTO_TYPE);
        this.cryptoKey = sliceBytes(data, offset + E.KEY, offset + E.KEY + 16);
        this.cryptoCounter = sliceBytes(data, offset + E.COUNTER, offset + E.COUNTER + 16);
    }
}

class NCZBlockHeader {
    constructor(data, offset) {
        this.magic = bytesToAscii(data, offset, offset + 8);
        this.version = data[offset + 8];
        this.type = data[offset + 9];
        this.unused = data[offset + 10];
        this.blockSizeExponent = data[offset + 11];
        this.numberOfBlocks = readLeU32(data, offset + 12);
        this.decompressedSize = readLeU64(data, offset + 16);
    }
}

class FakeSection {
    constructor(offset, size) {
        this.offset = offset;
        this.size = size;
        this.cryptoType = NCZ_CRYPTO_TYPE.NONE;
        this.cryptoKey = allocByte(16);
        this.cryptoCounter = allocByte(16);
    }
}

async function parseNczSections(reader) {
    if (reader._nczParsed) return reader._nczParsed;

    const magicBytes = await reader.read(0, 8);
    const magic = bytesToAscii(magicBytes, 0, 8);
    console.log('[NCZ] magic at offset 0:', JSON.stringify(magic));

    let nczhdrOffset = 0;
    let ncaHeader = null;
    if (magic !== 'NCZSECTN') {
        const magicAt4000Bytes = await reader.read(UNCOMPRESSABLE_HEADER_SIZE, 8);
        const magicAt4000 = bytesToAscii(magicAt4000Bytes, 0, 8);
        console.log('[NCZ] magic at offset 0x4000:', JSON.stringify(magicAt4000));
        if (magicAt4000 === 'NCZSECTN') {
            console.log('[NCZ] NCA header detected at offset 0, NCZSECTN at 0x4000');
            ncaHeader = await reader.read(0, UNCOMPRESSABLE_HEADER_SIZE);
            nczhdrOffset = UNCOMPRESSABLE_HEADER_SIZE;
        } else {
            // Strict, matching python nsz (raise "No NCZSECTN found"). A .ncz
            // without NCZSECTN at 0 or 0x4000 — plain NCA under a .ncz name or
            // a corrupt pack — is an error, not a silent raw copy.
            throw new Error(
                `Invalid NCZ magic: expected NCZSECTN at 0 or 0x4000, got ${magic} (at 0) / ${magicAt4000} (at 0x4000)`);
        }
    }

    let offset = nczhdrOffset + 8;
    const sectionCountBytes = await reader.read(offset, 8);
    const sectionCount = readLeU64(sectionCountBytes, 0);
    console.log('[NCZ] sectionCount:', sectionCount);
    offset += 8;

    const sections = [];
    for (let i = 0; i < sectionCount; i++) {
        const sectionData = await reader.read(offset, NCZ_SECTN_ENTRY.ENTRY_SIZE);
        sections.push(new NCZSection(sectionData, 0));
        offset += NCZ_SECTN_ENTRY.ENTRY_SIZE;
    }

    if (sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE > 0) {
        sections.unshift(new FakeSection(
            UNCOMPRESSABLE_HEADER_SIZE,
            sections[0].offset - UNCOMPRESSABLE_HEADER_SIZE
        ));
    }

    let ncaSize = UNCOMPRESSABLE_HEADER_SIZE;
    for (const s of sections) {
        ncaSize += s.size;
    }

    const result = { sections, ncaSize, headerEnd: offset, ncaHeader };
    reader._nczParsed = result;
    return result;
}

class NCZDecompressor {
    constructor(data) {
        if (data instanceof DataReader) {
            this.reader = data;
        } else {
            this.reader = new BufferReader(data);
        }
    }

    async decompress(progressCallback = null, writeChunk = null, parsed = null) {
        const { sections, ncaSize, headerEnd, ncaHeader } = parsed ?? await parseNczSections(this.reader);
        console.log('[NCZ] sections:', sections.length, 'ncaSize:', ncaSize, 'headerEnd:', headerEnd);

        let useBlock = false;
        if (headerEnd < this.reader.length) {
            const magicBytes = await this.reader.read(headerEnd, 8);
            const magic = bytesToAscii(magicBytes, 0, 8);
            useBlock = magic === 'NCZBLOCK';
            console.log('[NCZ] compression mode:', useBlock ? 'block' : 'streaming');
        }

        let output = null;
        let wfn = writeChunk;
        if (!wfn) {
            output = allocByte(ncaSize);
            wfn = async (chunk, pos) => output.set(chunk, pos);
        }

        if (ncaHeader) await wfn(ncaHeader, 0);

        if (useBlock) {
            await this._decompressBlocks(sections, ncaSize, headerEnd, progressCallback, wfn);
        } else if (headerEnd < this.reader.length) {
            await this._decompressStream(sections, ncaSize, headerEnd, progressCallback, wfn);
        }

        return output;
    }

    async _decompressStream(sections, ncaSize, headerEnd, progressCallback, writeChunk) {
        const remaining = this.reader.length - headerEnd;
        const sortedSections = [...sections].sort((a, b) => a.offset - b.offset);
        const sectionAesCtrs = new Map();
        for (const s of sortedSections) {
            if (s.cryptoType === NCZ_CRYPTO_TYPE.CTR || s.cryptoType === NCZ_CRYPTO_TYPE.BKTR) {
                sectionAesCtrs.set(s, new AesCtr(s.cryptoKey, s.cryptoCounter, 0, aesBackend()));
            }
        }

        let sectionIdx = 0;
        let lastAesCtr = null;
        let lastDecryptEnd = -1;
        const processChunk = async (chunk, decompOffset) => {
            // Capture before writeChunk: a plaintext section's chunk can be
            // transferred (detached) by the SW adapter, zeroing .length.
            const chunkLen = chunk.length;
            let offset = 0;
            while (offset < chunkLen) {
                const ncaPos = decompOffset + offset;
                while (sectionIdx < sortedSections.length - 1 &&
                       ncaPos >= sortedSections[sectionIdx].offset + sortedSections[sectionIdx].size) {
                    sectionIdx++;
                }
                let aesCtr = null;
                let boundary = chunkLen;
                if (sectionIdx < sortedSections.length) {
                    const s = sortedSections[sectionIdx];
                    aesCtr = sectionAesCtrs.get(s) || null;
                    boundary = Math.min(chunkLen, offset + (s.offset + s.size - ncaPos));
                }
                const subSize = boundary - offset;
                let data = chunk.subarray(offset, offset + subSize);
                if (aesCtr) {
                    if (aesCtr !== lastAesCtr || ncaPos !== lastDecryptEnd) {
                        aesCtr.seek(ncaPos);
                    }
                    data = await aesCtr.decrypt(data);
                    lastDecryptEnd = ncaPos + data.length;
                    lastAesCtr = aesCtr;
                }
                await writeChunk(data, ncaPos);
                offset += subSize;
                if (progressCallback) progressCallback((decompOffset + offset) / ncaSize);
            }
            return decompOffset + chunkLen;
        };

        let pos = headerEnd;
        let toRead = remaining;
        let decompOffset = UNCOMPRESSABLE_HEADER_SIZE;
        // The payload covers 0x4000..ncaSize, so its decompressed size is the
        // sum of all section sizes = ncaSize - 0x4000. The strict WASM backend
        // uses expectedSize to gate the output byte count exactly (the tootallnate
        // frames here carry no content size — multi-segment, no FCS field);
        // inputSize is the compressed payload length (an input upper-bound check).
        // The Node backend ignores both hints.
        for await (const chunk of decompressStream(async () => {
            if (toRead <= 0) return null;
            const size = Math.min(toRead, READ_CHUNK_SIZE);
            const data = await this.reader.read(pos, size);
            pos += data.length;
            toRead -= data.length;
            return data;
        }, ncaSize - UNCOMPRESSABLE_HEADER_SIZE, remaining)) {
            decompOffset = await processChunk(chunk, decompOffset);
        }
    }

    async _decompressBlocks(sections, ncaSize, headerEnd, progressCallback, writeChunk) {
        const blockHeaderData = await this.reader.read(headerEnd, 24);
        const blockHeader = new NCZBlockHeader(blockHeaderData, 0);
        if (blockHeader.blockSizeExponent < 14 || blockHeader.blockSizeExponent > 32) {
            throw new Error(`Corrupted NCZBLOCK header: Block size must be between 14 and 32, got ${blockHeader.blockSizeExponent}`);
        }
        const sizeListSize = blockHeader.numberOfBlocks * 4;
        const sizeListData = await this.reader.read(headerEnd + 24, sizeListSize);

        const reader = new AsyncBlockDecompressorReader(
            this.reader, headerEnd,
            blockHeader.blockSizeExponent, blockHeader.numberOfBlocks,
            blockHeader.decompressedSize, sizeListData
        );

        let decompressedOffset = UNCOMPRESSABLE_HEADER_SIZE;
        let isFirstSection = true;
        for (const section of sections) {
            let i = section.offset;
            const end = section.offset + section.size;

            if (isFirstSection) {
                isFirstSection = false;
                const skip = UNCOMPRESSABLE_HEADER_SIZE - sections[0].offset;
                if (skip > 0) i += skip;
            }

            let aesCtr = null;
            if (section.cryptoType === NCZ_CRYPTO_TYPE.CTR || section.cryptoType === NCZ_CRYPTO_TYPE.BKTR) {
                aesCtr = new AesCtr(section.cryptoKey, section.cryptoCounter, 0, aesBackend());
                aesCtr.seek(i);
            }

            while (i < end) {
                const chunkSize = Math.min(SECTION_CHUNK_SIZE, end - i);
                const chunk = await reader.read(chunkSize);
                if (!chunk || chunk.length === 0) break;
                // Capture before writeChunk: for plaintext sections data === chunk,
                // and the SW adapter transfers it (detached .length would stall i).
                const chunkLen = chunk.length;

                const data = aesCtr ? await aesCtr.decrypt(chunk) : chunk;
                await writeChunk(data, i);

                i += chunkLen;
                decompressedOffset += chunkLen;
                if (progressCallback) progressCallback(decompressedOffset / ncaSize);
            }
        }
    }


}

// Parse the NCZBLOCK size list into an independent block schedule: per-block
// relOffset (from baseOffset) and compressedSize in two parallel flat arrays,
// plus blockSize and the last (short) block's decompressedSize derived from
// decompressedSize % blockSize. Flat parallel arrays (not per-block objects)
// for cache locality and zero heap churn on huge NCZ. Pure — no I/O, no
// container globals — so a parallel block decoder can pair relOffsets[i] with
// sizes[i] as per-block jobs and run decompressBlock in workers.
function parseBlockSchedule(blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData) {
    const blockSize = Math.pow(2, blockSizeExponent);
    const sizes = new Array(numberOfBlocks);
    const relOffsets = new Array(numberOfBlocks);
    let offset = 24 + numberOfBlocks * 4;
    for (let i = 0; i < numberOfBlocks; i++) {
        const compressedSize = readLeU32(sizeListData, i * 4);
        sizes[i] = compressedSize;
        relOffsets[i] = offset;
        offset += compressedSize;
    }
    const remainder = decompressedSize % blockSize;
    return { sizes, relOffsets, blockSize, remainder };
}

function concatParts(parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

class AsyncBlockDecompressorReader {
    constructor(reader, baseOffset, blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData) {
        this.reader = reader;
        this.baseOffset = baseOffset;
        this.currentBlock = null;
        this.currentBlockIndex = -1;

        this.schedule = parseBlockSchedule(blockSizeExponent, numberOfBlocks, decompressedSize, sizeListData);
    }

    async nextBlock() {
        const i = ++this.currentBlockIndex;
        const { sizes, relOffsets, blockSize, remainder } = this.schedule;
        if (i >= sizes.length) {
            this.currentBlock = null;
            return null;
        }

        const compressedSize = sizes[i];
        let decompressedSize = blockSize;
        if (i === sizes.length - 1 && remainder > 0) {
            decompressedSize = remainder;
        }

        const compressedData = await this.reader.read(this.baseOffset + relOffsets[i], compressedSize);

        // The raw/incompressible-vs-compressed decision is container knowledge:
        // a stored raw block fits in less space than the decompressed size, so
        // no zstd decode is needed. The raw fast path returns the bytes
        // directly (no Promise), so it stays free of a per-block microtask.
        if (compressedSize < decompressedSize) {
            this.currentBlock = await decompressBlock(compressedData, decompressedSize);
        } else {
            this.currentBlock = compressedData;
        }

        return this.currentBlock;
    }

    async read(size) {
        if (!this.currentBlock) {
            await this.nextBlock();
        }
        if (!this.currentBlock) return null;

        const toRead = Math.min(this.currentBlock.length, size);
        const chunk = sliceBytes(this.currentBlock, 0, toRead);

        if (toRead < this.currentBlock.length) {
            this.currentBlock = this.currentBlock.subarray(toRead);
        } else {
            this.currentBlock = null;
        }

        return chunk;
    }

    close() {
        // No resources to release
    }
}

// ── Virtual NCA view over an NCZ (re-compression) ───────────────────────────
// Presents the ORIGINAL NCA's bytes — the raw 0x4000 header verbatim + the
// payload zstd-decompressed and re-encrypted per the NCZSECTN table — to code
// that expects an NCA reader (fs/compress.js: analyzeNca, expandBktr,
// fillPlaintextBlock), so an .ncz member can be re-compressed without ever
// materializing the whole NCA.
//
// The compressor's read pattern is: raw header, one DEEP read (the BKTR
// subsection table near the end of the payload), then a sequential walk from
// 0x4000. The backward jump after the deep read is handled by restarting the
// internal stream — block-mode frames are independent (the wanted frame is
// just (re-)decompressed on demand, last one cached); the solid frame is
// re-fed from its start. Memory is O(1 input block / output chunk).
//
// Re-encryption: ONE AesCtr per CTR/BKTR section (cheap small allocs),
// seek()ed to the absolute NCA offset at the start of every sub-run — exactly
// the keystream the decompressor re-applies (CTR encrypt == decrypt). Seeked
// per sub-run, so discarded fast-forward chunks need no crypto at all.
export class NczNcaReader extends DataReader {
    constructor(reader) {
        super();
        this.reader = reader;
        this._parsed = null;
        this._sections = null;
        this._schedule = null;    // block mode: { sizes, relOffsets, blockSize, remainder, baseOffset }
        this._solid = false;
        this._gen = null;         // solid mode: decompressStream generator
        this._streamNext = 0;     // solid mode: NCA offset of the next chunk
        this._filePos = 0;        // solid mode: compressed-input cursor
        this._pending = null;     // { data, pos } — re-encrypted plaintext not yet served
        this._lastBlock = -1;     // block mode: cached block index
        this._lastBlockData = null;
    }

    // Parse the NCZSECTN table + payload layout (idempotent). Strict: a member
    // named .ncz that is not a valid NCZ throws (same stance as the decompress
    // path — a raw NCA under a .ncz name is an error, not a silent copy).
    async ensure() {
        if (this._parsed) return this._parsed;
        const parsed = await parseNczSections(this.reader);
        this._parsed = parsed;
        this._sections = [...parsed.sections].sort((a, b) => a.offset - b.offset);
        for (const s of this._sections) {
            if (s.cryptoType === NCZ_CRYPTO_TYPE.CTR || s.cryptoType === NCZ_CRYPTO_TYPE.BKTR) {
                s._ctr = new AesCtr(s.cryptoKey, s.cryptoCounter, 0, aesBackend());
            }
        }
        const { headerEnd } = parsed;
        if (headerEnd >= this.reader.length) return parsed; // header-only NCA, no payload
        const magic = bytesToAscii(await this.reader.read(headerEnd, 8), 0, 8);
        if (magic === 'NCZBLOCK') {
            const bh = new NCZBlockHeader(await this.reader.read(headerEnd, 24), 0);
            if (bh.blockSizeExponent < 14 || bh.blockSizeExponent > 32) {
                throw new Error(`Corrupted NCZBLOCK header: Block size must be between 14 and 32, got ${bh.blockSizeExponent}`);
            }
            const sizeList = await this.reader.read(headerEnd + 24, bh.numberOfBlocks * 4);
            this._schedule = {
                ...parseBlockSchedule(bh.blockSizeExponent, bh.numberOfBlocks, bh.decompressedSize, sizeList),
                baseOffset: headerEnd,
            };
        } else {
            this._solid = true;
            // First-pull cursor: the compressed frame starts at headerEnd
            // (_resetSolid restores exactly this state on backward seeks).
            this._filePos = headerEnd;
            this._streamNext = UNCOMPRESSABLE_HEADER_SIZE;
        }
        return parsed;
    }

    // The VIRTUAL NCA size (the parsed sections' end), not the .ncz file size.
    get length() {
        return this._parsed ? this._parsed.ncaSize : this.reader.length;
    }

    // Read `size` bytes of the virtual NCA at absolute NCA offset.
    async read(absOffset, size) {
        await this.ensure();
        const { ncaSize } = this._parsed;
        if (size <= 0 || absOffset >= ncaSize) return new Uint8Array(0);
        const end = Math.min(ncaSize, absOffset + size);
        if (end <= UNCOMPRESSABLE_HEADER_SIZE) {
            // Raw NCA header region — verbatim the .ncz's first 0x4000 bytes.
            return await this.reader.read(absOffset, end - absOffset);
        }
        if (absOffset < UNCOMPRESSABLE_HEADER_SIZE) {
            // Straddles the header/payload boundary.
            const head = await this.reader.read(absOffset, UNCOMPRESSABLE_HEADER_SIZE - absOffset);
            const tail = await this._readPayload(UNCOMPRESSABLE_HEADER_SIZE, end);
            return concatParts([head, tail]);
        }
        return await this._readPayload(absOffset, end);
    }

    async _readPayload(off, end) {
        if (this._schedule) return await this._readBlocks(off, end);
        if (!this._solid) return new Uint8Array(0); // header-only NCZ
        return await this._readSolid(off, end);
    }

    // ── Block mode: independent frames, decompressed on demand ───────────────
    async _readBlocks(off, end) {
        const { blockSize, sizes } = this._schedule;
        const ncaSize = this._parsed.ncaSize;
        const parts = [];
        let pos = off;
        while (pos < end) {
            const i = Math.floor((pos - UNCOMPRESSABLE_HEADER_SIZE) / blockSize);
            const blockStart = UNCOMPRESSABLE_HEADER_SIZE + i * blockSize;
            const blockEnd = Math.min(blockStart + blockSize, ncaSize);
            const plain = await this._blockPlain(i);
            const take = Math.min(end, blockEnd) - pos;
            parts.push(plain.subarray(pos - blockStart, pos - blockStart + take));
            pos += take;
        }
        return parts.length === 1 ? parts[0] : concatParts(parts);
    }

    async _blockPlain(i) {
        if (this._lastBlock === i) return this._lastBlockData;
        const { blockSize, sizes, relOffsets, remainder, baseOffset } = this._schedule;
        const compressedSize = sizes[i];
        const dSize = (i === sizes.length - 1 && remainder > 0) ? remainder : blockSize;
        let plain;
        if (compressedSize < dSize) {
            // A zstd frame — the raw-stored case can never be ≥ the plaintext.
            const frame = await this.reader.read(baseOffset + relOffsets[i], compressedSize);
            plain = await decompressBlock(frame, dSize);
        } else {
            // Stored raw (incompressible): the bytes ARE the plaintext.
            plain = await this.reader.read(baseOffset + relOffsets[i], compressedSize);
        }
        plain = await this._reencrypt(plain, UNCOMPRESSABLE_HEADER_SIZE + i * blockSize);
        this._lastBlock = i;
        this._lastBlockData = plain;
        return plain;
    }

    // ── Solid mode: one frame, re-fed from the start on backward seeks ───────
    async _readSolid(off, end) {
        const want = end - off;
        // Position the internal stream at (or before) off.
        if (this._pending && (off < this._pending.pos || off >= this._pending.pos + this._pending.data.length)) {
            this._resetSolid();
        } else if (!this._pending && this._gen && this._streamNext > off) {
            this._resetSolid();
        }
        // Discard pending that lies wholly before off.
        while (this._pending && this._pending.pos + this._pending.data.length <= off) this._pending = null;
        if (this._pending) {
            const skip = off - this._pending.pos;
            if (skip > 0) this._pending = { data: this._pending.data.subarray(skip), pos: off };
        }
        // Fast-forward the stream to off. Whole chunks landing before off are
        // discarded WITHOUT crypto (never served — the per-sub-run seek() makes
        // skipping safe and saves a full AES pass); the one straddling chunk is
        // re-encrypted — its [off, ...) tail becomes the served pending.
        while (!this._pending && (!this._gen || this._streamNext < off)) {
            const c = await this._solidPull(false);
            if (!c) throw new Error('NCZ solid frame is shorter than the declared payload size');
            if (c.pos + c.data.length <= off) continue; // whole chunk before off — discard
            const enc = await this._reencrypt(c.data, c.pos);
            this._pending = { data: enc.subarray(off - c.pos), pos: off };
        }
        const parts = [];
        let got = 0;
        while (got < want) {
            if (this._pending) {
                const take = Math.min(want - got, this._pending.data.length);
                parts.push(this._pending.data.subarray(0, take));
                got += take;
                this._pending = take < this._pending.data.length
                    ? { data: this._pending.data.subarray(take), pos: this._pending.pos + take }
                    : null;
                continue;
            }
            const c = await this._solidPull(true);
            if (!c) throw new Error('NCZ solid frame is shorter than the declared payload size');
            const take = Math.min(want - got, c.data.length);
            parts.push(c.data.subarray(0, take));
            got += take;
            if (take < c.data.length) this._pending = { data: c.data.subarray(take), pos: c.pos + take };
        }
        return parts.length === 1 ? parts[0] : concatParts(parts);
    }

    _resetSolid() {
        this._gen = null;
        this._pending = null;
        this._streamNext = UNCOMPRESSABLE_HEADER_SIZE;
        this._filePos = this._parsed.headerEnd;
    }

    // Next chunk of the solid frame at this._streamNext (or null at end).
    // doCrypto=false for fast-forward discards (never served — the per-sub-run
    // seek() makes skipping crypto safe and saves a full AES pass).
    async _solidPull(doCrypto) {
        if (!this._gen) {
            const headerEnd = this._parsed.headerEnd;
            const inputSize = this.reader.length - headerEnd;
            // expectedSize is authoritative (the tootallnate frames carry no
            // content size) — the strict gate catches silent truncation.
            this._gen = decompressStream(async () => {
                if (this._filePos >= this.reader.length) return null;
                const n = Math.min(READ_CHUNK_SIZE, this.reader.length - this._filePos);
                const data = await this.reader.read(this._filePos, n);
                this._filePos += data.length;
                return data;
            }, this._parsed.ncaSize - UNCOMPRESSABLE_HEADER_SIZE, inputSize);
            this._streamNext = UNCOMPRESSABLE_HEADER_SIZE;
        }
        const next = await this._gen.next();
        if (next.done) return null;
        const pos = this._streamNext;
        this._streamNext += next.value.length;
        return { data: doCrypto ? await this._reencrypt(next.value, pos) : next.value, pos };
    }

    // Re-encrypt (CTR decrypt) a plaintext slice starting at absolute NCA
    // offset `start`, per the NCZSECTN table. The sections cover [0x4000,
    // ncaSize) contiguously (the parser inserts a FakeSection for the leading
    // gap), so every byte belongs to exactly one section.
    async _reencrypt(plain, start) {
        const sections = this._sections;
        let anyCtr = false;
        for (const s of sections) if (s._ctr) { anyCtr = true; break; }
        if (!anyCtr) return plain;
        const out = new Uint8Array(plain.length);
        let i = 0;
        let si = 0;
        while (i < plain.length) {
            const pos = start + i;
            while (si < sections.length - 1 && pos >= sections[si].offset + sections[si].size) si++;
            const s = sections[si];
            const take = Math.min(plain.length - i, s.offset + s.size - pos);
            const slice = plain.subarray(i, i + take);
            if (s._ctr) {
                s._ctr.seek(pos);
                out.set(await s._ctr.decrypt(slice), i);
            } else {
                out.set(slice, i);
            }
            i += take;
        }
        return out;
    }
}

export { NCZDecompressor, DataReader, AdapterNCZReader, BufferReader, READ_CHUNK_SIZE, parseNczSections, parseBlockSchedule, AsyncBlockDecompressorReader };
