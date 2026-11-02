import { DataReader, BufferReader } from './ncz.js';
import { HFS0Reader } from './hfs0.js';

export { HFS0Reader };

const XCI_PARTITION_NAMES = new Set(['secure', 'normal', 'update', 'logo']);

// XCI container geometry (switchbrew XCI): HEAD at 0x100 (backup 0x1100),
// root HFS0 at 0xF000, each partition preceded by a 0x8000 header region and
// sized to a 0x200 multiple (python nsz BlockCompressor.align0x200). Shared
// by the reader (here), the decompressor (fs/xcz-decompress.js) and the
// compressor (fs/compress.js).
export const XCI_LAYOUT = {
    HEAD_OFFSET: 0x100,
    HEAD_BACKUP_OFFSET: 0x1100,
    HEAD_SIZE: 0x200,
    ROOT_HFS0_OFFSET: 0xF000,
    PARTITION_HEADER_SIZE: 0x8000,
    MIN_PARTITION_SIZE: 0x200,
};

// HEAD field offsets (switchbrew XCI Head, relative to the HEAD start).
export const XCI_HEAD = {
    MAGIC: 0x000,                 // "HEAD"
    SECURE_OFFSET: 0x104,
    BACKUP_OFFSET: 0x108,
    TITLE_KEK_INDEX: 0x10C,
    GAMECARD_SIZE: 0x10D,
    GAMECARD_HEADER_VERSION: 0x10E,
    GAMECARD_FLAGS: 0x10F,
    PACKAGE_ID: 0x110,
    VALID_DATA_END_OFFSET: 0x118,
    GAMECARD_INFO: 0x120,         // 16B
    HFS0_OFFSET: 0x130,
    HFS0_HEADER_SIZE: 0x138,
    HFS0_HEADER_HASH: 0x140,      // 32B
    HFS0_INITIAL_DATA_HASH: 0x160, // 32B
    SECURE_MODE: 0x180,
    TITLE_KEY_FLAG: 0x184,
    KEY_FLAG: 0x188,
    NORMAL_AREA_END_OFFSET: 0x18C,
};

// python nsz BlockCompressor.align0x200 — padding added to the ACTUAL
// partition size to reach the next 0x200 boundary (an empty partition is a
// 0x200 stub).
export const align0x200 = (n) => XCI_LAYOUT.MIN_PARTITION_SIZE - (n % XCI_LAYOUT.MIN_PARTITION_SIZE);

export class XCIReader {
    constructor(readerOrBuffer) {
        if (readerOrBuffer instanceof DataReader || (readerOrBuffer && typeof readerOrBuffer.read === 'function')) {
            this.reader = readerOrBuffer;
        } else {
            this.reader = new BufferReader(readerOrBuffer);
        }
        this.rootHfs0 = null;
        this.partitions = [];
    }

    async parse() {
        const L = XCI_LAYOUT, H = XCI_HEAD;
        const magicAt = (buf, off) => String.fromCharCode(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
        const probe = await this.reader.read(0, L.HEAD_SIZE);
        let headerBytes = probe;
        let headOffset = L.HEAD_OFFSET;

        if (magicAt(probe, L.HEAD_OFFSET) !== 'HEAD') {
            const backup = await this.reader.read(L.HEAD_BACKUP_OFFSET - L.HEAD_OFFSET, L.HEAD_SIZE);
            if (magicAt(backup, L.HEAD_OFFSET) === 'HEAD') {
                headerBytes = backup;
                headOffset = L.HEAD_BACKUP_OFFSET;
            } else {
                throw new Error(`Invalid XCI container (bad HEAD magic at 0x${L.HEAD_OFFSET.toString(16)}/0x${L.HEAD_BACKUP_OFFSET.toString(16)})`);
            }
        }

        const view = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength);

        this.headOffset = headOffset;
        this.secureOffset = view.getUint32(H.SECURE_OFFSET, true);
        this.backupOffset = view.getUint32(H.BACKUP_OFFSET, true);
        this.titleKekIndex = view.getUint8(H.TITLE_KEK_INDEX);
        this.gamecardSize = view.getUint8(H.GAMECARD_SIZE);
        this.gamecardHeaderVersion = view.getUint8(H.GAMECARD_HEADER_VERSION);
        this.gamecardFlags = view.getUint8(H.GAMECARD_FLAGS);
        this.packageId = Number(view.getBigUint64(H.PACKAGE_ID, true));
        this.validDataEndOffset = Number(view.getBigUint64(H.VALID_DATA_END_OFFSET, true));
        this.gamecardInfo = headerBytes.slice(H.GAMECARD_INFO, H.GAMECARD_INFO + 0x10);

        this.hfs0Offset = Number(view.getBigUint64(H.HFS0_OFFSET, true));
        this.hfs0HeaderSize = Number(view.getBigUint64(H.HFS0_HEADER_SIZE, true));
        this.hfs0HeaderHash = headerBytes.slice(H.HFS0_HEADER_HASH, H.HFS0_HEADER_HASH + 0x20);
        this.hfs0InitialDataHash = headerBytes.slice(H.HFS0_INITIAL_DATA_HASH, H.HFS0_INITIAL_DATA_HASH + 0x20);
        this.secureMode = view.getUint32(H.SECURE_MODE, true);

        this.titleKeyFlag = view.getUint32(H.TITLE_KEY_FLAG, true);
        this.keyFlag = view.getUint32(H.KEY_FLAG, true);
        this.normalAreaEndOffset = view.getUint32(H.NORMAL_AREA_END_OFFSET, true);

        const rootHfs0Offset = this.hfs0Offset + headOffset - L.HEAD_OFFSET;
        const hfs0Data = await this.reader.read(rootHfs0Offset, this.hfs0HeaderSize);
        this.rootHfs0 = new HFS0Reader(hfs0Data, rootHfs0Offset);
        this.partitions = this.rootHfs0.getFiles();
    }

    async readPartitionHeader(partitionEntry) {
        const probe = await this.reader.read(partitionEntry.offset, 0x10);
        const v = new DataView(probe.buffer, probe.byteOffset, probe.byteLength);
        const fileCount = v.getUint32(4, true);
        const stringTableSize = v.getUint32(8, true);
        const headerSize = 0x10 + fileCount * 0x40 + stringTableSize;
        const data = await this.reader.read(partitionEntry.offset, headerSize);
        return new HFS0Reader(data, partitionEntry.offset);
    }

    async getSecureFiles() {
        const secure = this.partitions.find((p) => p.name === 'secure');
        if (!secure) return [];
        const hfs0 = await this.readPartitionHeader(secure);
        return hfs0.getFiles();
    }

    getPartitions() {
        return this.partitions;
    }

    async readPartitionFiles(partitionEntry) {
        const data = await this.reader.read(partitionEntry.offset, partitionEntry.size);
        return new HFS0Reader(data, partitionEntry.offset);
    }
}
