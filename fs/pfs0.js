// Layout sizes mirror hacpack's packed structs (pfs0.h): pfs0_header_t
// (magic, num_files, string_table_size, reserved) and pfs0_file_entry_t
// (offset, size, string_table_offset, reserved). hacpack computes the header
// as sizeof(pfs0_header_t) + sizeof(pfs0_file_entry_t)·N + stringtable.
const PFS0_HEADER_SIZE = 0x10;
const PFS0_ENTRY_SIZE = 0x18;

class PFS0 {
    constructor(data) {
        this._data = new Uint8Array(data);
        this._view = new DataView(this._data.buffer, this._data.byteOffset, this._data.byteLength);
        this.files = [];
        this.headerSize = 0;
        this._parse();
    }

    static async open(reader) {
        const head = new Uint8Array(await reader.read(0, PFS0_HEADER_SIZE));
        const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
        const fileCount = view.getUint32(4, true);
        const stringTableSize = view.getUint32(8, true);
        const headerSize = PFS0_HEADER_SIZE + fileCount * PFS0_ENTRY_SIZE + stringTableSize;
        const buf = new Uint8Array(await reader.read(0, headerSize));
        return new PFS0(buf);
    }

    _parse() {
        const magic = String.fromCharCode(this._data[0], this._data[1], this._data[2], this._data[3]);
        if (magic !== 'PFS0') {
            throw new Error(`Invalid PFS0 magic: ${magic}`);
        }

        const fileCount = this._view.getUint32(4, true);
        const stringTableSize = this._view.getUint32(8, true);
        this.stringTableSize = stringTableSize;
        this.headerSize = PFS0_HEADER_SIZE + fileCount * PFS0_ENTRY_SIZE + stringTableSize;

        const stringTableOffset = PFS0_HEADER_SIZE + fileCount * PFS0_ENTRY_SIZE;

        let stringEndOffset = stringTableSize;

        for (let i = fileCount - 1; i >= 0; i--) {
            const entryOffset = PFS0_HEADER_SIZE + i * PFS0_ENTRY_SIZE;
            const relOffset = Number(this._view.getBigUint64(entryOffset, true));
            const size = Number(this._view.getBigUint64(entryOffset + 8, true));
            const nameOffset = this._view.getUint32(entryOffset + 16, true);

            let name = '';
            for (let j = nameOffset; j < stringEndOffset && j < stringTableSize && this._data[stringTableOffset + j] !== 0; j++) {
                name += String.fromCharCode(this._data[stringTableOffset + j]);
            }
            stringEndOffset = nameOffset;

            const absOffset = relOffset + this.headerSize;
            this.files.push({
                name,
                offset: absOffset,
                size
            });
        }

        this.files.reverse();
    }

    getFiles() {
        return this.files;
    }
}

// PFS0 header size as a pure function of the member name LENGTHS (not the data
// sizes — data offsets come after the header). Lets a caller compute the layout
// before the names are known, as long as their lengths are fixed (e.g. an NSP
// program NCA named by its contentId: 32 hex chars + ".nca" = always 36).
export function pfs0HeaderSize(nameLengths, { fixPadding = false, inputStringTableSize = null, headerAlign = 0x20 } = {}) {
    const stringTableLen = nameLengths.reduce((sum, len) => sum + len + 1, 0);
    const rawSize = PFS0_HEADER_SIZE + nameLengths.length * PFS0_ENTRY_SIZE + stringTableLen;
    const pad = (headerAlign - (rawSize % headerAlign)) % headerAlign;
    const paddedSize = fixPadding
        ? stringTableLen + pad
        : (inputStringTableSize ?? (stringTableLen + pad));
    return PFS0_HEADER_SIZE + nameLengths.length * PFS0_ENTRY_SIZE + paddedSize;
}

class PFS0Writer {
    // headerAlign: 0x20 (Python nsz rule — `Pfs0.getStringTableSize()` pads so the
    // TOTAL header is 0x20-aligned; note hacpack is different: `pfs0.c:121`
    // aligns only the string table, not the header) or 0x10 (Nintendo rule for
    // outer NSP/NSZ containers: pad so the total header is 0x10-aligned —
    // verified on original NSZ headers: Stardew 0x1D0, Little Nightmares II
    // 0x190, both mod 0x20 = 16). The inner CNMT PFS0 (META NCA) uses the 0x20
    // rule (verified: Stardew CNMT strtab=0x38, hdr=0x60).
    constructor(fixPadding = false, inputStringTableSize = null, headerAlign = 0x20) {
        this.files = [];
        this.fixPadding = fixPadding;
        this.inputStringTableSize = inputStringTableSize;
        this.headerAlign = headerAlign;
    }

    add(name, size) {
        const offset = this.files.length === 0
            ? 0
            : this.files[this.files.length - 1].offset + this.files[this.files.length - 1].size;
        this.files.push({ name, offset, size });
        this.addpos = offset + size;
    }

    buildHeader() {
        const stringTable = this.files.map(f => f.name).join('\0') + '\0';
        const headerSize = pfs0HeaderSize(this.files.map(f => f.name.length),
            { fixPadding: this.fixPadding, inputStringTableSize: this.inputStringTableSize, headerAlign: this.headerAlign });
        const paddedSize = headerSize - PFS0_HEADER_SIZE - this.files.length * PFS0_ENTRY_SIZE;
        const padded = stringTable.length < paddedSize
            ? stringTable + '\0'.repeat(paddedSize - stringTable.length)
            : stringTable;
        const namesBytes = new TextEncoder().encode(padded);
        const buf = new Uint8Array(headerSize);
        const v = new DataView(buf.buffer);

        buf[0] = 0x50; buf[1] = 0x46; buf[2] = 0x53; buf[3] = 0x30;
        v.setUint32(4, this.files.length, true);
        v.setUint32(8, paddedSize, true);
        v.setUint32(12, 0, true);

        let soff = 0;
        for (let i = 0; i < this.files.length; i++) {
            const f = this.files[i];
            const pos = PFS0_HEADER_SIZE + i * PFS0_ENTRY_SIZE;
            v.setBigUint64(pos, BigInt(f.offset), true);
            v.setBigUint64(pos + 8, BigInt(f.size), true);
            v.setUint32(pos + 16, soff, true);
            v.setUint32(pos + 20, 0, true);
            soff += f.name.length + 1;
        }

        buf.set(namesBytes, PFS0_HEADER_SIZE + this.files.length * PFS0_ENTRY_SIZE);
        return { buffer: buf, headerSize };
    }
}

export { PFS0, PFS0Writer };
