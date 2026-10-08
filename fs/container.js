// Container detection/opening: identify whether an input is an NSP/NSZ
// (PFS0) or an XCZ (XCI) and return its top-level file entries.

import { PFS0 } from './pfs0.js';
import { XCIReader } from './xci.js';

// Enrich a PFS0/XCI entry with its output member name (nsz/xcz → nca).
function enrichEntry(e) {
    return { ...e, outputName: e.name.toLowerCase().endsWith('.ncz') ? e.name.replace(/\.ncz$/i, '.nca') : e.name };
}

// Container length when the reader exposes one, null otherwise. The DataReader
// base class throws from its `length` getter when a subclass never implemented
// it, so the access is guarded.
function readerLength(reader) {
    try {
        const len = reader && reader.length;
        return typeof len === 'number' && Number.isFinite(len) && len > 0 ? len : null;
    } catch (_e) {
        return null;
    }
}

// Fail fast when entries point past the end of the container. The PFS0/HFS0
// header describes the FULL container, so a truncated download (or a header
// from a larger original) sends every member past the cut to an offset that
// reads back as 0 bytes — which otherwise surfaces much later as a cryptic
// "Failed to decrypt NCA header: bad magic ''" from the NCA decoder.
function assertEntriesFit(entries, length, name) {
    if (length === null) return;
    for (const e of entries) {
        const end = e.offset + e.size;
        if (end > length) {
            const present = Math.max(0, length - e.offset);
            throw new Error(
                `${name}: truncated/corrupt container — member '${e.name}' ends at ${end} bytes ` +
                `but the file is only ${length} (${present} of ${e.size} bytes present). ` +
                `Re-download or re-copy the file.`
            );
        }
    }
}

// r = { reader, name }. Returns { kind: 'pfs0'|'xci', entries }.
// Each entry has { name, offset, size, outputName }.
export async function openContainer(r) {
    const magic = await r.reader.read(0, 4);
    const m = String.fromCharCode(magic[0], magic[1], magic[2], magic[3]);
    if (m === 'PFS0') {
        const pfs0 = await PFS0.open(r.reader);
        const entries = pfs0.getFiles().map(enrichEntry);
        assertEntriesFit(entries, readerLength(r.reader), r.name);
        return { kind: 'pfs0', entries };
    }
    let head = await r.reader.read(0x100, 4);
    let isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    if (!isHead) {
        head = await r.reader.read(0x1100, 4);
        isHead = String.fromCharCode(head[0], head[1], head[2], head[3]) === 'HEAD';
    }
    if (isHead) {
        const xci = new XCIReader(r.reader);
        await xci.parse();
        const entries = await xci.getSecureFiles();
        if (entries.length === 0) {
            throw new Error(`no secure partition files found in ${r.name}`);
        }
        const enriched = entries.map(enrichEntry);
        assertEntriesFit(enriched, readerLength(r.reader), r.name);
        return { kind: 'xci', entries: enriched };
    }
    throw new Error(`unsupported container in ${r.name} (magic ${m})`);
}
