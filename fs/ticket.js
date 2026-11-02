import { bytesToHex } from './bytes.js';

export class Ticket {
    static parse(buffer) {
        const view = new DataView(buffer);
        let offset = 0;

        const signatureType = view.getUint32(offset, true);
        offset += 4;

        const signatureSizes = {
            0x010000: 0x200,
            0x010001: 0x100,
            0x010002: 0x3C,
            0x010003: 0x200,
            0x010004: 0x100,
            0x010005: 0x3C
        };

        if (!(signatureType in signatureSizes)) {
            throw new Error('Invalid ticket format');
        }

        const sigSize = signatureSizes[signatureType];
        offset += sigSize;

        const paddingSize = 0x40 - ((sigSize + 4) % 0x40);
        offset += paddingSize;

        const issuerBytes = new Uint8Array(buffer.slice(offset, offset + 0x40));
        let issuer = '';
        for (let i = 0; i < 0x40 && issuerBytes[i] !== 0; i++) {
            issuer += String.fromCharCode(issuerBytes[i]);
        }
        offset += 0x40;

        const titleKeyBlock = new Uint8Array(buffer.slice(offset, offset + 0x10));
        offset += 0x100;

        offset += 1;
        const keyType = view.getUint8(offset);
        offset += 1;

        offset += 0xE;

        const ticketIdBytes = new Uint8Array(buffer.slice(offset, offset + 8));
        const ticketId = bytesToHex(ticketIdBytes);
        offset += 8;

        const deviceIdBytes = new Uint8Array(buffer.slice(offset, offset + 8));
        const deviceId = bytesToHex(deviceIdBytes);
        offset += 8;

        const rightsIdBytes = new Uint8Array(buffer.slice(offset, offset + 16));
        const rightsId = bytesToHex(rightsIdBytes);
        offset += 16;

        const accountId = view.getUint32(offset, false);

        const titleId = rightsId.substring(0, 16);
        const masterKeyRevision = parseInt(rightsId.charAt(18) || '0', 16);
        const titleKey = bytesToHex(titleKeyBlock);

        return {
            signatureType,
            issuer,
            titleKeyBlock: titleKey,
            keyType,
            ticketId,
            deviceId,
            rightsId,
            accountId,
            titleId,
            masterKeyRevision,
            titleKey
        };
    }
}

// Collect the container's .tik members into rightsId/titleId → entry maps
// (python nsz Pfs0.open fills the Titles db the same way). `files` is the
// full member list (e.g. PFS0.getFiles()); only names ending in .tik are
// scanned. Entry: { name, size, offset } (copying the member, split.js) +
// read() → pre-read ticket bytes (titlekey extraction, compress.js).
// Maps are keyed by lowercased id; malformed tickets are skipped with a warn.
export async function collectTicketMaps(reader, files, log = () => {}) {
    const byRightsId = new Map();
    const byTitleId = new Map();
    for (const f of files) {
        if (!f.name.toLowerCase().endsWith('.tik')) continue;
        try {
            const data = (await reader.read(f.offset, f.size)).slice();
            // Ticket.parse builds a DataView over the raw ArrayBuffer.
            const t = Ticket.parse(data.buffer);
            const entry = { name: f.name, size: f.size, offset: f.offset, read: async () => data };
            byRightsId.set(t.rightsId.toLowerCase(), entry);
            byTitleId.set(t.titleId.toLowerCase(), entry);
        } catch (err) {
            log('warn', `[Tik] ${f.name}: unreadable ticket (${err.message})`);
        }
    }
    return { byRightsId, byTitleId };
}
