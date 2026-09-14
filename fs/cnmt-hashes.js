import { decryptNcaHeader, readCnmtFromMeta } from './nca.js';

export async function extractContentHashMap(ncaData, keys) {
    const map = new Map();
    const arr = ncaData instanceof Uint8Array ? ncaData : new Uint8Array(ncaData);

    const header = decryptNcaHeader(arr, keys);
    if (!header) return map;

    try {
        const reader = { read: (offset, length) => arr.subarray(offset, offset + length) };
        const cnmt = await readCnmtFromMeta(reader, { offset: 0, size: arr.length }, header);
        if (cnmt && cnmt.contentEntries) {
            for (const entry of cnmt.contentEntries) {
                map.set(entry.ncaId, entry.hash);
            }
        }
    } catch (e) {
        console.error('Error extracting CNMT hash map:', e);
    }
    return map;
}