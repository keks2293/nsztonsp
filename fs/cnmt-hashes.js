import { parseCnmtFromRawNca } from './nca.js';

export async function extractContentHashMap(ncaData, keys) {
    const map = new Map();
    const arr = ncaData instanceof Uint8Array ? ncaData : new Uint8Array(ncaData);

    try {
        const m = await parseCnmtFromRawNca(arr, keys);
        if (m.cnmt.contentEntries) {
            for (const entry of m.cnmt.contentEntries) {
                map.set(entry.ncaId, entry.hash);
            }
        }
    } catch (e) {
        console.error('Error extracting CNMT hash map:', e);
    }
    return map;
}