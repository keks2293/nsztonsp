// BKTR (Bucket Tree) primitives for NCA RomFS patching
// Reference: SciresM/hactool (nca.c, bktr.h) + switchbrew.org/wiki/NCA

import { AesEcb } from '../crypto/aes128.js';
import { hexToBytes, readLeU32, readLeU64 } from './bytes.js';


export function parseBktrHeader(fsHdr, offset) {
    return {
        offset: readLeU64(fsHdr, offset),
        size: readLeU64(fsHdr, offset + 8),
        magic: readLeU32(fsHdr, offset + 0x10),
    };
}

// Shared AES-ECB block-counter ("AesCtrEx") loop: for each 16-byte block, the
// constant counter head [0:8) is combined with the BE64 block index in [8:16),
// the counter block is AES-ECB-encrypted to a keystream, and the cipher text
// block is XORed with it. Both BKTR table and patch-region decryption are this
// exact loop — only the counter head construction differs. Output == cipher size.
function aesCtrExBlockLoop(aes, cipher, counterHead, offsetBase) {
    const size = cipher.length;
    const result = new Uint8Array(size);
    const counter = new Uint8Array(16);
    counter.set(counterHead, 0);

    for (let pos = 0; pos < size; pos += 16) {
        const chunkEnd = Math.min(pos + 16, size);
        let tmp = (offsetBase + pos) / 16;
        for (let j = 15; j >= 8; j--) {
            counter[j] = tmp & 0xFF;
            tmp >>= 8;
        }
        const keystream = aes.encryptBlock(counter);
        const rawBlock = cipher.subarray(pos, chunkEnd);
        for (let i = 0; i < chunkEnd - pos; i++) {
            result[pos + i] = rawBlock[i] ^ keystream[i];
        }
    }
    return result;
}

// Decrypt BKTR table ciphertext using AES-ECB with custom counter
// (AesCtr.seek gives wrong counter for BKTR tables, hence manual counter).
// cipher = the table region bytes; absOffset = their absolute NCA offset
// (used for the per-16-byte-block counter, exactly as hactool does).
export async function decryptBktrTableData(cipher, titlekey, nonce, absOffset) {
    return aesCtrExBlockLoop(new AesEcb(titlekey), cipher, nonce, absOffset);
}

// Parse relocation block per hactool bktr.h bktr_relocation_block_t
export function parseRelocationBlock(block) {
    const numBuckets = readLeU32(block, 4);
    const totalSize = readLeU64(block, 8);
    const entries = [];

    // Per hactool bktr.h: bucket_virtual_offsets[0x3FF0/sizeof(uint64_t)] = 1022 entries
    // Fixed size: 0x3FF0 bytes, so buckets start at 0x4000
    for (let b = 0; b < numBuckets; b++) {
        const bucketOff = 0x4000 + b * 0x4000;
        if (bucketOff + 0x10 > block.length) break;
        const nEntries = readLeU32(block, bucketOff + 4);
        let eStart = bucketOff + 0x10;
        for (let i = 0; i < nEntries; i++) {
            if (eStart + 0x14 > block.length) break;
            entries.push({
                virtOffset: readLeU64(block, eStart),
                physOffset: readLeU64(block, eStart + 8),
                isPatch: readLeU32(block, eStart + 0x10) !== 0,
            });
            eStart += 0x14;
        }
    }

    return { totalSize, entries };
}

// Parse subsection block per hactool bktr.h bktr_subsection_block_t
// bucket_physical_offsets[0x3FF0/sizeof(uint64_t)] = 1022 entries, fixed size 0x3FF0 bytes
// bktr_subsection_entry_t: offset(u64) + _0x8(u32) + ctr_val(u32) = 16 bytes with pragma pack(1)
export function parseSubsectionBlock(block) {
    const numBuckets = readLeU32(block, 4);
    const totalSize = readLeU64(block, 8);
    const entries = [];

    // Buckets start at 0x4000 (fixed, after bucket_physical_offsets array)
    for (let b = 0; b < numBuckets; b++) {
        const bucketOff = 0x4000 + b * 0x4000;
        if (bucketOff + 0x10 > block.length) break;
        const nEntries = readLeU32(block, bucketOff + 4);
        let eStart = bucketOff + 0x10;
        for (let i = 0; i < nEntries; i++) {
            if (eStart + 0x10 > block.length) break;
            entries.push({
                offset: readLeU64(block, eStart),
                ctrVal: readLeU32(block, eStart + 12),
            });
            eStart += 16;
        }
    }

    return { totalSize, entries };
}

export function findSubsectionEntry(entries, physOffset) {
    const idx = subEntryIdx(entries, physOffset);
    if (idx < 0) return null;
    return entries[idx];
}

export function subEntryIdx(entries, physOffset) {
    let lo = 0, hi = entries.length - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (entries[mid].offset > physOffset) hi = mid - 1;
        else lo = mid + 1;
    }
    if (hi < 0) return -1;
    const nextOff = hi + 1 < entries.length ? entries[hi + 1].offset : Infinity;
    if (physOffset < nextOff) return hi;
    return -1;
}

// Decrypt a patch region using AesCtrEx
// Counter (Stratosphere AesCtrCounterExtendedStorage::Read + MakeIv):
//   ctr[0:4] = FsHeader.secure_value BE (FsHeader[0x144:0x148], u32 LE → BE)
//   ctr[4:8] = subEntry.ctrVal BE (generation from BKTR entry, u32 LE → BE)
//   ctr[8:16] = fileOffset/16 BE
export async function decryptPatchRegionData(cipher, titlekey, secureValue, subEntry, fileOffset) {
    const counterHead = new Uint8Array(8);
    // ctr[0:4] = secure_value BE (constant for all blocks)
    counterHead[0] = (secureValue >> 24) & 0xFF;
    counterHead[1] = (secureValue >> 16) & 0xFF;
    counterHead[2] = (secureValue >> 8) & 0xFF;
    counterHead[3] = secureValue & 0xFF;
    // ctr[4:8] = ctrVal BE (constant for this subsection)
    counterHead[4] = (subEntry.ctrVal >> 24) & 0xFF;
    counterHead[5] = (subEntry.ctrVal >> 16) & 0xFF;
    counterHead[6] = (subEntry.ctrVal >> 8) & 0xFF;
    counterHead[7] = subEntry.ctrVal & 0xFF;

    return aesCtrExBlockLoop(new AesEcb(titlekey), cipher, counterHead, fileOffset);
}

// Load titlekeys from file (format: rights_id = titlekey)
// Returns Map<rights_id_string, Uint8Array>
export async function loadTitlekeysFile(path) {
    try {
        const { readFileSync } = await import('fs');
        const text = readFileSync(path, 'utf-8');
        const map = new Map();
        for (const line of text.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx === -1) continue;
            const rid = trimmed.substring(0, eqIdx).trim();
            const keyHex = trimmed.substring(eqIdx + 1).trim();
            if (rid.length === 32 && keyHex.length === 32) {
                const bytes = hexToBytes(keyHex);
                map.set(rid, bytes);
            }
        }
        return map;
    } catch {
        return null;
    }
}

// Lookup titlekey from titlekeys database by rights_id
export function lookupTitlekeyFromDatabase(rightsId, titlekeysMap) {
    if (!titlekeysMap || !rightsId) return null;
    // rightsId should be 32-char hex string
    const rid = rightsId.toLowerCase().replace(/\s/g, '');
    return titlekeysMap.get(rid) || null;
}
