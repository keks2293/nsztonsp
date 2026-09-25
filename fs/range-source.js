// Range sources: serve NCA ciphertext byte ranges by absolute NCA offset.
//
//   read(offset, length) -> Promise<Uint8Array>
//   registerRange(offset, length)  -- optional pre-registration
//   stream(consume) -> Promise  -- lockstep pass, no buffers
//
// Backends:
//  - BufferRangeSource: over an already-buffered NCA (Uint8Array).
//  - FileRangeSource: random access over a container reader (.nsp input).
//  - ViewRangeSource: over a SparseNcaView (sparse header + sections).
//  - NczStreamSource: ONE sequential pass of NCZ decompression (.nsz input).
//
// This is the same streaming discipline the NSZ→NSP converter uses
// (decompress chunk-by-chunk, consume, never buffer the whole NCA).

import { NCZDecompressor } from './ncz.js';
import { NCA_HEADER_SIZE } from './nca-utils.js';

// Lazy zero-copy "sparse NCA" view. Serves subarray() over [header @0, sections at
// their original NCA offsets, zeros elsewhere] WITHOUT allocating an NCA-sized
// buffer (the old buildSparseNcaBuffer copied every section into a full-size
// zero-filled Uint8Array, doubling memory). A range fully inside the header or
// inside ONE section returns a zero-copy subview. A range that straddles a gap
// between sections/header is a USAGE ERROR (no current caller does it — reads
// are whole-section: BKTR tables + ExeFS stream + patch runs), so it throws
// instead of materializing a mixed buffer (which silently served wrong bytes:
// start-relative offsets read as section-relative).
export class SparseNcaView {
    constructor(header, sections) {
        this._header = header;
        this._sections = sections;
        let maxEnd = NCA_HEADER_SIZE;
        for (const s of sections) {
            maxEnd = Math.max(maxEnd, s.offset + s.data.length);
        }
        this.size = maxEnd;
    }
    get length() { return this.size; }
    subarray(start, end = this.size) {
        if (end <= start) return new Uint8Array(0);
        if (end <= NCA_HEADER_SIZE) {
            return this._header.subarray(start, end);
        }
        for (const s of this._sections) {
            if (start >= s.offset && end <= s.offset + s.data.length) {
                return s.data.subarray(start - s.offset, end - s.offset);
            }
        }
        throw new Error(`SparseNcaView: read [0x${start.toString(16)}, 0x${end.toString(16)}) is outside the header and any single section — whole-section/header ranges only`);
    }
}

// Unified random-access range source. All three backends share the same
// structure; the only difference is how data is fetched:
//   - subarray() for in-memory buffers/views
//   - reader.read() for container files
//
// read(offset, length) -> Promise<Uint8Array>
// registerRange()      -> no-op (used by NczStreamSource which is sequential)
//
// Exported factory constructors preserve the original API:
//   new BufferRangeSource(ncaData)
//   new FileRangeSource(containerReader, fileOffset, fileSize)
//   new ViewRangeSource(view)

class RangeSource {
    constructor(length, readFn) {
        this._length = length;
        this._read = readFn;
    }
    get length() { return this._length; }
    registerRange() {}
    async read(offset, length) {
        if (offset < 0 || offset + length > this._length) {
            throw new Error(`RangeSource: read [${offset}, ${offset + length}) out of bounds (len ${this._length})`);
        }
        return this._read(offset, length);
    }
}

export function BufferRangeSource(data) {
    return new RangeSource(data.length, (offset, length) => data.subarray(offset, offset + length));
}

export function FileRangeSource(reader, fileOffset, fileSize) {
    return new RangeSource(fileSize, (offset, length) => reader.read(fileOffset + offset, length));
}

export function ViewRangeSource(view) {
    return new RangeSource(view.length, (offset, length) => view.subarray(offset, offset + length));
}

const STOP_PUMP = 'STOP_PUMP';

// Sentinel for NczStreamSource.stream(): the consumer throws `new Error(STOP_STREAM)`
// to stop the pass early (mirrors the private STOP_PUMP in _pump). Exported so
// lockstep consumers can signal a clean stop.
export const STOP_STREAM = 'STOP_STREAM';

export class NczStreamSource {
    constructor(nczReader, parsed, log = () => {}, onProgress = null) {
        this._reader = nczReader;
        this._parsed = parsed;
        this._log = log;
        this._onProgress = typeof onProgress === 'function' ? onProgress : null;
        this._reached = 0; // far-most decompressed absolute offset (NW of each chunk)
        this._ranges = [];
        this._nextRange = 0;
        this._readCursor = 0; // candidate index for read(); advances forward only
        this._pumpStarted = false;
        this._pumpError = null;
    }
    get length() { return this._parsed.ncaSize; }

    registerRange(offset, length) {
        const last = this._ranges[this._ranges.length - 1];
        if (last && offset < last.end) {
            throw new Error('NczStreamSource: ranges must be strictly increasing (NCZ is sequential)');
        }
        this._ranges.push({
            start: offset, end: offset + length,
            data: new Uint8Array(length), filled: 0,
            ready: null, resolve: null, reject: null,
        });
        return this._ranges.length - 1;
    }

    async read(offset, length) {
        const end = offset + length;
        if (offset < 0 || end > this._parsed.ncaSize) {
            throw new Error(`NczStreamSource: read [${offset}, ${end}) out of bounds (ncaSize ${this._parsed.ncaSize})`);
        }
        // Find the registered range that CONTAINS [offset, end) (an exact match is
        // just the case where sub == null; a sub-range read returns a zero-copy view
        // of the buffered range data — lets the caller read a large registered range
        // in chunks). Ranges are pre-registered up front in strictly-increasing,
        // non-overlapping order, so at most one contains the read. Consumers that
        // read monotonically (each offset >= the previous — e.g. scatter's Pass U
        // walks patches in physical order) let a cursor advance forward: O(1)
        // amortized instead of a linear scan from 0 on every read (LN2's base has
        // ~2500 ranges). A backward/non-monotonic read (merge reads the base in
        // virtual order) falls back to one full scan — still correct, and one scan
        // instead of the old two (exact, then containing).
        const ranges = this._ranges;
        let idx = this._readCursor;
        while (idx < ranges.length && ranges[idx].end <= offset) idx++; // offset is past this range
        if (idx < ranges.length && ranges[idx].start <= offset && end <= ranges[idx].end) {
            this._readCursor = idx; // advance (never retreat) for the next read
        } else {
            // Cursor overshot (backward read) or the offset is in a gap: the
            // containing range, if any, is elsewhere — scan from 0. A read outside
            // every range is a usage error, not lazy-fill.
            idx = ranges.findIndex(r => r.start <= offset && end <= r.end);
            if (idx < 0) {
                throw new Error(`NczStreamSource: read [0x${offset.toString(16)}, 0x${end.toString(16)}) has no registered range — register ranges up front (NCZ is sequential)`);
            }
        }
        const r = ranges[idx];
        const sub = (offset === r.start && end === r.end) ? null : { off: offset - r.start, len: length };
        // Fast path: the pump (unthrottled, runs ahead of a slow consumer) may
        // have filled this range before any read of it. r.ready was never
        // created, so awaiting it would deadlock — return the buffered data.
        if (r.filled === r.data.length) {
            return sub ? r.data.subarray(sub.off, sub.off + sub.len) : r.data;
        }
        if (this._pumpError) {
            throw this._pumpError;
        }
        if (!this._pumpStarted) {
            this._pumpStarted = true;
            this._pump();
        }
        if (!r.ready) {
            r.ready = new Promise((resolve, reject) => { r.resolve = resolve; r.reject = reject; });
        }
        const data = await r.ready;
        return sub ? data.subarray(sub.off, sub.off + sub.len) : data;
    }

    // Shared one-pass decompression driver for both access modes: create the
    // decompressor, run one pass with the given chunk callback, and swallow the
    // early-stop sentinel(s) (STOP_PUMP for the fill pass, STOP_STREAM for the
    // lockstep pass) — anything else propagates. The chunk callback and the error
    // policy (fire-and-forget state for _pump, rethrow for stream) stay with the
    // caller; this owns only "one NCZ pass + stop-token handling".
    _runPass(writeChunk, stopTokens) {
        const decomp = new NCZDecompressor(this._reader);
        return decomp.decompress(() => {}, writeChunk, this._parsed).catch(e => {
            if (e && stopTokens.includes(e.message)) return; // normal early stop
            throw e;
        });
    }

    // Lockstep streaming mode: decompress the NCZ once and deliver each decrypted
    // chunk to `consume(chunk, ncaOffset)` in physical (NCA offset) order. No range
    // registration, no pre-allocated buffers — peak memory is one chunk plus whatever
    // the consumer holds. `consume` is awaited, so the pump paces to the consumer
    // (no fill-ahead). A consumer that throws `new Error(STOP_STREAM)` stops the pass
    // at the last wanted byte (e.g. after the last needed section — mirrors _pump's
    // STOP_PUMP). Use on a fresh source; it does not interact with registerRange.
    async stream(consume) {
        await this._runPass(async (chunk, offset) => {
            await consume(chunk, offset);
        }, [STOP_STREAM]);
    }

    _pump() {
        this._pumpPromise = this._runPass((chunk, offset) => {
            const cStart = offset, cEnd = offset + chunk.length;
            // Optional progress: report the far-most decompressed absolute offset,
            // including the discarded prefix BEFORE the first registered range
            // (for sequential NCZ sources that is the whole work of reaching a
            // table/run deep in the file — e.g. own-BKTR's reloc/sub tables).
            if (this._onProgress && cEnd > this._reached) {
                this._reached = cEnd;
                this._onProgress(cEnd);
            }
            while (this._nextRange < this._ranges.length) {
                const r = this._ranges[this._nextRange];
                if (cEnd <= r.start) {
                    break; // chunk precedes the range — discard
                }
                if (cStart > r.end) {
                    throw new Error('NczStreamSource: decompression skipped past a registered range');
                }
                const a = Math.max(cStart, r.start);
                const b = Math.min(cEnd, r.end);
                r.data.set(chunk.subarray(a - cStart, b - cStart), a - r.start);
                r.filled = b - r.start;
                if (r.filled === r.data.length) {
                    this._nextRange++;
                    if (r.resolve) r.resolve(r.data);
                    // chunk may cover the next range too — loop continues
                } else {
                    break; // range extends past this chunk — wait for more data
                }
            }
            if (this._nextRange >= this._ranges.length) {
                throw new Error(STOP_PUMP);
            }
        }, [STOP_PUMP]).catch(e => {
            this._pumpError = e;
            for (const r of this._ranges) {
                if (r.reject) r.reject(e);
            }
        }).finally(() => {
            for (const r of this._ranges) {
                if (r.filled < r.data.length && r.reject) {
                    r.reject(this._pumpError || new Error('NczStreamSource: NCA data ended before registered range'));
                }
            }
        });
    }
}
