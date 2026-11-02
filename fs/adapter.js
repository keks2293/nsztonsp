async function buildAdapter(output, read, callbacks) {
    const { log = () => {}, progress = () => {}, createHash } = callbacks;

    if (output.fd !== undefined) {
        const fs = await import('node:fs');
        return {
            read,
            write: (offset, data) => fs.writeSync(output.fd, data, 0, data.byteLength, offset),
            log, progress, createHash,
        };
    }
    if (output.writable) {
        const w = output.writable;
        // FSA (FileSystemWritableFileStream) supports {type,position,data}; SWDownloader uses (pos, data).
        // Detect FSA by its seek() method (SWDownloader doesn't have it).
        const write = typeof w.seek === 'function'
            ? (offset, data) => w.write({ type: 'write', position: offset, data })
            : (offset, data) => w.write(offset, data);
        return { read, write, log, progress, createHash };
    }
    if (output.memory) {
        const chunks = output._chunks || (output._chunks = []);
        // Keep _chunks sorted by offset AND disjoint. A seekable target may
        // legitimately rewrite a region — the NCZ block-size list is zeroed
        // first and patched back after the blocks are compressed, and the PFS0
        // header is written last at offset 0 — so an incoming write that
        // overlaps existing chunks trims/splits/drops them (last write wins).
        // Chunk buffers are referenced in place (Blob, read-back): no copies.
        const write = (offset, data) => {
            if (data.length === 0) return;
            const end = offset + data.length;
            const inserts = [];
            let i = 0;
            while (i < chunks.length) {
                const c = chunks[i];
                const cEnd = c.offset + c.data.length;
                if (cEnd <= offset || c.offset >= end) { i++; continue; }
                if (c.offset < offset) inserts.push({ offset: c.offset, data: c.data.subarray(0, offset - c.offset) });
                if (cEnd > end) inserts.push({ offset: end, data: c.data.subarray(end - c.offset) });
                chunks.splice(i, 1);
            }
            inserts.push({ offset, data });
            inserts.sort((a, b) => a.offset - b.offset);
            for (const ins of inserts) {
                let lo = 0, hi = chunks.length;
                while (lo < hi) {
                    const mid = (lo + hi) >> 1;
                    if (chunks[mid].offset < ins.offset) lo = mid + 1;
                    else hi = mid;
                }
                chunks.splice(lo, 0, ins);
            }
        };
        return {
            read,
            write,
            log, progress, createHash,
            _chunks: chunks,
        };
    }
    throw new Error('adapter: output must be { fd }, { writable }, or { memory: true }');
}

function collectBlob(adapter, totalSize) {
    // The memory output emulates a SPARSE FILE, exactly like fd/FSA: written
    // chunks keep their positions, and unwritten holes read as zeros. fd gets
    // that for free (POSIX: a positioned write extends the file and the
    // intervening bytes are zeros); FSA inherits the platform's POSIX-like
    // semantics. Producers therefore write data at logical offsets — plus the
    // FINAL EXTENT that sets the file length — and do NOT pad internal holes
    // with explicit zero writes (doing so for fd would defeat sparseness and
    // waste disk writes, the same way python nsz never writes its gaps).
    // _chunks is kept sorted by offset and disjoint at write time, so this can
    // reference chunk buffers in place (zero copy) and only ALLOCATES the
    // actual gaps (head/interior/tail) up to totalSize.
    const chunks = adapter._chunks;
    const parts = [];
    let pos = 0;
    for (const c of chunks) {
        if (c.offset > pos) parts.push(new Uint8Array(c.offset - pos));
        parts.push(c.data);
        pos = c.offset + c.data.length;
    }
    if (totalSize > pos) parts.push(new Uint8Array(totalSize - pos));
    return new Blob(parts, { type: 'application/octet-stream' });
}

// Build a seekable read(offset, length) for the output, or null if the output
// cannot be read back (e.g. sequential-only SW download). read() returns the
// requested range as an ORDERED LIST of zero-copy views (Uint8Array[]) covering
// [offset, offset+length) in file order — the consumer (the streaming contentId /
// IVFC hashers) feeds the views sequentially, which is all a streaming hash needs,
// so no flat buffer / memcpy is required. fd and FSA have no pre-existing chunk
// structure, so they return a single view over a freshly-read buffer; the memory
// output returns one in-place view per overlapping _chunks entry (the chunks stay
// alive until collectBlob). Used by the streaming update path to re-read the
// written Program NCA and compute its contentId (sha256) — mirroring hacpack's
// nca_calculate_hash reading the file.
async function buildRead(output) {
    if (output.fd !== undefined) {
        const fs = await import('node:fs');
        return (offset, length) => {
            const buf = Buffer.alloc(length);
            fs.readSync(output.fd, buf, 0, length, offset);
            return [new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)];
        };
    }
    // NOTE: the File System Access API's FileSystemWritableFileStream has seek()
    // but NO read() (MDN: only write/seek/truncate), so FSA outputs can't be read
    // back — they return null here and use the buffered path. Only a writable that
    // exposes BOTH seek() and read() is usable for the re-read contentId pass.
    if (output.writable && typeof output.writable.seek === 'function' && typeof output.writable.read === 'function') {
        return async (offset, length) => {
            await output.writable.seek(offset);
            const stream = await output.writable.read();
            const reader = stream.getReader();
            const out = new Uint8Array(length);
            let filled = 0;
            while (filled < length) {
                const { value, done } = await reader.read();
                if (done) break;
                const n = Math.min(value.length, length - filled);
                out.set(value.subarray(0, n), filled);
                filled += n;
            }
            reader.releaseLock();
            return [out.subarray(0, filled)];
        };
    }
    if (output.memory) {
        // Memory output buffers every write into output._chunks (kept sorted by
        // offset at write time, shared with buildAdapter). read() walks the sorted
        // chunks and returns the requested range as an ordered list of in-place
        // zero-copy views — one subarray per overlapping chunk (no temp alloc, no
        // memcpy; the chunk buffers stay alive in _chunks until collectBlob, and
        // the consumer hashes them sequentially). Simpler and copy-free for every
        // range, including ones that span multiple chunks (the scatter case, where
        // BKTR-sized chunks make a flat single-buffer read impossible to build
        // without a copy).
        return (offset, length) => {
            const chunks = output._chunks || [];
            const views = [];
            for (const c of chunks) {
                if (c.offset >= offset + length) break;
                if (c.offset + c.data.length <= offset) continue;
                const s = Math.max(c.offset, offset);
                const e = Math.min(c.offset + c.data.length, offset + length);
                views.push(c.data.subarray(s - c.offset, e - c.offset));
            }
            return views;
        };
    }
    return null;
}

const COPY_CHUNK = 8 * 1024 * 1024;

async function copyRange(reader, offset, size, write, onChunk) {
    for (let pos = 0; pos < size; pos += COPY_CHUNK) {
        const n = Math.min(COPY_CHUNK, size - pos);
        const data = await reader.read(offset + pos, n);
        await write(pos, data);
        if (onChunk) onChunk(n);
    }
}

export { buildAdapter, buildRead, collectBlob, copyRange };
