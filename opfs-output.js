// OPFS-staged, read-back-capable output for the update pipeline. All writes and
// reads are forwarded to opfs-worker.js, which holds a FileSystemSyncAccessHandle
// (worker-only: synchronous read+write at arbitrary offsets). Exposing both a
// write() and a readAt() makes buildRead() return a reader, so update() takes the
// streaming single-decompression path even when the final destination is an
// append-only SW download stream or a directory picked via the File System Access
// API (whose FileSystemWritableFileStream supports seek() but never read()).
//
// Delivery is a separate, explicit step: copy the staged file to the chosen
// destination (SWDownloader stream or a directory) then unlink() the staging file.

export class OpfsOutput {
    #worker = null;
    #seq = 0;
    #pending = new Map();
    #name = '';
    #maxPos = 0;
    #closed = false;

    // Open the staging file eagerly so createSyncAccessHandle() runs during the
    // UI pause before conversion (not mid-stream).
    static async create(name, workerUrl) {
        const out = new OpfsOutput(name, workerUrl);
        await out.#post('open', { name });
        return out;
    }

    constructor(name, workerUrl = new URL('./opfs-worker.js', import.meta.url).href) {
        this.#name = name;
        this.#worker = new Worker(workerUrl, { type: 'module' });
        this.#worker.onmessage = (e) => this.#onMsg(e.data);
        this.#worker.onerror = (e) => this.#failAll(new Error('opfs worker error: ' + (e.message || '')));
    }

    // Present so buildAdapter dispatches the FSA write signature and appendOnly
    // stays false (seekable output).
    async seek() {}

    async write(...args) {
        const { position, data } = args[0] && args[0].type === 'write'
            ? args[0]
            : { position: args[0], data: args[1] };
        const view = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        const len = view.byteLength;
        this.#maxPos = Math.max(this.#maxPos, position + len);
        if (len === 0) return;
        // Fully-owned buffers (BKTR decrypt outputs, built headers, hash levels)
        // are transferred as-is — zero-copy, and safe: the pipeline hashes the
        // chunk BEFORE write() and never touches it again. Subarray views get
        // slice(0) first — their parent may be a pooled/reused source buffer and
        // is, by construction, not constructed for this call.
        const buffer = view.byteLength === view.buffer.byteLength ? view.buffer : view.slice(0).buffer;
        await this.#post('write', { pos: position, data: buffer }, [buffer]);
    }

    // buildRead() readAt contract: (offset, length) => Promise<Uint8Array>.
    async readAt(offset, length) {
        const res = await this.#post('read', { pos: offset, len: length });
        return new Uint8Array(res.data);
    }

    async getSize() {
        const res = await this.#post('getSize');
        return res.size;
    }

    async flush() {
        await this.#post('flush');
    }

    get bytesWritten() { return this.#maxPos; }

    async close() {
        this.#teardown('close');
    }

    async unlink() {
        this.#teardown('unlink');
    }

    #teardown(cmd) {
        if (this.#closed) return;
        this.#closed = true;
        this.#post(cmd).catch(() => {});
        this.#dispose();
        return Promise.resolve();
    }

    #dispose() {
        if (this.#worker) { this.#worker.terminate(); this.#worker = null; }
        this.#failAll(new Error('opfs output closed'));
    }

    #onMsg(msg) {
        const p = this.#pending.get(msg.id);
        if (!p) return;
        this.#pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error));
        else p.resolve(msg);
    }

    #failAll(err) {
        for (const [, p] of this.#pending) p.reject(err);
        this.#pending.clear();
    }

    #post(cmd, payload = {}, transfer) {
        if (this.#closed) return Promise.reject(new Error('opfs output closed'));
        const id = ++this.#seq;
        return new Promise((resolve, reject) => {
            this.#pending.set(id, { resolve, reject });
            if (this.#worker) this.#worker.postMessage({ id, cmd, ...payload }, transfer || []);
            else reject(new Error('opfs output closed'));
        });
    }
}