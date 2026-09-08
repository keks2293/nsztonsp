// OPFS staging worker. Holds a FileSystemSyncAccessHandle (worker-only API) for
// the output of an update() so it can be written at arbitrary offsets AND read
// back — unlocking the single-decompression streaming path in fs/update.js
// ("Streaming update (seekable output)"). Distinct from download-worker.js /
// sw.js which are the SERVICE worker serving the final download stream.
//
// Protocol (JSON + optional transfer):
//   open {name}     -> {ok}                 (creates+truncates OPFS file)
//   write {pos,data}-> {ok}                 (data.buffer transferred in)
//   read  {pos,len} -> {ok,data}            (data.buffer transferred out)
//   getSize         -> {ok,size}
//   flush           -> {ok}
//   close           -> {ok}                 (flush + close handle)
//   unlink          -> {ok}                 (flush + close + remove file)
// Every request carries {id}; replies echo it. Any failure replies {id,error}.

let dir = null;
let fileName = '';
let fileHandle = null;
let ac = null;

self.onmessage = async (e) => {
    const { id, cmd, pos, data, len, name } = e.data;
    const reply = (msg = {}, transfer) => self.postMessage({ id, ...msg }, transfer || []);
    try {
        switch (cmd) {
            case 'open': {
                dir = await navigator.storage.getDirectory();
                fileName = name;
                fileHandle = await dir.getFileHandle(name, { create: true });
                if (ac) { ac.close(); ac = null; }
                ac = await fileHandle.createSyncAccessHandle();
                ac.truncate(0);
                reply({ ok: true });
                break;
            }
            case 'write': {
                const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
                ac.write(bytes, { at: pos });
                reply({ ok: true });
                break;
            }
            case 'read': {
                const buf = new Uint8Array(len);
                ac.read(buf, { at: pos });
                reply({ ok: true, data: buf.buffer }, [buf.buffer]);
                break;
            }
            case 'getSize':
                reply({ ok: true, size: ac.getSize() });
                break;
            case 'flush':
                ac.flush();
                reply({ ok: true });
                break;
            case 'close':
            case 'unlink':
                if (ac) { ac.flush(); ac.close(); ac = null; }
                if (cmd === 'unlink') {
                    try { await dir.removeEntry(fileName); } catch (_) {}
                }
                reply({ ok: true });
                break;
            default:
                reply({ error: 'unknown cmd: ' + cmd });
        }
    } catch (err) {
        reply({ error: String((err && err.message) || err) });
    }
};