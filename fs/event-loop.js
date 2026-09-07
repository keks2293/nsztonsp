import { isNode } from '../crypto/platform.js';

// Event-loop yield (a real macrotask → browser paint boundary), faster than
// setTimeout(0)'s 1 ms minimum delay: a port message is queued as a task with
// no minimum. Long synchronous JS stretches (the BKTR merge, the hash
// precompute) have microtask-only boundaries, so without these yields the
// browser cannot repaint the progress bar mid-work and the bar appears to
// jump (e.g. 43% → 100% across the whole hash phase).
//
// Node: a used MessagePort is a ref'd handle that unref() cannot release
// (attaching onmessage re-refs it), so the process would hang after the
// script's work is done — setImmediate is the same speed there and holds
// no ref.
const YIELD_CHANNEL = isNode ? null : new MessageChannel();
export function yieldToEventLoop() {
    if (!YIELD_CHANNEL) return new Promise(resolve => setImmediate(resolve));
    return new Promise(resolve => {
        YIELD_CHANNEL.port1.onmessage = resolve;
        YIELD_CHANNEL.port2.postMessage(null);
    });
}
