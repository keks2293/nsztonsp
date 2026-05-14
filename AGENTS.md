# Rules for AI Agents

## Read All MD Files on Start

**Always read all `*.md` files in the project root before starting work.** These contain critical context about the project:

- `AGENTS.md` — This file (rules, static files, workarounds)
- `NSZ-FORMAT-ANALYSIS.md` — NCZ/XCZ/NCA format specs, crypto types, Python nsz comparison, known bugs and fixes
- `PLAN.md` — Action plan, completed steps, success criteria
- `PROGRESS.md` — Working components, recent fixes, remaining issues
- `TESTS.md` — Test suite documentation, test vectors, how to run tests
- `FIXES_PLAN.md` — Planned fixes with file/line references

These docs contain format specifications, crypto implementation details, and known issues that are essential for correct development.

## Update PROGRESS.md After Changes

**Always update PROGRESS.md after making functional changes.** Add entries under the appropriate section:
- New features or fixes → add to "Recent Changes" with date and description
- When sections grow long, move older entries to a collapsed `<details>` block

PROGRESS.md is the single source of truth for what works and what doesn't.

## Static Files

**DO NOT manually edit files in the `static/` folder.**

The `static/` folder contains downloaded/copied dependencies for browser use:
- `static/zstddec.mjs` - Copied from `node_modules/zstddec/dist/zstddec-stream.modern.js` (ES Module, imports directly). WASM-based native zstd decoder. Used for streaming decompression in browser. Handles any window size.
- `static/prod.keys` - User-provided Nintendo Switch keys file
- `static/hash-wasm.mjs` - Copied from `node_modules/hash-wasm/dist/index.esm.min.js` (ES Module, imports directly). WASM-based hash functions (SHA-256, etc.). Used for near-native speed SHA-256 in browser. 211 kB (all algorithms included).

### How to update static files:

1. Update the npm packages:
   ```bash
   npm install zstddec@x.x.x
   npm install hash-wasm@x.x.x
   ```

2. Copy the files to `static/` **WITHOUT ANY MODIFICATIONS**:
   ```bash
   cp node_modules/zstddec/dist/zstddec-stream.modern.js static/zstddec.mjs
   cp node_modules/hash-wasm/dist/index.esm.min.js static/hash-wasm.mjs
   ```

3. **NO manual editing of static files** - If the original files don't work as-is:
   - Do workarounds in the **consuming code** (e.g., `crypto/zstd.js`), not in the static files
   - Document any workarounds in `AGENTS.md` under "Workarounds" section

### Workarounds

When original files from npm don't work directly in the target environment:

- **Problem**: `zstddec`'s `decodeStreaming()` is a synchronous generator — requires all input chunks to be available synchronously. Browser `File` API reads are async, forcing pre-reading the entire compressed stream into `compressedChunks[]` (~2.5 GB peak for large NSZ).
  **Solution**: Monkey-patch `ZSTDDecoder.prototype._init` in `crypto/zstddec-stream.js` to capture the WASM `instance` object. Then implement an async generator that reads one chunk at a time from the `File` and feeds it directly to `ZSTD_decompressStream`. Peak compressed memory drops from file-size to one 16 MB chunk.
  
  Update when upgrading `zstddec`: the monkey-patch may break if `_init` signature changes. Verify by running the browser test page.

- **Problem**: `DecompressionStream` API doesn't support `'zstd'` format in any browser — constructor throws `"Failed to construct 'DecompressionStream': Unsupported compression format: 'zstd'"`.
  **Solution**: Use `zstddec` (WASM-based native zstd) for all decompression in browser via `static/zstddec.mjs`. Imported in `crypto/zstd.js` and `fs/ncz.js`.

- **Problem**: `zstddec` streaming ESM build has a bug in `decode()` when passing explicit `uncompressedSize` — produces truncated/all-zeros output for large streams (>1GB).
  **Solution**: In `ncz.js` (around line 310), call `decoder.decode(compressedData, 0)` (auto-detect size). This works correctly: calls `ZSTD_findDecompressedSize` internally, falls back to streaming API if size is unknown.

### Browser Usage

Browser HTML files load dependencies:
```html
<!-- zstddec.mjs is imported via ES module in crypto/zstd.js and fs/ncz.js -->
```

`zstddec.mjs` is imported directly as ES module (WASM binary is base64-embedded in the JS).

**DO NOT use import maps or CDN URLs** - the whole point of the `static/` folder is to enable offline use.

## Package Versions

Current versions (update this when upgrading):
- `zstddec`: 0.2.0 (use streaming ESM version: `zstddec/dist/zstddec-stream.modern.js`)
- `hash-wasm`: 4.12.0


