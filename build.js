import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'fs';
import { execSync } from 'child_process';

const ENTRY = 'main.js';
const OUT = 'app.mjs';
const ASSETS = ['favicon.svg', 'download-worker.js', 'sw.js'];

// Ad tag of the new platform (verbatim), injected into <head> when DEPLOY_URL
// matches a domain below. Old nap5k.com tags removed 2026-10-26.
const AD_TAG = `<script>
(function(qgx){
var d = document,
    s = d.createElement('script'),
    l = d.currentScript || d.scripts[d.scripts.length - 1];
s.settings = qgx || {};
s.src = "\/\/rude-movie.com\/c.DX9u6tbl2K5-lXS\/W\/QX9_N\/zgUD1RMjzVEWwZODSH0d3jN-TIUmzOMsTbEozc";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})
</script>`;

const AD_SITES = {
    'nsztonsp.netlify.app': AD_TAG,
    'nszjs.netlify.app': AD_TAG,
};

const DEPLOY_URL = process.env.DEPLOY_URL || process.env.URL || '';
const AD = Object.entries(AD_SITES).find(([d]) => DEPLOY_URL.includes(d))?.[1] || null;

// New ad platform ownership verification — inert meta, injected on EVERY build
// (unconditional: verification must not depend on DEPLOY_URL being set/matching).
const VERIFY_META = `<meta name="9a78969ad0697719fdf533e1b584eddaeef5db8a" content="9a78969ad0697719fdf533e1b584eddaeef5db8a" />`;

mkdirSync('out', { recursive: true });
execSync(`npx esbuild ${ENTRY} --bundle --minify --format=esm --outfile=out/${OUT} --external:node:fs --external:node:child_process --external:node:crypto --external:node:zlib --external:crypto`, { stdio: 'inherit' });

let html = readFileSync('index.html', 'utf8');
html = html.replace(`import('./${ENTRY}')`, `import('./${OUT}')`);
html = html.replace('<head>', `<head>\n    ${[VERIFY_META, AD].filter(Boolean).join('\n    ')}`);
if (AD) {
    console.log(`[build] Ad injected`);
}
writeFileSync('out/index.html', html);

for (const file of ASSETS) {
  copyFileSync(file, `out/${file}`);
}
mkdirSync('out/static', { recursive: true });
copyFileSync('static/prod.keys', 'out/static/prod.keys');
