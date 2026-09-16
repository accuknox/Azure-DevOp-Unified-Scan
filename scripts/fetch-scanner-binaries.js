#!/usr/bin/env node
/**
 * Download accuknox-aspm-scanner into src/bin/ so the VSIX can run without GitHub.
 *
 * Default: Windows exe + Linux ELF. Azure DevOps docs advise optimizing above 50MB;
 * both binaries together land around 40MB in the VSIX.
 * Override with SCANNER_PLATFORMS=win32 or SCANNER_PLATFORMS=linux.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

const VERSION = process.env.SCANNER_VERSION || 'v0.15.1';
const OUT_DIR = path.join(__dirname, '..', 'src', 'bin');
const BASE = `https://github.com/accuknox/aspm-scanner-cli/releases/download/${VERSION}`;

// dest is the filename setup() looks for; asset is the GitHub release name.
const ALL = {
  win32: { asset: 'accuknox-aspm-scanner.exe', dest: 'accuknox-aspm-scanner.exe' },
  linux: { asset: 'accuknox-aspm-scanner-linux-amd64', dest: 'accuknox-aspm-scanner' },
};

const platforms = (process.env.SCANNER_PLATFORMS || 'win32,linux')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

fs.mkdirSync(OUT_DIR, { recursive: true });

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    const request = (currentUrl, n) => {
      if (n > 10) {
        reject(new Error('Too many redirects'));
        return;
      }
      https
        .get(currentUrl, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            res.resume();
            request(new URL(res.headers.location, currentUrl).toString(), n + 1);
            return;
          }
          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`HTTP ${res.statusCode} for ${currentUrl}`));
            return;
          }
          res.pipe(file);
          file.on('finish', () => file.close(() => resolve()));
        })
        .on('error', (err) => {
          fs.unlink(dest, () => reject(err));
        });
    };
    request(url, 0);
  });
}

(async () => {
  for (const plat of platforms) {
    const spec = ALL[plat];
    if (!spec) {
      console.error(`Unknown platform '${plat}'. Use win32 and/or linux.`);
      process.exit(1);
    }
    const dest = path.join(OUT_DIR, spec.dest);
    const url = `${BASE}/${spec.asset}`;
    console.log(`Fetching ${url}`);
    await download(url, dest);
    fs.chmodSync(dest, 0o755);
    const mb = (fs.statSync(dest).size / 1024 / 1024).toFixed(1);
    console.log(`Wrote ${dest} (${mb} MB)`);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
