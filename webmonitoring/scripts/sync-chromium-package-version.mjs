import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const chromiumDir = path.join(repoRoot, 'chromium');
const manifestPath = path.join(chromiumDir, 'manifest.json');
const packagePath = path.join(chromiumDir, 'package.json');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

if (typeof manifest.version !== 'string' || manifest.version.length === 0) {
  throw new Error(`Invalid manifest version in ${manifestPath}`);
}

const oldVersion = pkg.version;
pkg.version = manifest.version;

if (oldVersion !== pkg.version) {
  fs.writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
  console.log(`Updated chromium/package.json version: ${oldVersion ?? '<none>'} -> ${pkg.version}`);
} else {
  console.log(`chromium/package.json version already up to date: ${pkg.version}`);
}
