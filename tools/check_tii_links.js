const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TII = path.join(ROOT, 'Tii');

function walk(dir, list=[]) {
  const files = fs.readdirSync(dir);
  for (const f of files) {
    const full = path.join(dir, f);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full, list);
    else list.push(full);
  }
  return list;
}

function isInternalHref(h) {
  if (!h) return false;
  h = h.trim();
  if (h.startsWith('http') || h.startsWith('mailto:') || h.startsWith('tel:') || h.startsWith('#') || h.startsWith('data:')) return false;
  return true;
}

function checkFiles() {
  if (!fs.existsSync(TII)) { console.error('Tii folder not found at', TII); process.exit(1); }
  const all = walk(TII).filter(f => f.endsWith('.html') || f.endsWith('.js'));
  const report = { files: {}, problems: [] };

  for (const file of all) {
    const rel = path.relative(ROOT, file);
    const txt = fs.readFileSync(file, 'utf8');
    const anchors = [];
    // find href="..." and src="..."
    const re = /(?:href|src)=\"([^\"]+)\"/g;
    let m;
    while ((m = re.exec(txt)) !== null) {
      anchors.push(m[1]);
    }
    report.files[rel] = anchors;

    for (const a of anchors) {
      if (!isInternalHref(a)) continue;
      // Normalize: convert relative to absolute if starts without / and not starting with Tii/
      if (a.startsWith('Tii/')) {
        // missing leading slash
        report.problems.push({ file: rel, href: a, issue: 'missing-leading-slash (use /Tii/)' });
        continue;
      }
      if (a.startsWith('/')) {
        // absolute path under site root; check if file exists inside repo for simple html paths
        const withoutQuery = a.split('?')[0];
        const p = path.join(ROOT, withoutQuery.replace(/^\//, ''));
        if (withoutQuery.endsWith('.html') && !fs.existsSync(p)) {
          report.problems.push({ file: rel, href: a, issue: 'absolute-target-missing' });
        }
        continue;
      }
      // relative path (doesn't start with /, http, #, mailto)
      // Recommend converting to /Tii/ if it points inside Tii
      if (a.startsWith('courses/') || a.startsWith('..') || a.indexOf('/') === 0 || a.match(/^[a-z0-9-]+\.html$/i)) {
        report.problems.push({ file: rel, href: a, issue: 'relative-link' });
      }
    }
  }
  return report;
}

function checkLogout() {
  const authJs = path.join(TII, 'auth.js');
  if (!fs.existsSync(authJs)) return { ok: false, reason: 'auth.js missing' };
  const txt = fs.readFileSync(authJs, 'utf8');
  const hasLogout = /export function logout\(\)\s*\{[\s\S]*window\.location\.href\s*=\s*['\"]\/?Tii\/[\w\-\.]+['\"]/m.test(txt);
  return { ok: hasLogout };
}

(function main(){
  const r = checkFiles();
  const lg = checkLogout();
  console.log('Scanned files under Tii. Summary:');
  console.log('Total files scanned:', Object.keys(r.files).length);
  console.log('Total anchors found:', Object.values(r.files).reduce((s,a)=>s+a.length,0));
  console.log('Problems found:', r.problems.length);
  if (r.problems.length) console.table(r.problems.slice(0,200));
  else console.log('No relative/incorrect anchors detected by the checker.');
  console.log('\nLogout check:', lg);
})();
