const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TII = path.join(ROOT, 'Tii');

const replacements = [
  'index.html','curriculum.html','lessons.html','portal.html','feedback.html','login.html','register.html','admin-login.html','admin-portal.html','profile.html','upload-course.html','delete-course.html','upload-lesson.html','delete-lesson.html','other-courses.html','otp-verification.html','assignments.html','course-update.html','course-schedule.html','student-foroum.html','ad-upload.html','ad-delete.html','admin-profile.html','user.html'
];

function walk(dir, list=[]) {
  const files = fs.readdirSync(dir);
  for (const f of files) {
    const full = path.join(dir, f);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full, list);
    else if (full.endsWith('.html')) list.push(full);
  }
  return list;
}

function fixFile(file) {
  let txt = fs.readFileSync(file, 'utf8');
  let changed = false;
  for (const r of replacements) {
    // replace href="r" and href='r'
    const re1 = new RegExp(`href=\\"${r}\\"`, 'g');
    const re2 = new RegExp(`href=\\'${r}\\'`, 'g');
    const repl1 = `href=\"/Tii/${r}\"`;
    const repl2 = `href=\'/Tii/${r}\'`;
    if (re1.test(txt)) { txt = txt.replace(re1, repl1); changed = true; }
    if (re2.test(txt)) { txt = txt.replace(re2, repl2); changed = true; }
    // also fix plain references inside JS strings like "portal.html"
    const jsre = new RegExp(`(['\"])${r}(['\"])`, 'g');
    txt = txt.replace(jsre, (m, a, b) => {
      // Avoid changing imports like './auth.js' because r ends with .html
      if (a === "'") return `'/${path.posix.join('Tii',r)}'`;
      return `"/${path.posix.join('Tii',r)}"`;
    });
  }
  if (changed) fs.writeFileSync(file, txt, 'utf8');
  return changed;
}

(function main(){
  if (!fs.existsSync(TII)) { console.error('Tii folder not found at', TII); process.exit(1); }
  const files = walk(TII);
  let total = 0;
  for (const f of files) {
    const ch = fixFile(f);
    if (ch) total++;
  }
  console.log('Fixed', total, 'files.');
})();
