// server.js - Production-ready Node.js backend for Render
// Uses Firebase Realtime Database (free tier) and Nodemailer for OTP delivery

const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

const fs = require('fs');
const COURSES_DIR = path.join(__dirname, 'Tii', 'courses');
// Ensure courses directory exists
try { fs.mkdirSync(COURSES_DIR, { recursive: true }); } catch (e) { console.warn('Could not create courses directory', e); }

// Uploads directory for lesson images. Multer is optional — some hosts or environments may not allow installing new npm packages.
const LESSON_UPLOAD_DIR = path.join(__dirname, 'Tii', 'uploads', 'lessons');
try { fs.mkdirSync(LESSON_UPLOAD_DIR, { recursive: true }); } catch (e) { console.warn('Could not create lesson uploads directory', e); }

// Try to load multer; if it's not available, we'll offer a base64 upload fallback so the server still runs.
let upload = null;
let hasMulter = false;
try {
  const multer = require('multer');
  const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, LESSON_UPLOAD_DIR); },
    filename: function (req, file, cb) { cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + path.extname(file.originalname || '')); }
  });
  upload = multer({ storage: storage, limits: { fileSize: 5 * 1024 * 1024 } });
  hasMulter = true;
  console.log('[INFO] multer available — multipart uploads enabled');
} catch (e) {
  console.warn('[WARN] multer is not installed. Falling back to base64 image uploads at /api/uploads/lessons/base64');
}

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve frontend static files from the Tii/ directory
// This makes files available at /Tii/<filename>
app.use('/Tii', express.static(path.join(__dirname, 'Tii')));

// ============================================
// FIREBASE REALTIME DB SETUP (use admin SDK or REST)
// For free tier: use Firebase REST API or install firebase-admin
// ============================================
const admin = require('firebase-admin');

let db;
try {
  if (!admin.apps.length) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL,
    });
  }
  db = admin.database();
  console.log('Γ£à Firebase connected');
} catch (err) {
  console.warn('ΓÜá∩╕Å Firebase not configured. Falling back to file-backed persistent DB. For production, set FIREBASE_SERVICE_ACCOUNT and FIREBASE_DATABASE_URL.');

  // File-backed persistent store for environments without Firebase.
  // Data is stored as a mapping of path -> value in `persistent-db.json` at project root.
  const fs = require('fs');
  const PERSIST_PATH = path.join(__dirname, 'persistent-db.json');

  // Load existing store or initialize empty
  let fileStore = {};
  try {
    if (fs.existsSync(PERSIST_PATH)) {
      const raw = fs.readFileSync(PERSIST_PATH, 'utf8');
      fileStore = raw ? JSON.parse(raw) : {};
    } else {
      // ensure file exists
      fs.writeFileSync(PERSIST_PATH, JSON.stringify({}, null, 2), 'utf8');
      fileStore = {};
    }
  } catch (e) {
    console.warn('Could not read or create persistent DB file, falling back to in-memory store.', e);
    fileStore = {};
  }

  // Helper to persist the in-memory fileStore to disk (atomic replacement)
  function persist() {
    try {
      fs.writeFileSync(PERSIST_PATH, JSON.stringify(fileStore, null, 2), 'utf8');
    } catch (e) {
      console.error('Failed to persist DB to disk:', e);
    }
  }

  // Helpers to work with nested paths like 'courses/chemistry/lessons'
  function pathParts(p) {
    if (!p) return [];
    return p.split('/').filter(Boolean);
  }

  function getAtPath(p) {
    const parts = pathParts(p);
    if (parts.length === 0) return fileStore;
    let node = fileStore;
    for (let i = 0; i < parts.length; i++) {
      if (node === undefined || node === null) return undefined;
      node = node[parts[i]];
    }
    return node;
  }

  function setAtPath(p, value) {
    const parts = pathParts(p);
    if (parts.length === 0) {
      fileStore = value || {};
      return;
    }
    let node = fileStore;
    for (let i = 0; i < parts.length - 1; i++) {
      const k = parts[i];
      if (typeof node[k] !== 'object' || node[k] === null) node[k] = {};
      node = node[k];
    }
    node[parts[parts.length - 1]] = value;
  }

  function updateAtPath(p, updates) {
    const existing = getAtPath(p);
    if (existing && typeof existing === 'object') {
      setAtPath(p, { ...existing, ...(updates || {}) });
    } else {
      setAtPath(p, { ...(updates || {}) });
    }
  }

  async function pushAtPath(p, data) {
    const parts = pathParts(p);
    let node = fileStore;
    for (let i = 0; i < parts.length; i++) {
      const k = parts[i];
      if (i === parts.length - 1) {
        if (typeof node[k] !== 'object' || node[k] === null) node[k] = {};
        const key = `k_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
        node[k][key] = data || null;
        return key;
      }
      if (typeof node[k] !== 'object' || node[k] === null) node[k] = {};
      node = node[k];
    }
    // If p is empty, push at root
    const key = `k_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
    fileStore[key] = data || null;
    return key;
  }

  db = {
    ref: (p) => ({
      set: async (data) => {
        setAtPath(p, data);
        persist();
        console.log(`Γ£à Persistent DB set: ${p}`);
        return { key: p };
      },
      get: async () => {
        const data = getAtPath(p);
        return {
          val: () => (data === undefined ? null : data),
          exists: () => data !== undefined && data !== null,
        };
      },
      on: (event, callback) => {
        // No real-time listeners for file store; noop
      },
      update: async (updates) => {
        updateAtPath(p, updates);
        persist();
      },
      push: async (data) => {
        const key = await pushAtPath(p, data);
        persist();
        return { key };
      },
    }),
  };
}

// ============================================
// EMAIL SETUP (using mock console logs)
// ============================================
// Note: Email sending is disabled for security.
// Admin tokens and OTP codes are displayed in server logs only.

// ============================================
// UTILITIES
// ============================================
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  const secret = 'temp-secret-' + Math.random().toString(36).substr(2, 9);
  console.warn('[SECURITY] JWT_SECRET not set in environment. Using temporary key. Set JWT_SECRET in .env or environment variables!');
  console.warn('[DEBUG] Generated temp JWT_SECRET:', secret.substring(0, 10) + '...');
  return secret;
})();

console.log('[INFO] JWT_SECRET loaded:', JWT_SECRET.substring(0, 10) + '...');
console.log('[INFO] NODE_ENV:', process.env.NODE_ENV || 'not set');
console.log('[INFO] Port:', PORT);

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to safely check if snapshot exists
function snapshotExists(snapshot) {
  if (!snapshot) return false;
  if (typeof snapshot.exists === 'function') return snapshot.exists();
  if (typeof snapshot.exists === 'boolean') return snapshot.exists;
  return snapshot.val() !== null && snapshot.val() !== undefined;
}

// Helper to safely get snapshot value
function snapshotVal(snapshot) {
  if (!snapshot) return null;
  if (typeof snapshot.val === 'function') return snapshot.val();
  return snapshot;
}

async function sendOTPEmail(email, otp) {
  // Email sending disabled for security. OTP displayed in logs only.
  console.log(`[EMAIL MOCK] OTP for ${email}: ${otp}`);
}

// ============================================
// HEALTH CHECK (required for Render)
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// DEBUG ENDPOINT: GET OTP (for testing only - REMOVE IN PRODUCTION)
// ============================================
app.get('/api/debug/otp/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    
    if (!snapshot.exists()) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = snapshot.val();
    res.json({
      email,
      otp: user.otp,
      otp_expiry: new Date(user.otp_expiry),
      message: 'Debug only - remove this endpoint in production',
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// REGISTRATION ENDPOINT
// ============================================
app.post('/register', async (req, res) => {
  try {
    const { full_name, email, password, phone_number, date_of_birth, country, bio, security_question, security_answer } = req.body;

    // Identify which required fields are missing and return them for better UX
    const requiredFields = ['full_name', 'email', 'password', 'security_question', 'security_answer'];
    const missing = requiredFields.filter(f => !req.body[f] || req.body[f].toString().trim() === '');
    if (missing.length) {
      console.warn('Registration attempted with missing fields:', missing);
      return res.status(400).json({ message: 'Missing required fields.', missing_fields: missing });
    }

    // Check if user exists
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (snapshotExists(snapshot)) {
      return res.status(400).json({ message: 'Email already registered.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user in Firebase (verified immediately)
    await db.ref(`users/${email.replace(/\./g, '_')}`).set({
      full_name,
      email,
      password: hashedPassword,
      phone_number: phone_number || '',
      date_of_birth: date_of_birth || '',
      country: country || '',
      bio: bio || '',
      security_question,
      security_answer: security_answer.toLowerCase().trim(),
      role: 'student',
      verified: true,
      // initialize tokens container so frontend can read it reliably
      tokens: {},
      created_at: new Date().toISOString(),
    });

    // Generate JWT token
    const token = jwt.sign(
      { email, role: 'student' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Registration successful.',
      authToken: token,
      full_name,
      role: 'student',
      email,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

// ============================================
// LOGIN ENDPOINT
// ============================================
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required.' });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = snapshotVal(snapshot);

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      status: 'success',
      authToken: token,
      full_name: user.full_name,
      role: user.role,
      email: user.email,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// ============================================
// ADMIN LOGIN STEP 1: CREDENTIAL CHECK
// ============================================
app.post('/admin_login_check', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required.' });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const user = snapshotVal(snapshot);

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // If already admin
    if (user.role === 'admin') {
      const token = jwt.sign(
        { email, role: 'admin' },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        action: 'login_success',
        authToken: token,
        full_name: user.full_name,
        role: 'admin',
        email: user.email,
      });
    }

    // If student, require admin token
    res.status(403).json({
      message: 'Admin token required.',
      action: 'require_token',
    });
  } catch (error) {
    console.error('Admin login check error:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// SEND ADMIN TOKEN
// ============================================
app.post('/send_admin_token', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email required.' });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = snapshotVal(snapshot);

    // Count active tokens across all users (limit pool to 5 active tokens)
    const allUsersSnap = await db.ref('users').get();
    const allUsers = snapshotVal(allUsersSnap) || {};
    let activeCount = 0;
    Object.keys(allUsers).forEach(k => {
      const u = allUsers[k];
      if (u && u.admin_token && u.admin_token_expiry && Date.now() <= u.admin_token_expiry) {
        activeCount += 1;
      }
    });

    // If this user already has an active token, return it instead of creating a new one
    if (user.admin_token && user.admin_token_expiry && Date.now() <= user.admin_token_expiry) {
      return res.json({
        message: 'User already has an active admin token.',
        token: user.admin_token,
        expires_at: new Date(user.admin_token_expiry).toISOString(),
      });
    }

    // Enforce global active token limit (max 5)
    if (activeCount >= 5) {
      return res.status(429).json({ message: 'Maximum number of active admin tokens reached. Please wait until a token is used or expires.' });
    }

    // Generate admin token
    const adminToken = generateOTP(); // Simple 6-digit token
    const tokenExpiry = Date.now() + OTP_EXPIRY;

    // Store admin token on user
    await db.ref(`users/${email.replace(/\./g, '_')}`).update({
      admin_token: adminToken,
      admin_token_expiry: tokenExpiry,
      admin_token_requested_at: Date.now(),
    });

    // Also persist the token under the user's tokens list so tokens can be listed per email
    try {
      const pushRef = await db.ref(`users/${email.replace(/\./g, '_')}/tokens`).push({
        token: adminToken,
        expires_at: tokenExpiry,
        created_at: Date.now(),
        status: 'active',
      });
      // If push returned a reference, store its key for future updates (best-effort)
      const tokenKey = (pushRef && pushRef.key) ? pushRef.key : null;
      if (tokenKey) {
        await db.ref(`users/${email.replace(/\./g, '_')}/tokens/${tokenKey}`).update({ id: tokenKey });
      }
    } catch (e) {
      console.warn('Failed to persist admin token under user tokens:', e && e.message ? e.message : e);
    }

    // Log token generation
    console.log("============================================================");
    console.log("≡ƒöÉ ADMIN TOKEN GENERATED");
    console.log("============================================================");
    console.log(`≡ƒôº User Email: ${email}`);
    console.log(`≡ƒöæ Admin Token: ${adminToken}`);
    console.log(`ΓÅ░ Token Expiry: ${new Date(tokenExpiry).toISOString()}`);
    console.log(`ΓÅ│ Valid for: 3 minutes`);
    console.log("============================================================");

    // Admin token displayed in server logs only (email sending disabled for security)
    console.log(`[EMAIL MOCK] Admin token for ${email}: ${adminToken}`);

    // Broadcast update to SSE clients so admin dashboards refresh instantly
    broadcastTokenUpdate().catch(() => {});

    res.json({ 
      message: 'Admin token sent to admin email.',
      token: adminToken,
      expires_at: new Date(tokenExpiry).toISOString()
    });
  } catch (error) {
    console.error('Send admin token error:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// ADMIN LOGIN STEP 2: TOKEN VERIFICATION
// ============================================
app.post('/admin_login', async (req, res) => {
  try {
    const { email, password, token } = req.body;

    if (!email || !password || !token) {
      return res.status(400).json({ message: 'Email, password, and token required.' });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(401).json({ message: 'User not found.' });
    }

    const user = snapshotVal(snapshot);

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password.' });
    }

    // Check admin token expiry and match
    if (Date.now() > user.admin_token_expiry) {
      return res.status(400).json({ message: 'Admin token expired.' });
    }

    if (user.admin_token !== token) {
      return res.status(400).json({ message: 'Invalid admin token.' });
    }

    // Upgrade user to admin
    // Mark token record as used (if present) and then upgrade user to admin
    try {
      const tokensSnap = await db.ref(`users/${email.replace(/\./g, '_')}/tokens`).get();
      const tokens = snapshotVal(tokensSnap) || {};
      Object.keys(tokens).forEach(async (tk) => {
        const t = tokens[tk];
        if (t && t.token === token && t.status === 'active') {
          await db.ref(`users/${email.replace(/\./g, '_')}/tokens/${tk}`).update({ status: 'used', used_at: Date.now() });
        }
      });
    } catch (e) {
      console.warn('Failed to mark token as used in tokens list:', e && e.message ? e.message : e);
    }

    await db.ref(`users/${email.replace(/\./g, '_')}`).update({
      role: 'admin',
      admin_token: null,
      admin_token_expiry: null,
    });

    // Broadcast update to SSE clients so admin dashboards refresh instantly
    broadcastTokenUpdate().catch(() => {});

    // Generate JWT token
    const jwtToken = jwt.sign(
      { email, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Admin access granted.',
      authToken: jwtToken,
      full_name: user.full_name,
      role: 'admin',
      email: user.email,
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// CHECK ADMIN TOKEN STATUS (for admin dashboard)
// ============================================
app.post('/api/admin-token-status', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email required.' });
    }

    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = snapshotVal(snapshot);
    
    // Only show token if it exists and is not expired
    if (user.admin_token && Date.now() <= user.admin_token_expiry) {
      const timeRemaining = Math.ceil((user.admin_token_expiry - Date.now()) / 1000);
      return res.json({
        has_token: true,
        token: user.admin_token,
        expires_in_seconds: timeRemaining,
        expires_at: new Date(user.admin_token_expiry).toISOString(),
      });
    } else {
      return res.json({
        has_token: false,
        message: 'No active token. Request a new one.',
      });
    }
  } catch (error) {
    console.error('Token status check error:', error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// LIST ALL PENDING ADMIN TOKENS (admin only)
// ============================================
app.get('/api/admin-tokens', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header required.' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Bearer token required.' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (verifyErr) {
      return res.status(401).json({ message: 'Invalid or expired token.' });
    }

    // Only admins can view all pending tokens
    if (payload.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required.' });
    }

    // Get all users and find those with pending tokens
    const snapshot = await db.ref('users').get();
    const users = snapshotVal(snapshot) || {};
    const pendingTokens = [];

    Object.keys(users).forEach(userKey => {
      const user = users[userKey];
      if (user.admin_token && Date.now() <= user.admin_token_expiry) {
        const timeRemaining = Math.ceil((user.admin_token_expiry - Date.now()) / 1000);
        pendingTokens.push({
          email: user.email,
          token: user.admin_token,
          expires_in_seconds: timeRemaining,
          requested_at: user.admin_token_requested_at || 'N/A',
        });
      }
    });

    return res.json({ 
      pending_tokens: pendingTokens,
      count: pendingTokens.length
    });
  } catch (error) {
    console.error('List tokens error:', error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// REVOKE/EXPIRE A TOKEN (admin only)
// Body: { email, token }
// Marks the token status as 'revoked' and clears user's active admin_token if matching
// ============================================
app.post('/api/admin-tokens/revoke', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header required.' });
    const bearer = authHeader.split(' ')[1];
    if (!bearer) return res.status(401).json({ message: 'Bearer token required.' });

    let payload;
    try { payload = jwt.verify(bearer, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid or expired token.' }); }
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Admin access required.' });

    const { email, token } = req.body;
    if (!email || !token) return res.status(400).json({ message: 'Email and token required.' });

    const userKey = email.replace(/\./g, '_');
    const tokensSnap = await db.ref(`users/${userKey}/tokens`).get();
    const tokens = snapshotVal(tokensSnap) || {};
    let found = false;
    await Promise.all(Object.keys(tokens).map(async (tk) => {
      const t = tokens[tk];
      if (t && t.token === token && t.status === 'active') {
        found = true;
        await db.ref(`users/${userKey}/tokens/${tk}`).update({ status: 'revoked', revoked_at: Date.now() });
      }
    }));

    // Clear user's top-level admin_token if it matches
    const userSnap = await db.ref(`users/${userKey}`).get();
    const user = snapshotVal(userSnap);
    if (user && user.admin_token === token) {
      await db.ref(`users/${userKey}`).update({ admin_token: null, admin_token_expiry: null });
    }

    if (!found) return res.status(404).json({ message: 'Active token not found for that user.' });

    // Broadcast update
    broadcastTokenUpdate().catch(() => {});

    return res.json({ message: 'Token revoked.' });
  } catch (error) {
    console.error('Revoke token error:', error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// ADMIN TOKENS SSE STREAM (server-sent events)
// Publishes real-time changes to connected admin clients
// ============================================
const sseClients = new Set();

async function getPendingTokensSnapshot() {
  const snapshot = await db.ref('users').get();
  const users = snapshotVal(snapshot) || {};
  const pendingTokens = [];
  Object.keys(users).forEach(userKey => {
    const user = users[userKey];
    if (user && user.admin_token && user.admin_token_expiry && Date.now() <= user.admin_token_expiry) {
      const timeRemaining = Math.ceil((user.admin_token_expiry - Date.now()) / 1000);
      pendingTokens.push({
        email: user.email,
        token: user.admin_token,
        expires_in_seconds: timeRemaining,
        expires_at: new Date(user.admin_token_expiry).toISOString(),
        requested_at: user.admin_token_requested_at || null,
      });
    }
  });
  return pendingTokens;
}

async function broadcastTokenUpdate() {
  try {
    const data = { pending_tokens: await getPendingTokensSnapshot() };
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    sseClients.forEach(res => {
      try {
        res.write(payload);
      } catch (e) {
        // ignore write errors; client will be cleaned up on close
      }
    });
  } catch (e) {
    console.warn('Failed to broadcast token update:', e && e.message ? e.message : e);
  }
}

app.get('/api/admin-tokens/stream', async (req, res) => {
  // Authenticate: support Authorization header or ?token=<jwt> query param (EventSource can't set headers)
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const bearer = authHeader ? (authHeader.split(' ')[1]) : null;
  const queryToken = req.query && req.query.token ? req.query.token : null;
  const jwtToken = bearer || queryToken;

  if (!jwtToken) {
    res.status(401).json({ message: 'Authorization required (provide token in header or ?token= query).' });
    return;
  }

  let payload;
  try {
    payload = jwt.verify(jwtToken, JWT_SECRET);
  } catch (e) {
    res.status(401).json({ message: 'Invalid or expired token.' });
    return;
  }

  if (payload.role !== 'admin') {
    res.status(403).json({ message: 'Admin access required.' });
    return;
  }

  // Basic SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });

  // Send initial data snapshot
  const initial = { pending_tokens: await getPendingTokensSnapshot() };
  res.write(`data: ${JSON.stringify(initial)}\n\n`);

  // Add to client set
  sseClients.add(res);

  // Remove client on close
  req.on('close', () => {
    sseClients.delete(res);
  });
});

// ============================================
// START SERVER
// ============================================
// Profile endpoint: returns user profile (requires Authorization: Bearer <token>)
app.get('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header required.' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Bearer token required.' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (verifyErr) {
      return res.status(401).json({ message: 'Invalid or expired token.' });
    }

    const email = payload.email;
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) return res.status(404).json({ message: 'User not found.' });

    const user = snapshotVal(snapshot);
    // Do not return password in profile response
    if (user.password) delete user.password;

    return res.json({ user });
  } catch (error) {
    console.error('Profile fetch error:', error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// PROFILE UPDATE ENDPOINT (PUT /api/profile)
// ============================================
app.put('/api/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header required.' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Bearer token required.' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
    } catch (verifyErr) {
      return res.status(401).json({ message: 'Invalid or expired token.' });
    }

    const email = payload.email;
    const { phone_number, date_of_birth, country, bio } = req.body;

    // Fetch existing user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) return res.status(404).json({ message: 'User not found.' });

    // Update profile fields
    const updates = {};
    if (phone_number !== undefined) updates.phone_number = phone_number || '';
    if (date_of_birth !== undefined) updates.date_of_birth = date_of_birth || '';
    if (country !== undefined) updates.country = country || '';
    if (bio !== undefined) updates.bio = bio || '';
    updates.profile_updated_at = new Date().toISOString();

    await db.ref(`users/${email.replace(/\./g, '_')}`).update(updates);

    console.log(`✅ Profile updated for user: ${email}`);

    return res.status(200).json({ 
      message: 'Profile updated successfully.',
      updates 
    });
  } catch (error) {
    console.error('Profile update error:', error);
    return res.status(500).json({ message: 'Server error during profile update.' });
  }
});

// ============================================
// SECURITY QUESTION ENDPOINT
// ============================================
app.post('/api/security-question', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required.' });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = snapshotVal(snapshot);

    res.status(200).json({
      security_question: user.security_question || 'Security question not set.',
    });
  } catch (error) {
    console.error('Security question fetch error:', error);
    return res.status(500).json({ message: 'Server error.' });
  }
});

// ============================================
// RESET PASSWORD ENDPOINT
// Returns structured errors with `missing_fields` or `invalid_fields` to help the client focus inputs
// ============================================
app.post('/reset-password', async (req, res) => {
  try {
    const { email, security_answer, new_password } = req.body;

    // Identify missing fields and return them for UX
    const required = ['email', 'security_answer', 'new_password'];
    const missing = required.filter(f => !req.body[f] || req.body[f].toString().trim() === '');
    if (missing.length) return res.status(400).json({ message: 'Missing required fields.', missing_fields: missing });

    // Validate new password
    if (new_password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters.', missing_fields: ['new_password'] });
    }

    // Fetch user
    const snapshot = await db.ref(`users/${email.replace(/\./g, '_')}`).get();
    if (!snapshotExists(snapshot)) {
      return res.status(404).json({ message: 'User not found.', missing_fields: ['email'] });
    }

    const user = snapshotVal(snapshot);

    // Verify security answer
    const userAnswer = (user.security_answer || '').toLowerCase().trim();
    const providedAnswer = (security_answer || '').toLowerCase().trim();
    if (userAnswer !== providedAnswer) {
      return res.status(401).json({ message: 'Security answer is incorrect.', invalid_fields: ['security_answer'] });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 10);

    // Update password in Firebase
    await db.ref(`users/${email.replace(/\./g, '_')}`).update({
      password: hashedPassword,
      password_updated_at: new Date().toISOString(),
    });

    console.log(`Γ£à Password reset successful for user: ${email}`);

    return res.status(200).json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ message: 'Server error during password reset.' });
  }
});

// ============================================
// COURSES API
// Admins can add/delete courses; public can list courses
// Stored under `courses/<id>` in the DB
// ============================================
app.get('/api/courses', async (req, res) => {
  try {
    const snapshot = await db.ref('courses').get();
    const data = snapshotVal(snapshot) || {};
    // Transform object map to array
    const courses = Object.keys(data).map(id => ({ id, ...data[id] }));
    res.json({ courses });
  } catch (error) {
    console.error('Fetch courses error:', error);
    res.status(500).json({ message: 'Server error fetching courses.' });
  }
});

// ============================================
// LESSONS API (per-course)
// GET /api/courses/:id/lessons
app.get('/api/courses/:id/lessons', async (req, res) => {
  try {
    const id = req.params.id;
    // If an Authorization header with a valid admin token is provided, include unpublished lessons.
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    let isAdmin = false;
    if (token) {
      try {
        const payload = jwt.verify(token, JWT_SECRET);
        if (payload && payload.role === 'admin') isAdmin = true;
      } catch (e) { /* ignore invalid token */ }
    }

    const snapshot = await db.ref(`courses/${id}/lessons`).get();
    const data = snapshotVal(snapshot) || {};
    let lessons = Object.keys(data).map(k => ({ id: k, ...(data[k] || {}) }));
    // filter unpublished lessons for non-admins (treat missing `published` as published)
    if (!isAdmin) {
      lessons = lessons.filter(l => l.published !== false);
    }
    // sort by order (numeric) then created_at
    lessons.sort((a,b) => {
      const ao = typeof a.order === 'number' ? a.order : (a.order ? Number(a.order) : 0);
      const bo = typeof b.order === 'number' ? b.order : (b.order ? Number(b.order) : 0);
      if (ao !== bo) return ao - bo;
      return new Date(a.created_at || 0) - new Date(b.created_at || 0);
    });
    res.json({ lessons });
  } catch (e) {
    console.error('Fetch lessons error:', e);
    res.status(500).json({ message: 'Server error fetching lessons.' });
  }
});

// POST /api/courses/:id/lessons  (admin only)
app.post('/api/courses/:id/lessons', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

    const courseId = req.params.id;
    const { title, content, resource_url, weeks, topic, date, other_info, image_url } = req.body;
    if (!title) return res.status(400).json({ message: 'Lesson title required.' });

    const lessonId = `l_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
    const lesson = {
      title,
      content: content || '',
      resource_url: resource_url || '',
      weeks: weeks || '',
      topic: topic || '',
      date: date || '',
      other_info: other_info || '',
      image_url: image_url || '',
      order: (typeof req.body.order === 'number') ? req.body.order : (req.body.order ? Number(req.body.order) : 0),
      published: req.body.published === true || req.body.published === 'true' ? true : false,
      created_at: new Date().toISOString(),
      created_by: decoded.email || 'admin'
    };

    await db.ref(`courses/${courseId}/lessons/${lessonId}`).set(lesson);
    res.status(201).json({ id: lessonId, ...lesson });
  } catch (e) {
    console.error('Create lesson error:', e);
    res.status(500).json({ message: 'Server error creating lesson.' });
  }
});

// DELETE /api/courses/:id/lessons/:lessonId (admin only)
app.delete('/api/courses/:id/lessons/:lessonId', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

    const courseId = req.params.id;
    const lessonId = req.params.lessonId;
    if (!lessonId) return res.status(400).json({ message: 'Lesson id required.' });

    await db.ref(`courses/${courseId}/lessons/${lessonId}`).set(null);
    res.json({ message: 'Lesson deleted.' });
  } catch (e) {
    console.error('Delete lesson error:', e);
    res.status(500).json({ message: 'Server error deleting lesson.' });
  }
});

// PUT /api/courses/:id/lessons/:lessonId (admin only) - edit lesson
app.put('/api/courses/:id/lessons/:lessonId', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

    const courseId = req.params.id;
    const lessonId = req.params.lessonId;
    const { title, content, resource_url, order, published, weeks, topic, date, other_info, image_url } = req.body;
    if (!lessonId) return res.status(400).json({ message: 'Lesson id required.' });

    const updates = {};
    if (title !== undefined) updates.title = title;
    if (content !== undefined) updates.content = content;
    if (resource_url !== undefined) updates.resource_url = resource_url;
    if (weeks !== undefined) updates.weeks = weeks;
    if (topic !== undefined) updates.topic = topic;
    if (date !== undefined) updates.date = date;
    if (other_info !== undefined) updates.other_info = other_info;
    if (image_url !== undefined) updates.image_url = image_url;
    if (order !== undefined) updates.order = (typeof order === 'number') ? order : (order ? Number(order) : 0);
    if (published !== undefined) updates.published = published === true || published === 'true' ? true : false;
    if (Object.keys(updates).length === 0) return res.status(400).json({ message: 'No updates provided.' });

    await db.ref(`courses/${courseId}/lessons/${lessonId}`).update({ ...updates, updated_at: new Date().toISOString(), updated_by: decoded.email || 'admin' });
    res.json({ message: 'Lesson updated.' });
  } catch (e) {
    console.error('Edit lesson error:', e);
    res.status(500).json({ message: 'Server error editing lesson.' });
  }
});

// Upload lesson image (admin only)
if (hasMulter) {
  app.post('/api/uploads/lessons', upload.single('image'), async (req, res) => {
    try {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
      if (!token) return res.status(401).json({ message: 'Unauthorized' });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
      if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

      if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
      const filename = req.file.filename;
      const url = `/Tii/uploads/lessons/${filename}`;
      res.json({ url });
    } catch (e) {
      console.error('Upload lesson image error:', e);
      res.status(500).json({ message: 'Server error uploading image.' });
    }
  });
} else {
  // multer not available: instruct clients to use base64 endpoint or send base64 here
  app.post('/api/uploads/lessons', async (req, res) => {
    res.status(501).json({ message: 'Multer not available on this host. Use /api/uploads/lessons/base64 (POST JSON { filename, data })' });
  });

  // Base64 upload fallback: accepts JSON { filename, data } where data is data URL or base64 string
  app.post('/api/uploads/lessons/base64', async (req, res) => {
    try {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
      if (!token) return res.status(401).json({ message: 'Unauthorized' });
      let decoded;
      try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
      if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

      const { filename, data } = req.body;
      if (!data) return res.status(400).json({ message: 'No image data provided.' });
      // data may be a data URL: data:[<mediatype>][;base64],<data>
      let matches = null; let b64 = data;
      if (typeof data === 'string' && data.startsWith('data:')) {
        matches = data.match(/^data:(.+);base64,(.+)$/);
        if (!matches) return res.status(400).json({ message: 'Invalid data URL.' });
        b64 = matches[2];
      }
      const buffer = Buffer.from(b64, 'base64');
      const ext = filename ? path.extname(filename) : '.png';
      const safeName = Date.now() + '_' + Math.random().toString(36).slice(2,8) + (ext || '.png');
      const outPath = path.join(LESSON_UPLOAD_DIR, safeName);
      await fs.promises.writeFile(outPath, buffer);
      const url = `/Tii/uploads/lessons/${safeName}`;
      res.json({ url });
    } catch (e) {
      console.error('Base64 upload error:', e);
      res.status(500).json({ message: 'Server error saving base64 image.' });
    }
  });
}

app.post('/api/courses', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    let decoded;
    try { 
      decoded = jwt.verify(token, JWT_SECRET); 
    } catch (e) { 
      console.error('Token verification failed:', e.message);
      return res.status(401).json({ message: 'Invalid token: ' + e.message }); 
    }
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

    const { title, description, url, placement } = req.body;
    if (!title || !description) return res.status(400).json({ message: 'Title and description required.' });

    const id = `c_${Date.now()}`;
    const course = {
      title,
      description,
      url: url || '',
      placement: placement || 'other',
      created_at: new Date().toISOString(),
      created_by: decoded.email || 'admin',
    };

    await db.ref(`courses/${id}`).set(course);

    // Generate a local HTML page for this course if no external URL provided
    try {
      const pagePath = `/Tii/courses/${id}.html`;
      const targetUrl = course.url && course.url.length ? course.url : pagePath;
      // update course url in DB if it was empty
      if (!course.url || course.url.trim() === '') {
        course.url = targetUrl;
        await db.ref(`courses/${id}`).update({ url: targetUrl });
      }
      await generateCoursePage(id, course);
    } catch (e) {
      console.warn('Failed to generate course page:', e && e.message ? e.message : e);
    }

    res.status(201).json({ id, ...course });
  } catch (error) {
    console.error('Create course error:', error);
    res.status(500).json({ message: 'Server error creating course.' });
  }
});

// DEBUG: unauthenticated base64 upload for local testing only
// POST /api/uploads/lessons/debug { filename, data }
app.post('/api/uploads/lessons/debug', async (req, res) => {
  try {
    const { filename, data } = req.body;
    if (!data) return res.status(400).json({ message: 'No image data provided.' });
    let b64 = data;
    if (typeof data === 'string' && data.startsWith('data:')) {
      const m = data.match(/^data:(.+);base64,(.+)$/);
      if (!m) return res.status(400).json({ message: 'Invalid data URL.' });
      b64 = m[2];
    }
    const buffer = Buffer.from(b64, 'base64');
    const ext = filename ? path.extname(filename) : '.png';
    const safeName = Date.now() + '_' + Math.random().toString(36).slice(2,8) + (ext || '.png');
    const outPath = path.join(LESSON_UPLOAD_DIR, safeName);
    await fs.promises.writeFile(outPath, buffer);
    const url = `/Tii/uploads/lessons/${safeName}`;
    console.log('[DEBUG] wrote', outPath);
    res.json({ url });
  } catch (e) {
    console.error('Debug base64 upload error:', e);
    res.status(500).json({ message: 'Server error saving debug image.' });
  }
});

// DEBUG: unauthenticated endpoint to create a lesson for testing (local only)
// POST /api/debug/courses/:id/lessons { title, content, topic, weeks, date, other_info, resource_url, image_url, order, published }
app.post('/api/debug/courses/:id/lessons', async (req, res) => {
  try {
    const courseId = req.params.id;
    const { title, content, topic, weeks, date, other_info, resource_url, image_url } = req.body;
    if (!title) return res.status(400).json({ message: 'title required' });
    const lessonId = `dl_${Date.now()}_${Math.random().toString(36).slice(2,8)}`;
    const lesson = {
      title,
      content: content || '',
      topic: topic || '',
      weeks: weeks || '',
      date: date || '',
      other_info: other_info || '',
      resource_url: resource_url || '',
      image_url: image_url || '',
      order: (typeof req.body.order === 'number') ? req.body.order : (req.body.order ? Number(req.body.order) : 0),
      published: req.body.published === true || req.body.published === 'true' ? true : false,
      created_at: new Date().toISOString(),
      created_by: 'debug'
    };
    await db.ref(`courses/${courseId}/lessons/${lessonId}`).set(lesson);
    return res.status(201).json({ id: lessonId, ...lesson });
  } catch (e) {
    console.error('Debug create lesson error:', e);
    return res.status(500).json({ message: 'Server error creating debug lesson.' });
  }
});

// DEBUG: unauthenticated lesson creation for local testing only
// POST /api/courses/:id/lessons/debug { title, content, resource_url, weeks, topic, date, other_info, image_url, order, published }
app.post('/api/courses/:id/lessons/debug', async (req, res) => {
  try {
    const courseId = req.params.id;
    const { title, content, resource_url, weeks, topic, date, other_info, image_url } = req.body;
    if (!title) return res.status(400).json({ message: 'Title required for debug lesson.' });
    const lessonId = `l_debug_${Date.now()}_${Math.random().toString(36).slice(2,6)}`;
    const lesson = {
      title,
      content: content || '',
      resource_url: resource_url || '',
      weeks: weeks || '',
      topic: topic || '',
      date: date || '',
      other_info: other_info || '',
      image_url: image_url || '',
      order: (typeof req.body.order === 'number') ? req.body.order : (req.body.order ? Number(req.body.order) : 0),
      published: req.body.published === true || req.body.published === 'true' ? true : false,
      created_at: new Date().toISOString(),
      created_by: 'debug'
    };
    await db.ref(`courses/${courseId}/lessons/${lessonId}`).set(lesson);
    res.status(201).json({ id: lessonId, ...lesson });
  } catch (e) {
    console.error('Debug create lesson error:', e);
    res.status(500).json({ message: 'Server error creating debug lesson.' });
  }
});

app.delete('/api/courses/:id', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); } catch (e) { return res.status(401).json({ message: 'Invalid token' }); }
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin role required' });

    const id = req.params.id;
    if (!id) return res.status(400).json({ message: 'Course id required.' });

    await db.ref(`courses/${id}`).set(null);
    res.json({ message: 'Course deleted.' });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ message: 'Server error deleting course.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`≡ƒÜÇ Server running on port ${PORT}`);
});

// ---------------------------
// Course page generation
// ---------------------------
async function generateCoursePage(id, course) {
  try {

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${safeTitle} — The Informatics Initiative</title>
  <link rel="stylesheet" href="/Tii/styles.css">
  <style>
    body { background: #f7fafc; padding: 0; }
    .course-hero { max-width: 900px; margin: 32px auto 0 auto; background: #fff; padding: 32px 28px 24px 28px; border-radius: 12px; box-shadow: 0 6px 24px rgba(0,0,0,0.07); }
    .course-meta { color: #2a6e62; margin-bottom: 18px; font-size: 1.1em; }
    .course-body { color: #444; margin-bottom: 18px; font-size: 1.15em; }
    .lesson-list { margin-top: 18px; display: flex; flex-direction: column; gap: 18px; }
    .lesson-card { background: #f9fffa; border: 1px solid #e6f4ef; border-radius: 8px; padding: 18px 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.03); }
    .lesson-title { font-size: 1.2em; color: #2a6e62; margin-bottom: 6px; }
    .lesson-meta { color: #666; font-size: 0.98em; margin-bottom: 8px; }
    .lesson-img { max-width: 320px; border-radius: 6px; border: 1px solid #eee; margin-top: 8px; }
    .lesson-resource { margin-top: 8px; display: inline-block; }
    .lesson-other { margin-top: 8px; color: #666; font-style: italic; }
  </style>
</head>
<body>
  <a href="/Tii/index.html" style="margin-left:32px;display:inline-block;margin-top:18px;color:#2a6e62">← Back to Home</a>
  <main>
    <div class="course-hero">
      <h1 style="font-size:2.2em;color:#2a6e62;margin-bottom:8px;">${safeTitle}</h1>
      <div class="course-meta">${placementLabel} • Added by ${course.created_by || 'admin'} on ${new Date(course.created_at).toLocaleString()}</div>
      <div class="course-body">${safeDesc}</div>
      <div class="lesson-list" id="lesson-list">
        <p style="color:#666">Loading lessons…</p>
      </div>
      <div style="margin-top:24px;"><a class="explore-btn-secondary" href="/Tii/other-courses.html">Back to courses</a></div>
    </div>
  </main>
  <script>
    (async function(){
      const courseId = '${id}';
      const listEl = document.getElementById('lesson-list');
      try {
        const resp = await fetch('/api/courses/' + courseId + '/lessons');
        if (!resp.ok) { listEl.innerHTML = '<p style="color:#c0392b">Failed to load lessons.</p>'; return; }
        const data = await resp.json();
        const lessons = data.lessons || [];
        if (!lessons.length) { listEl.innerHTML = '<p style="color:#666">No lessons yet. Admins can upload lessons from the admin portal.</p>'; return; }
        listEl.innerHTML = '';
        lessons.forEach(l => {
          const div = document.createElement('div');
          div.className = 'lesson-card';
          const parts = [];
          parts.push('<div class="lesson-title">' + (l.title || 'Untitled') + '</div>');
          let meta = [];
          if (l.topic) meta.push('<strong>Topic:</strong> ' + l.topic);
          if (l.weeks) meta.push('<strong>Weeks:</strong> ' + l.weeks);
          if (l.date) meta.push('<strong>Date:</strong> ' + l.date);
          if (meta.length) parts.push('<div class="lesson-meta">' + meta.join(' | ') + '</div>');
          if (l.image_url) parts.push('<img class="lesson-img" src="' + l.image_url + '" alt="lesson image"/>');
          if (l.resource_url) parts.push('<a class="lesson-resource explore-btn-secondary" href="' + l.resource_url + '" target="_blank">Open Resource</a>');
          if (l.other_info) parts.push('<div class="lesson-other">' + l.other_info + '</div>');
          if (l.content) parts.push('<div style="margin-top:10px;color:#444">' + (l.content || '').replace(/\n/g,'<br/>') + '</div>');
          div.innerHTML = parts.join('');
          listEl.appendChild(div);
        });
        // Show admin controls if token present in localStorage
        try {
          const token = localStorage && localStorage.getItem && localStorage.getItem('authToken');
          if (token) {
            const controls = document.createElement('div');
            controls.style.marginTop = '18px';
            controls.innerHTML = '<a class="explore-btn" href="/Tii/upload-lesson.html?course=' + courseId + '">Add Lesson</a> <a class="explore-btn-secondary" href="/Tii/delete-lesson.html?course=' + courseId + '">Manage Lessons</a>';
            listEl.parentNode.appendChild(controls);
          }
        } catch(e) {}
      } catch (e) { listEl.innerHTML = '<p style="color:#c0392b">Network error loading lessons.</p>'; }
    })();
  </script>
</body>
</html>`;

    const filePath = path.join(COURSES_DIR, `${id}.html`);
    await fs.promises.writeFile(filePath, html, 'utf8');
    console.log(`Generated course page: ${filePath}`);
  } catch (e) {
    console.warn('Error generating course HTML for', id, e && e.message ? e.message : e);
  }
}

// On startup, generate pages for existing courses (if missing)
(async function ensureCoursePages() {
  try {
    const snapshot = await db.ref('courses').get();
    const data = snapshotVal(snapshot) || {};
    for (const id of Object.keys(data)) {
      const course = data[id] || {};
      const filePath = path.join(COURSES_DIR, `${id}.html`);
      // generate if missing
      if (!fs.existsSync(filePath)) {
        // if url is empty, set it to the generated path
        if (!course.url || course.url.trim() === '') {
          const pagePath = `/Tii/courses/${id}.html`;
          try { await db.ref(`courses/${id}`).update({ url: pagePath }); course.url = pagePath; } catch (e) { /* ignore */ }
        }
        await generateCoursePage(id, course);
      }
    }
  } catch (e) {
    console.warn('Failed to ensure course pages on startup:', e && e.message ? e.message : e);
  }
})();
