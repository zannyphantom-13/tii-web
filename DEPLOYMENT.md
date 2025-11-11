# Setup & Deployment Guide

## Local Development Setup

### 1. Python Service (Flask)
```bash
cd python-service
pip install -r requirements.txt
# Create .env from .env.example
python app.py
```
Server runs on: `http://localhost:3000`

### 2. Node Service (Express) - Optional
```bash
cd node-service
npm install
node server.js
```
Runs on: `http://localhost:3000` (change port if needed)

### 3. Frontend
- Open `frontend/index.html` in browser
- API automatically detects localhost vs production

---

## Production Deployment (Render)

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Ready for Render deployment"
git push origin main
```

### Step 2: Create Render Web Service
1. Go to [render.com](https://render.com)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `informatics-backend` (or your choice)
   - **Environment**: Python 3.11
   - **Build Command**: `pip install -r python-service/requirements.txt`
   - **Start Command**: `cd python-service && python app.py`
   - **Region**: Choose closest to your users

### Step 3: Set Environment Variables
In Render dashboard, add under "Environment":
```
ENVIRONMENT=production
SECRET_KEY=<generate-a-secure-random-string>
DATABASE_URL=<your-postgresql-url>
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=<your-gmail>
MAIL_PASSWORD=<your-app-password>
MAIL_DEFAULT_SENDER=noreply@tii.com
ADMIN_EMAIL=codestiiwebadmin@gmail.com
JWT_SECRET=<another-secure-random-string>
```

### Step 4: Deploy Frontend
Option A: Use Render Static Site
- Create another Render service for `frontend/` folder
- Point to your GitHub repo's `frontend` directory

Option B: Host on separate service (Netlify, GitHub Pages, etc.)
- Update frontend `API_URL` if not using same domain

---

## Environment Detection (How It Works)

### Frontend (`auth.js`)
```javascript
const API_URL = window.location.hostname === 'localhost' 
    ? 'http://localhost:3000' 
    : window.location.origin.replace(/:\d+$/, '');
```
- **Localhost**: Uses `http://localhost:3000`
- **Production**: Uses current domain (same as frontend URL)

### Backend (Python)
```python
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
DATABASE_URL = os.getenv('DATABASE_URL')  # Render provides this
```
- **Localhost**: SQLite at `python-service/students.db`
- **Render**: PostgreSQL (DATABASE_URL from Render)

### Backend (Node)
```javascript
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';
```
- Automatically uses Render's `PORT` variable
- Must set `JWT_SECRET` in environment

---

## Troubleshooting

### "Port already in use"
Change port locally:
```bash
# Python
PORT=5000 python python-service/app.py

# Node
PORT=5001 node node-service/server.js
```

### "API 404 errors"
1. Check if backend is running: `http://localhost:3000`
2. Verify CORS is enabled in backend
3. Check frontend API_URL detection (open browser console)

### "Database errors on Render"
1. Verify `DATABASE_URL` is set in Render environment
2. Ensure PostgreSQL add-on is provisioned
3. Check Render logs: Dashboard → Web Service → Logs

### "Email not sending"
- **Localhost**: Check console output (mock emails print to terminal)
- **Render**: Verify MAIL_USERNAME and MAIL_PASSWORD are set
- Use Gmail app passwords (not regular password)

---

## Key Files Changed
- `frontend/auth.js` - Dynamic API URL detection
- `node-service/server.js` - Environment-based PORT and JWT_SECRET
- `python-service/app.py` - DEBUG mode based on ENVIRONMENT
- `.env.example` - Configuration template
- `.gitignore` - Prevent committing secrets
- `Procfile` - Render build instructions
