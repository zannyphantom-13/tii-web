# Quick Start Guide

## ✅ Setup Complete!

Everything is configured for both **localhost** and **Render** deployment.

---

## 🚀 Running Locally

### Option 1: Using Batch Script (Windows)
```powershell
.\setup.bat
```

### Option 2: Using PowerShell Script
```powershell
.\setup.ps1
```

### Option 3: Manual Setup

**Terminal 1 - Python Service (Flask):**
```powershell
cd python-service
.\venv\Scripts\Activate.ps1
python app.py
```
Service will run on `http://localhost:3000`

**Terminal 2 - Node Service (Express) - Optional:**
```powershell
cd node-service
node server.js
```

**Terminal 3 - Frontend:**
Just open `frontend/index.html` in your browser

---

## 📁 Project Structure

```
procfile/
├── .env                          # ✅ Created - Local environment variables
├── .env.example                  # Template for environment variables
├── .gitignore                    # Prevents committing secrets
├── Procfile                      # Render deployment config
├── DEPLOYMENT.md                 # Full deployment guide
├── frontend/                     # HTML/CSS/JS frontend
│   ├── index.html
│   ├── auth.js                  # ✅ Updated - Auto-detects API URL
│   └── ... other files
├── python-service/              
│   ├── app.py                   # ✅ Updated - Reads .env file
│   ├── requirements.txt
│   └── venv/                    # ✅ Created - Virtual environment
└── node-service/                
    ├── server.js                # ✅ Updated - Uses PORT env var
    ├── package.json
    └── node_modules/            # Will be created by npm install
```

---

## 🔧 What Was Set Up

✅ **Python Virtual Environment** - Isolated Python dependencies
✅ **All Python Packages Installed** - Flask, SQLAlchemy, Flask-CORS, etc.
✅ **Environment Variables** - `.env` file with development settings
✅ **Frontend API URL Detection** - Automatically switches between localhost and production
✅ **Backend Port Configuration** - Reads PORT from environment
✅ **`.gitignore`** - Prevents accidentally committing `.env` and secrets

---

## 🔑 Environment Variables

Your `.env` file has been created with:
- `ENVIRONMENT=development`
- `SECRET_KEY` and `JWT_SECRET` for local testing
- Email configuration (set your Gmail credentials if needed)
- `ADMIN_EMAIL=hazytarzan12@gmail.com`

**For production (Render)**, you'll set:
- `ENVIRONMENT=production`
- `DATABASE_URL` (Render provides this)
- Real email credentials (Gmail app password)
- Strong random values for `SECRET_KEY` and `JWT_SECRET`

---

## 📡 API Endpoints

Your backend runs on port 3000 and provides:
- `/register` - Student registration
- `/login` - Student login
- `/verify-otp` - OTP verification
- `/admin_login_check` - Admin authentication check
- `/admin_login` - Admin final login
- `/submit-feedback` - Feedback submission

---

## ✨ Ready to Test!

1. **Start Python service**: `python app.py` (from python-service folder)
2. **Open browser**: `http://localhost:3000/` or open `frontend/index.html`
3. **Create account**: Test registration, OTP, and login flows

---

## 🚀 Deploying to Render

When ready to deploy:

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```

2. **In Render Dashboard:**
   - Create new Web Service
   - Connect GitHub repo
   - Set environment variables (see `DEPLOYMENT.md`)
   - Deploy!

---

## ❓ Troubleshooting

**Python packages not found?**
```powershell
cd python-service
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Port 3000 already in use?**
```powershell
# Use a different port
$env:PORT=5000
python python-service/app.py
```

**API returning 404?**
- Check if Python service is running: `http://localhost:3000`
- Open browser console (F12) to see actual API calls
- Check `.env` file has correct settings

---

## 📚 More Information

- See `DEPLOYMENT.md` for complete production guide
- See `DEPLOYMENT.md` for environment variable reference
- Frontend code: `frontend/` directory
- Backend code: `python-service/app.py`

**Happy coding! 🎉**
