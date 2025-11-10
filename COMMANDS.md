# 🚀 COPY & PASTE - START YOUR PROJECT NOW

## Option 1: Start Python Service Only (EASIEST)

```powershell
cd c:\Users\micha\Desktop\procfile\python-service
.\venv\Scripts\Activate.ps1
python app.py
```

Then open `frontend/index.html` in your browser.

---

## Option 2: Start Python + Node Services

### Terminal 1 - Python Service
```powershell
cd c:\Users\micha\Desktop\procfile\python-service
.\venv\Scripts\Activate.ps1
python app.py
```

### Terminal 2 - Node Service (in separate PowerShell window)
```powershell
cd c:\Users\micha\Desktop\procfile\node-service
node server.js
```

### Terminal 3 - Frontend
Open `c:\Users\micha\Desktop\procfile\frontend\index.html` in browser

---

## Option 3: Use Startup Script (BEST)

One PowerShell command starts everything:

```powershell
cd c:\Users\micha\Desktop\procfile
.\run-all.ps1
```

This automatically opens:
- Python service in one window
- Node service in another window
- Instructions to open frontend

---

## What to Do Next

1. **Wait for output like this:**
   ```
   * Running on http://0.0.0.0:3000
   ```

2. **Open browser to test:**
   ```
   http://localhost:3000
   ```
   Should see: `{"message": "Backend Server is Running."}`

3. **Open frontend:**
   Open file: `c:\Users\micha\Desktop\procfile\frontend\index.html`

4. **Test registration:**
   - Click Register
   - Fill in details
   - Check Python console for OTP (mock email)
   - Complete verification

---

## 🔍 Debug Tips

### Check Python Service is Running
```powershell
# In another PowerShell window:
Invoke-WebRequest http://localhost:3000
```

### Check What Port is in Use
```powershell
netstat -ano | Select-String :3000
```

### Kill Process Using Port 3000
```powershell
Stop-Process -Id <PID_FROM_ABOVE> -Force
```

### Check API URL Detection
1. Open `frontend/index.html`
2. Press F12 (Developer Tools)
3. Console tab, type: `API_URL`
4. Should show: `http://localhost:3000`

### View Python .env Configuration
```powershell
cat c:\Users\micha\Desktop\procfile\.env
```

---

## 📊 Quick Verification

After starting, check:

✅ Python service running: `http://localhost:3000`
✅ Frontend opens: `frontend/index.html`
✅ No console errors: F12 → Console tab
✅ API detected: F12 → Console → type `API_URL`
✅ Registration works: Try creating account

---

## 🛑 Stop Services

- **Python service**: Ctrl+C in the terminal window
- **Node service**: Ctrl+C in the terminal window
- **All services**: Close the windows or press Ctrl+C

---

## Common Issues & Fixes

### "Port 3000 already in use"
```powershell
# Use different port
$env:PORT=5000
python python-service/app.py
```

### "ModuleNotFoundError: No module named 'flask'"
```powershell
cd python-service
pip install -r requirements.txt
```

### "venv\Scripts\Activate.ps1 cannot be loaded"
```powershell
# PowerShell execution policy issue
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Then try again
```

### "Cannot find node"
```powershell
# Install Node.js from nodejs.org or use:
choco install nodejs
```

---

## 📚 Full Guides

- **`README_SETUP.md`** - Complete setup guide
- **`QUICKSTART.md`** - Quick reference
- **`DEPLOYMENT.md`** - Deploy to Render
- **`START_HERE.txt`** - Visual guide

---

## ✨ You're Ready!

Copy one of the commands above and paste it into PowerShell!

**Recommended:** Start with Option 1 (Python only) to test the backend first.

Happy coding! 🎉
