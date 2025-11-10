# Start All Services (PowerShell)
# This script starts both Python and Node services in separate windows

Write-Host "Starting Informatics Initiative Services..." -ForegroundColor Green
Write-Host ""

# Start Python Service in new window
Write-Host "Starting Python service on port 3000..." -ForegroundColor Cyan
Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\python-service'; .\venv\Scripts\Activate.ps1; python app.py"

# Wait a moment
Start-Sleep -Seconds 2

# Start Node Service in new window (optional)
Write-Host "Starting Node service..." -ForegroundColor Cyan
Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\node-service'; node server.js"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "All services started!" -ForegroundColor Green
Write-Host ""
Write-Host "Frontend:  Open frontend/index.html in browser" -ForegroundColor Yellow
Write-Host "Python:    http://localhost:3000" -ForegroundColor Yellow
Write-Host "API Docs:  Check python-service/app.py for endpoints" -ForegroundColor Yellow
Write-Host ""
Write-Host "Both windows will stay open. Close them to stop services." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green
