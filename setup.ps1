# Setup script for the project (PowerShell)

Write-Host "========================================" -ForegroundColor Green
Write-Host "Setting up Informatics Initiative" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Navigate to node-service and install dependencies
Set-Location "node-service"
Write-Host ""
Write-Host "Installing Node.js dependencies..." -ForegroundColor Cyan
npm install
Set-Location ".."

# Python setup
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Python environment is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "To activate Python virtual environment, run:" -ForegroundColor Yellow
Write-Host "  cd python-service" -ForegroundColor White
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Then start the Python server with:" -ForegroundColor Yellow
Write-Host "  python app.py" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Node.js setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To start the Node server, run:" -ForegroundColor Yellow
Write-Host "  cd node-service" -ForegroundColor White
Write-Host "  node server.js" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green

Read-Host "Press Enter to exit"
