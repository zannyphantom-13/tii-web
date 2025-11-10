@echo off
REM Setup script for the project (Windows batch)

echo ========================================
echo Setting up Informatics Initiative
echo ========================================

REM Navigate to node-service and install dependencies
cd node-service
echo.
echo Installing Node.js dependencies...
call npm install
cd ..

REM Python setup
echo.
echo ========================================
echo Python environment is ready!
echo.
echo To activate Python virtual environment, run:
echo   cd python-service
echo   venv\Scripts\activate
echo.
echo Then start the Python server with:
echo   python app.py
echo ========================================

echo.
echo ========================================
echo Node.js setup complete!
echo.
echo To start the Node server, run:
echo   cd node-service
echo   node server.js
echo ========================================

pause
