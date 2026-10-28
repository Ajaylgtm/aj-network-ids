@echo off
setlocal
cd /d "%~dp0"

python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b %errorlevel%

python -m unittest discover -s tests -v
if errorlevel 1 exit /b %errorlevel%

python -m PyInstaller --noconfirm --clean --onefile --windowed --name NetworkIDS app.py
if errorlevel 1 exit /b %errorlevel%

echo.
echo Build complete: "%~dp0dist\NetworkIDS.exe"
