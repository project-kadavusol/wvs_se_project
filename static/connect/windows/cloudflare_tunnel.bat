@echo off
echo Checking if Cloudflare Tunnel is installed...
where cloudflared >nul 2>&1
if %errorlevel% neq 0 (
    echo Cloudflare Tunnel not found. Installing...
    powershell -Command "Invoke-WebRequest -Uri https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe -OutFile cloudflared.exe"
    if exist cloudflared.exe (
        echo Installation complete.
    ) else (
        echo Installation failed. Please download cloudflared manually from:
        echo https://github.com/cloudflare/cloudflared/releases/latest
        pause
        exit /b
    )
)

:GET_IP
echo Please enter the IP address:
set /p ip=IP: 
if "%ip%"=="" (
    echo IP address cannot be empty. Please try again.
    goto GET_IP
)

:GET_PORT
echo Please enter the port number:
set /p port=Port: 
if "%port%"=="" (
    echo Port number cannot be empty. Please try again.
    goto GET_PORT
)

echo Starting Cloudflare Tunnel...
start /B cloudflared.exe tunnel --url http://%ip%:%port%

echo.
echo Cloudflare Tunnel started. Copy the generated URL and paste it into the scanner.
echo If you don’t see a URL, Cloudflare might take a few seconds to initialize.
pause
