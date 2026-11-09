@echo off
setlocal
"%~dp0ps5-pack-analyzer.exe" --interactive
set "status=%errorlevel%"
echo(
pause
exit /b %status%
