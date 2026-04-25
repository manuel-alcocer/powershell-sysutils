@echo off
REM Thin batch wrapper around DllSuite-Run.ps1 so CI agents can invoke
REM the analyzer without first knowing PowerShell argument quoting.
REM Forwards every argument verbatim and propagates the exit code.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DllSuite-Run.ps1" %*
exit /b %ERRORLEVEL%
