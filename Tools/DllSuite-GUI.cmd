@echo off
REM Launches the WinForms GUI without showing a console window.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0DllSuite-GUI.ps1"
