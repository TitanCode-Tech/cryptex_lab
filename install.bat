@echo off
REM Thin wrapper for install.py. Tries `py -3` first, then `python`.
setlocal
pushd "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL% == 0 (
    py -3 install.py %*
    set EXITCODE=%ERRORLEVEL%
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% == 0 (
        python install.py %*
        set EXITCODE=%ERRORLEVEL%
    ) else (
        echo No Python interpreter found on PATH. Install Python 3.10+ from python.org and try again.
        set EXITCODE=1
    )
)
popd
endlocal & exit /b %EXITCODE%
