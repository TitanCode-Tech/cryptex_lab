@echo off
setlocal
pushd "%~dp0"
where py >nul 2>&1
if %ERRORLEVEL% == 0 (
    py -3 update.py %*
    set EXITCODE=%ERRORLEVEL%
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% == 0 (
        python update.py %*
        set EXITCODE=%ERRORLEVEL%
    ) else (
        echo No Python interpreter found on PATH.
        set EXITCODE=1
    )
)
popd
endlocal & exit /b %EXITCODE%
