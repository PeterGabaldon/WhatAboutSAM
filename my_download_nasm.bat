REM ORIGINAL AT https://github.com/ShiftMediaProject/VSNASM/blob/master/install_script.bat

@echo OFF
setlocal

REM Defined cript variables
set NASMDL=http://www.nasm.us/pub/nasm/releasebuilds
set NASMVERSION=2.16.01

REM Store current directory and ensure working directory is the location of current .bat
set CALLDIR=%CD%
set SCRIPTDIR=%~dp0
set SCRIPTDIR=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC

set NASMDOWNLOAD=%NASMDL%/%NASMVERSION%/win%SYSARCH%/nasm-%NASMVERSION%-win%SYSARCH%.zip
echo Downloading required NASM release binary...
powershell.exe -Command "(New-Object Net.WebClient).DownloadFile('%NASMDOWNLOAD%', '%SCRIPTDIR%\nasm_%NASMVERSION%.zip')" >nul 2>&1
if not exist "%SCRIPTDIR%\nasm_%NASMVERSION%.zip" (
    echo Error: Failed to download required NASM binary!
    echo    The following link could not be resolved "%NASMDOWNLOAD%"
    goto Terminate
)

:InstallNASM
powershell.exe -Command Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::ExtractToDirectory('"%SCRIPTDIR%\nasm_%NASMVERSION%.zip"', '"%SCRIPTDIR%\TempNASMUnpack"') >nul 2>&1
if not exist "%SCRIPTDIR%\TempNASMUnpack" (
    echo Error: Failed to unpack NASM download!
    del /F /Q "%SCRIPTDIR%\nasm_.zip" >nul 2>&1
    goto Terminate
)

REM copy nasm executable to VC installation folder
echo Installing required NASM release binary...
del /F /Q "%VCINSTALLDIR%\nasm.exe" >nul 2>&1
copy /B /Y /V "%SCRIPTDIR%\TempNASMUnpack\nasm-%NASMVERSION%\nasm.exe" "%VCINSTALLDIR%" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: Failed to install NASM binary!
    echo    Ensure that this script is run in a shell with the necessary write privileges
    rd /S /Q "%SCRIPTDIR%\TempNASMUnpack" >nul 2>&1
    goto Terminate
)
rd /S /Q "%SCRIPTDIR%\TempNASMUnpack" >nul 2>&1
:SkipInstallNASM
echo Finished Successfully
