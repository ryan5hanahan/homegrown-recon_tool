@echo off
:: Setup script for ReconTool (Windows version)

echo Setting up ReconTool...

:: Create necessary directories
echo Creating directories...
if not exist results mkdir results
if not exist wordlists mkdir wordlists

:: Install Python dependencies
echo Installing Python dependencies...
pip install -r requirements.txt

:: Download common wordlists
echo Downloading common wordlists...

:: DNS wordlist
if not exist wordlists\dns.txt (
    echo Downloading DNS wordlist...
    powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt -OutFile wordlists\dns.txt"
    echo DNS wordlist downloaded.
) else (
    echo DNS wordlist already exists.
)

:: Subdomains wordlist
if not exist wordlists\subdomains.txt (
    echo Downloading subdomains wordlist...
    powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -OutFile wordlists\subdomains.txt"
    echo Subdomains wordlist downloaded.
) else (
    echo Subdomains wordlist already exists.
)

:: Web paths wordlist
if not exist wordlists\web_paths.txt (
    echo Downloading web paths wordlist...
    powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -OutFile wordlists\web_paths.txt"
    echo Web paths wordlist downloaded.
) else (
    echo Web paths wordlist already exists.
)

:: Check for external tools
echo Checking for external tools...

:: Function to check if a command exists
setlocal EnableDelayedExpansion
set missing_tools=

:: Check each tool
call :check_tool nmap
call :check_tool dig
call :check_tool subfinder
call :check_tool whatweb
call :check_tool gobuster
call :check_tool nikto
call :check_tool searchsploit
call :check_tool theHarvester
call :check_tool enum4linux
call :check_tool smbclient

:: Provide installation instructions for missing tools
if defined missing_tools (
    echo.
    echo Some external tools are missing. These tools are optional but recommended for full functionality.
    echo You can install them using the following methods:
    echo.
    echo For Windows:
    echo - nmap: https://nmap.org/download.html
    echo - dig: Install BIND tools or use Windows Subsystem for Linux
    echo - subfinder: https://github.com/projectdiscovery/subfinder
    echo - whatweb: Install Ruby and run 'gem install whatweb'
    echo - gobuster: https://github.com/OJ/gobuster
    echo - nikto: https://github.com/sullo/nikto
    echo - searchsploit: Part of Exploit-DB (https://www.exploit-db.com/searchsploit)
    echo - theHarvester: https://github.com/laramies/theHarvester
    echo - enum4linux: https://github.com/CiscoCXSecurity/enum4linux
    echo - smbclient: Install Samba client tools
    echo.
    echo Alternatively, consider using Windows Subsystem for Linux (WSL) for a more complete setup.
)

echo.
echo Setup completed!
echo You can now run the tool using: python recon.py -t TARGET [options]
goto :eof

:check_tool
where %1 >nul 2>nul
if %errorlevel% equ 0 (
    echo [+] %1 is installed.
) else (
    echo [-] %1 is not installed.
    set missing_tools=!missing_tools! %1
)
goto :eof
