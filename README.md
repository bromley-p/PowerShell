# PowerShell
A collection of useful PowerShell Scripts and GUI's

**********************************************************

Server2025_TaskSchedule-ForceDomainProfile.ps1 
There was a known issue with Windows Server 2025 changing the default firewall profile to PUBLIC on Domain Controller roles REF: https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-server-2025#3356msgdesc UPDATE JULY 2025 - This was resolved in Windows Update KB5060842
This script will check for existing files/folders and create if not found under C:\Util\Scripts\
Creates a PowerShell script called Srv2025_FixPublic_Private_FWProfile.ps1
Creates a Task Scheduler for the new Script and then sets it to run after startup of server

**********************************************************

ValidateCredentialsPerDomain.ps1 
A basic script to prompt for domain and credentials of an account to validate the username/password are correct. Returns true of false depending upon outcome NOTE: Sending passwords from the browser to the web server over HTTPS is standard practice. The password is encrypted by virtue of HTTPS as it is sent.

**********************************************************
