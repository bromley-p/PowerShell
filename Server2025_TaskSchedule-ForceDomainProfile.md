There was a known issue with Windows Server 2025 changing the default firewall profile to PUBLIC on Domain Controller roles.
REF: https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-server-2025#3356msgdesc
UPDATE JULY 2025 - This was resolved in Windows Update KB5060842.
This script will check for existing files / folders and create if not found under C:\Util\Scripts\.
Creates a PowerShell script called Srv2025_FixPublic_Private_FWProfile.ps1.
Creates a Task Scheduler for the new Script and then sets it to run after startup of server.
