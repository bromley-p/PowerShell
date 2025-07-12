########

### There was a known issue with Windows Server 2025 changing the default firewall profile to PUBLIC on Domain Controller roles
### REF: https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-server-2025#3356msgdesc
### UPDATE JULY 2025 - This was resolved in Windows Update KB5060842

# This script will check for existing files/folders and create if not found under C:\Util\Scripts\
# Creates a PowerShell script called Srv2025_FixPublic_Private_FWProfile.ps1
# Creates a Task Scheduler for the new Script and then sets it to run after startup of server

###
########

$scriptContent = @"
# Server2025_TaskSchedule-ForceDomainProfile.ps1
# This script fixes the public network profile issue on Windows Server 2025 DC

# Get the network profiles
`$networkProfiles = Get-NetConnectionProfile

# Wait for 60 seconds
Start-Sleep -Seconds 60

# Loop through each profile and restart-adapter if it is set to public
foreach (`$Nprofile in `$networkProfiles) {
    if (`$Nprofile.NetworkCategory -eq "Public") { 
        Restart-NetAdapter -Name `$Nprofile.InterfaceAlias
	    Write-host "Network Adapter was set to Public, restarting"
    }
    elseif (`$Nprofile.NetworkCategory -eq "Private") { 
        Restart-NetAdapter -Name `$Nprofile.InterfaceAlias
	    Write-host "Network Adapter was set to Private, restarting"
    }
    else {
        Write-host "Network Adapter is set to DomainAuthenticated... KEEP CALM AND CARRY ON..."
    }
}
"@

$scheduledTaskScriptLocation = "C:\Util\Scripts"
$scriptPath = "$scheduledTaskScriptLocation\Srv2025_FixPublic_Private_FWProfile.ps1"

####################################################################################
## CHECKING THAT ADMINISTRATIVE RIGHTS ARE BEING USED TO RUN THE SCRIPT
####################################################################################

Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$adminStatus = Test-Administrator

####################################################################################
# CREATE THE SCHEDULED TASK
####################################################################################

If($adminStatus){
    Write-Host "`n>>> CREATING SCHEDULED TASK... Running in elevated Administrator mode! <<<"

    # Create the directory if it doesn't exist
    if (-not (Test-Path -Path (Split-Path -Path $scriptPath))) {
        New-Item -ItemType Directory -Path (Split-Path -Path $scriptPath) -Force
    }

    # Write the script content to the file
    Set-Content -Path $scriptPath -Value $scriptContent

    Write-Output "Script created at $scriptPath"

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    #check if the task already exists
    $taskExists = Get-ScheduledTask -TaskName "Srv2025_FixPublic_Private_FWProfile" -ErrorAction SilentlyContinue
    if ($taskExists) {
        Write-Output "Scheduled task 'Srv2025_FixPublic_Private_FWProfile' already exists"
    }
    else {
        Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -TaskName "Srv2025_FixPublic_Private_FWProfile" -Description "Fixes the Server 2025 public or private network profile 1 minute after startup"
        Write-Output "Scheduled task 'Srv2025_FixPublic_Private_FWProfile' created to run at startup with a 1 minute delay in the script`nScript is located in $scheduledTaskScriptLocation"
    }
} Else {
    Write-Host "`nWARNING: To create the Scheduled Task, this script needs to be ran in an elevated Administrator window.`n>> Please open up PowerShell (or PowerShell ISE) using 'Run As Administrator'."
}