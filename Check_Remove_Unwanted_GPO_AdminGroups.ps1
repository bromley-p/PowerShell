# This script will check for the existence of pre-definied Admin groups on the system. It will remove them if found
# Useful for groups being pushed out via GPO every xx minutes, and then LOGS the changes to log file
# You can set this to run on a Task Scheduler, one/twice per hour in order to remove once GPO updates :)

##############################################################################################
# Listing the Groups that you want to be removed if detected. Can leave null if not required
##############################################################################################

$adminGroup1 = "DOMAIN\IT-HelpDesk"
$adminGroup2 = "DOMAIN\IT-PCAdmins"
$adminGroup3 = "DOMAIN\IT-ServerAdmins"
$adminGroup4 = ""

$scriptLoggingPath = "C:\Util"

#########################################################################
# Setting up the logging of the script to keep history of changes
#########################################################################

Function OpenLogFile {
    Param([string]$FilePath)

    $fdFile = [System.IO.StreamWriter]::new([System.IO.FileStream]::new($FilePath, 'Append', 'Write', 'Read'),[System.Text.Encoding]::utf8)
    $fdFile.AutoFlush = $true
    Return $fdFile
}

Function Writelog {
    Param([System.IO.StreamWriter]$fdLogFile, [string]$Message)

    $MyTime = Get-Date -Format "HH:mm:ss"
    $buffer = "$MyTime $Message"
    $fdLogFile.WriteLine($buffer)
}

Function CloseLogFile {
    Param([System.IO.StreamWriter]$fdLogFile)

    $fdLogFile.Flush()
    $fdLogFile.Close()
}

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
# CREATE THE UTIL FOLDER IF NOT EXISTING
####################################################################################

If($adminStatus){

    # Create the directory if it doesn't exist
    if (-not (Test-Path -Path $scriptLoggingPath)) {
     Write-Host "Test Path not exist"
        New-Item -ItemType Directory -Path $scriptPath -Force
    }

$Logfile = 'localAdminDetection-' + (Get-Date).ToString('yyyyMMdd') + '.log'
$fdLogFile = OpenLogFile $scriptLoggingPath\$Logfile

#########################################################################
# Checking if the groups defined at the start of the script are found
#########################################################################

$groupCheck = ""
$groupCheck = Get-LocalGroupMember -Group 'Administrators' | Where {($_.Name -like $adminGroup1) -or ($_.Name -like $adminGroup2) -or ($_.Name -like $adminGroup3) -or ($_.Name -like $adminGroup4)} | Select Name

If($groupCheck -eq $null)
{
Write-Host "None of the following groups were detected: $adminGroup1 $adminGroup2 $adminGroup3 $adminGroup4`nKEEP CALM AND CARRY ON."
WriteLog $fdLogFile "None of the following groups were detected: $adminGroup1 $adminGroup2 $adminGroup3 $adminGroup4"
}
else
{
    ForEach($groupMembership in $groupCheck)
    {
      $groupName = $groupMembership.Name

        if($groupName -eq $adminGroup1)
        {
            Try {
                $member = $adminGroup1
                Remove-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction SilentlyContinue
                WriteLog $fdLogFile "Security group detected: $adminGroup1. Removing now..."
                Write-Host "Security group detected: $adminGroup1. Removing now..."
            }
            Catch {
                WriteLog $fdLogFile "Error is $_"
            }
        }
        if($groupName -eq $adminGroup2)
        {
            Try {
                $member = $adminGroup2
                Remove-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction SilentlyContinue
                WriteLog $fdLogFile "Security group detected: $adminGroup2. Removing now..."
                Write-Host "Security group detected: $adminGroup2. Removing now..."
            }
            Catch {
                WriteLog $fdLogFile "Error is $_"
            }
        }
        if($groupName -eq $adminGroup3)
        {
            Try {
                $member = $adminGroup3
                Remove-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction SilentlyContinue
                WriteLog $fdLogFile "Security group detected: $adminGroup3. Removing now..."
                Write-Host "Security group detected: $adminGroup3. Removing now..."
            }
            Catch {
                WriteLog $fdLogFile "Error is $_"
            }
        }
        if($groupName -eq $adminGroup4)
        {
            Try {
                $member = $adminGroup4
                Remove-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction SilentlyContinue
                WriteLog $fdLogFile "Security group detected: $adminGroup4. Removing now..."
                Write-Host "Security group detected: $adminGroup4. Removing now..."
            }
            Catch {
                WriteLog $fdLogFile "Error is $_"
            }
        }
    }
}
} Else {
    Write-Host "`nWARNING: To remove any unwanted Administrator Groups, this script needs to be ran in an elevated Administrator window.`n>> Please open up PowerShell (or PowerShell ISE) using 'Run As Administrator'."
}

CloseLogFile $fdlogfile