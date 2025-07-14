#########################################################################################################
# 
# SECTION 1: CHECK FOR LOW DISK SPACE / RECYCLE BIN SIZE AND SERVICES NOT RUNNING (AND BITLOCKER STATUS)
# SECTION 2: CHECK FOR ANY PENDING REBOOTS AND THE REASONS (EMAIL REPORT ONCE-A-DAY)
# SECTION 3: UPDATE WINDOWS DEFENDER VIRUS DEFINITIONS
# SECTION 4: CHECK FOR ANY PENDING INSTALLS (FOR SYSTEMS THAT ARE NOT AUTOMATIC UPDATES)
# SECTION 5: GENERATE REPORT ON DISK SPACE AND SERVICES (EMAIL REPORT ONCE-A-DAY)
#
#########################################################################################################

$TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

# Gathering the domain\server name and current time for the process
$ErrorActionPreference= 'silentlycontinue'
$domainName = $env:userdomain
$computerName = $env:computername
$checkTime = Get-Date -Format HH  # This is in the 24-hour format, used to decide the hour for once-a-day report
$checkTimeFull = Get-Date -Format HH:mm  # This is in the 24-hour format, used to report when the script was ran
$checkDay = Get-Date -Format ddd # This is to get the day in short form, so you can restart services on certain days, not every day

# Declare variables for calculating and displaying DISK SPACE
$selectedDisks = ""
$percentFree = ""
$diskSpaceAlert = ""
$freeSpace = ""
$totalSpace = ""
$totalSpaceTotals = ""
$totalSpaceAlertReport = ""
$recycleBinSpaceUsed = ""
$recycleBinSpaceUsedReport = ""

# Declare variables for calculating and displaying SERVICES running or if REBOOT Required
$selectedServices = ""
$servicesRunning = ""
$servicesNotRunning = ""
$servicesStopped = ""
$totalServicesReport = ""
$totalOverallReport = ""
$totalReport = ""
$global:pendingRebootReason = ""

# Declare variables for calculating and displaying PENDING INSTALLS
$msUpdateSession = ""
$wsusUpdateResult = ""
$updates = ""
$updatesCount = ""
$wsusUpdateCount = ""
$updatesAlreadyDownloaded = ""
$updatesWaitingDownload = ""
$networkConnectionTest = Test-Connection 8.8.8.8

# Declare variables for Defender, BitLocker and Windows Update status
$bitlockerOSDriveStatus = ""
$bitlockerOSDriveStatusReport = ""
$bitlockerOSDriveStatusOFF = ""
$windowsDefenderCheckStartupType = ""
$windowsDefenderCheckRunningStatus = ""
$windowsDefenderEnabledCheck = ""
$windowsDefenderDetectedCheck = ""
$windowsDefenderAntivirusStatus = ""
$checkNugetInstalled = ""
$checkWindowsModule = ""
$windowsUpdatePowerShellCheck = ""
$windowsUpdatePowerShellCheckResults = ""
$windowsUpdateTitle = ""
$psWindowUpdateVerify = ""

####################################################################################
# >>> INITIAL IMPORTANT STEPS! - SETTING THE VARIABLES <<<
####################################################################################

# 1. SET the variables you want for the script to initiate/email the admin(s)
####################################################################################
# Example - for 7am use '07', for 7pm use '19'
$hourForRebootServerReport = '07'             # SECTION 2 - The hour that you want the Reboot Pending notication email to be sent
$hourForPendingInstallReport = '09'           # SECTION 4 - The hour that you want the Installs Pending notification email to be sent
$hourForDailySpaceCheckReport = '08'          # SECTION 5 - The hour you want the daily space/service report to be sent
$daysForDailySpaceCheckReport = ('Mon')       # SECTION 5 - The specific days that you want the daily space/service report to be sent

$driveTypesToCheck = 3                        # The type of 'disk' you want to include in the check i.e. 2 = "Removable disk", 3 = "Fixed local disk", 4 = "Network disk", 5 = "Compact disk"
$driveSpaceWarningLimit = 10                  # The % of disk space left on the drive before the threshold email alert is sent

# This is the array/list of services that you want to CHECK for on the server, OR ignore for the WSUS Pending Updates
# This will need to be tailored to suit your own requirements
####################################################################################
$servicesArrayToCheckRunning = ('Winmgmt','windefend','mpssvc')
$servicesArrayToCheckRunning = $servicesArrayToCheckRunning | sort-object

# There are usually daily updates from the following array, which could be ignored to reduce emails being sent
$wsusUpdatesToIgnore = @('Defender','Edge-Stable','Edge')
$wsusUpdateReportToEmailDays = ('Thu')

# 2. SET the email Variables for sending the warnings and report to the admins. This can be modified for BLAT or SMTP relay
####################################################################################
$smtp = "<enter smtp server address>" 
$from = "noone@nowhere.com" 
$toAdmin = "No One <noone@nowhere.com>" # You can edit / specific the recipient in each 'SECTION' to tailor who gets what
$toAdminGroup = "No One <noone@nowhere.com>","No OneMore <noonemore@nowhere.com>"

# 3. SET the email subject headings for the different notification email reports
####################################################################################
$subjectIssuesDetected = "WARNING: Issues Detected on $computerName"                  # SECTION 1 - Disk/Services Warning
$subjectRebootDetected = "WARNING: Reboot Required on $computerName"                  # SECTION 2 - Reboot Required Warning
$subjectPendingInstallDetected = "ALERT: Install Updates on $computerName"            # SECTION 4 - Updates to Install Required Warning
$subjectDriveServiceReport = "Weekly System Report: $domainName\$computerName"        # SECTION 5 - Daily Drive/Service Health Check Report

####################################################################################
## FUNCTION - CHECKING THAT ADMINISTRATIVE RIGHTS ARE BEING USED TO RUN THE SCRIPT
####################################################################################

# NOTE: If using the task scheduler to run this script, make sure to choose SYSTEM as the Run-As context

Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$adminStatus = Test-Administrator

If($adminStatus) {

        ####################################################################################
        # SECTION 1: CHECK FOR [DISK SPACE] AND [SERVICES] AND [RECYCLE BIN]
        ####################################################################################

        # Gather the information of the selected disk types
        ####################################################################################

        $selectedDisks = get-wmiobject Win32_LogicalDisk -Filter "DriveType = $driveTypesToCheck"  

        # For each disk returned from the defined list ($driveTypesToCheck), calculate the free space
        Write-Host "`n[DISK SPACE]" -ForegroundColor YELLOW
        forEach ($disk in $selectedDisks) {
       
               # This section at the top calculates how much space each recycle bin is taking up per drive
               #####################
               $driveBaseLetter = ""
               $recycleBinPath = ""
               $recycleBinSize = ""
               $recycleBinSizeRounded = ""

               $driveBaseLetter = $disk.DeviceID.Replace(':','')
               $recycleBinPath = $driveBaseLetter+':\$Recycle.Bin'
               $recycleBinSize = ((Get-ChildItem -LiteralPath $recycleBinPath -File -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum)*0.00000095367432
               $recycleBinSizeRounded = [math]::Round($recycleBinSize,2)
               $recycleBinSpaceUsedReport += "$driveBaseLetter"+":\ "+$recycleBinSizeRounded+" MB</BR>"
               $recycleBinSpaceUsed += "$driveBaseLetter"+":\ "+$recycleBinSizeRounded+" MB`n"
               #####################

               $Drive = $disk.DeviceID
               if ($disk.size -gt 0) {
                    $PercentFree = [Math]::round((($disk.freespace/$disk.size) * 100))
                }
               else {
                    $PercentFree = 0
               }
           
               # If the calculated space is less than the pre-defined threshold ($driveSpaceWarningLimit), email the admin(s)
               if ($PercentFree -le $driveSpaceWarningLimit)
                {
                $freeSpace = [Math]::round($disk.freespace/1073741824)   # Converting to GB
                $totalSpace = [Math]::round($disk.size/1073741824)       # Converting to GB
                $diskSpaceAlert = "<b>WARNING:</b> The server only has <b><font color='red'>$PercentFree%</font></b> free disk space on <b><font color='red'>$Drive\</font></b> ($freeSpace GB out of $totalSpace GB)</br>"
                Write-host "=> => WARNING: The server only has $PercentFree% free disk space on $Drive\ ($freeSpace GB out of $totalSpace GB)" -ForegroundColor yellow
        
                # Append all the disk space information to the overall warning report to be emailed
                $totalSpaceAlertReport += $diskSpaceAlert
               }

               # If the calculated space is above the pre-defined threshold, append it to the health check report list to email the admin(s)
               if ($PercentFree -gt $driveSpaceWarningLimit)
                {
                    $freeSpace = [Math]::round($disk.freespace/1073741824)   # Converting to GB
                    $totalSpace = [Math]::round($disk.size/1073741824)       # Converting to GB
                    $totalSpaceTotals += "Disk space for <b><font color='green'>$Drive\</font></b> is okay, it still has <b><font color='green'>$PercentFree%</font></b> free ($freeSpace GB out of $totalSpace GB)</br>"
                    Write-Host "Disk space for $Drive\ is okay, it still has $PercentFree% free ($freeSpace GB out of $totalSpace GB)"
                }    
        }

        Write-Host "`n[RECYCLE BIN SIZE]" -ForegroundColor YELLOW
        Write-Host "$recycleBinSpaceUsed"


        # Gather the Services running status of all the services from the pre-defined list
        ####################################################################################

        Write-Host "[SERVICES]" -ForegroundColor YELLOW

        # Check the pre-defined array of services ($servicesArrayToCheckRunning), unique to this server and if NOT running, email the admin(s) the list
        forEach ($serviceName in $servicesArrayToCheckRunning) {

            $selectedServices = Get-WmiObject -query "Select * From Win32_Service where name = '$serviceName'"
            forEach ($serviceItem in $selectedServices) {

                # If the selected service from the array is NOT running, add it to the list to email the admin(s)
                if ($serviceItem.state -ne "Running") {
          
                       $servicesNotRunning = $servicesNotRunning + "`n<b>WARNING:</b> The service <b>$serviceName</b> is <b><font color='red'>NOT</font></b> running!</font><BR />" + [char]13 + [char]10
                       Write-Host "=> => WARNING: The service $serviceName is NOT running!" -ForegroundColor yellow
                }
                else
                    {   # If the service IS Running then add to the list for the health check report to the admin(s)
                        $servicesRunning = $servicesRunning + "`nThe service <i>$serviceName</i> is okay <BR />"+ [char]13 + [char]10 
                        Write-Host "The service $serviceName is okay"
                }    
              } 
        }

        # Check if Bitlocker is on and Encrypted (for main drive only)
        $bitlockerOSDriveStatus = Get-BitLockerVolume -MountPoint "c:" | Select ProtectionStatus
        $bitlockerOSDriveStatusReport = Get-BitLockerVolume -MountPoint "c:" | Select ProtectionStatus,VolumeStatus,LockStatus | Format-List | Out-String
        Write-Host "`n[BITLOCKER]" -ForegroundColor YELLOW
        Write-Host "Bitlocker is currently set to:" $bitlockerOSDriveStatus.ProtectionStatus

        # Once the services array has been checked, it checks to see if there were any flagged as NOT running; and then generates the report to email
        $servicesStopped = $servicesNotRunning.count
        $totalServicesReport = "$servicesNotRunning" + "$servicesRunning<BR />" 


        # If EITHER the disk space is below the threshold, or the Services are not running, or Bitlocker is disabled, then send an alert email to the admin(s)
        ####################################################################################

            if(($totalSpaceAlertReport) -OR ($servicesNotRunning) -OR ($bitlockerOSDriveStatus.ProtectionStatus -eq 'Off')){  # Checks if either variable contains data

                If($bitlockerOSDriveStatus.ProtectionStatus -eq 'Off')
                {
                    $bitlockerOSDriveStatusOFF = "*** WARNING *** - BITLOCKER IS <b><font color='red'>OFF</font></b></BR>"
                }

                # Appends all the information together into one report to be emailed
                $totalOverallReport = "Server <b>$domainName\$computerName</b> requires <u>immediate</u> attention.<BR /><BR />[Disk Space Information]<BR />" + $totalSpaceAlertReport + $totalSpaceTotals + "<BR />[Services Running Information]<BR />" + $totalServicesReport + "[Bitlocker Protection Status]<BR />" + $bitlockerOSDriveStatusOFF + $bitlockerOSDriveStatusReport
        
                # Send the message to the admin via the SMTP server (or BLAT etc)
                send-MailMessage -SmtpServer $smtp -From $from -To $toAdminGroup -Subject $subjectIssuesDetected -Body $totalOverallReport -BodyAsHtml 
            }
            else {
                 # If it gets to this stage, then ALL services and disk space is okay
                 Write-Host "`n[DISK & SERVICES RESULTS]" -ForegroundColor YELLOW
                 Write-Host "PASSED: All services running as expected`nPASSED: All Disk space is above the $driveSpaceWarningLimit% remaining threshold"
            }

        ####################################################################################
        # SECTION 2: CHECK FOR ANY [PENDING REBOOTS] AND REASONS (EMAIL REPORT ONCE-A-DAY)
        ####################################################################################

        # This function checks pre-defined reqistry entries that Microsoft flags depending if a reboot is required.
        # NOTE: Some types of reboot flag may not be required to act upon and can be commented out

        Function CheckForPendingReboot{

         if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { 
             $global:pendingRebootReason += "* Updates are required for Component Based Services`n"
             return $true 
          }
         if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { 
             $global:pendingRebootReason += "* Updates are required for Windows Update Services`n" 
             return $true
         }
         # This 'if' statement check is detected frequently, however sometimes only Windows Update notifications are required
         #if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { 
         #    $global:pendingRebootReason += "* Updates are required for File Rename Operations Tasks`n" 
         #    return $true 
         #}
 
         # Checks if any reboots are pending due to the CCM (Microsoft Software Centre pushes)
         try { 
           $ccmClientUtil = [wmiclass]"\.\root\ccm\clientsdk:CCM_ClientUtilities"
           $ccmStatus = $ccmClientUtil.DetermineifRebootPending()
           if(($ccmStatus -ne $null) -and $ccmStatus.RebootPending) {
             $global:pendingRebootReason += "* Updates were flagged by CCM_ClientUtilities"
             return $true
           }
         } catch{}

          return $false  # If no reboots are required for ANY reason, then a false value is returned
        }

        # We now call the function and store the result (true or false) in the variable $RebootRequiredStatus to act on
        $RebootRequiredStatus = CheckForPendingReboot
        Write-Host "`n[PENDING REBOOTS]" -ForegroundColor YELLOW

        # If a pending reboot is discovered, then email the admin(s) with the reason for the reboot
        if($RebootRequiredStatus -eq $false)
        {
            Write-Host "PASSED: No Pending Reboots Required... KEEP CALM AND CARRY ON"
        } 
        else {
                # We ONLY want to be alerted about a reboot ONCE-A-DAY, therefore we can set the 'hour' (24-hour clock) that we want to send this ($hourForRebootServerReport)
                # This time is set in the initial variable section of the script
                if($CheckTime -eq $hourForRebootServerReport) {
        
                    $rebootDescription = "A system reboot is required on <b>$domainName\$computerName</b> because of the following reason(s):<BR /><strong><i>$global:pendingRebootReason</i></strong><BR />Please login to the server and reboot as soon as possible (when safe to do so obviously!)<BR /><BR />(This server check runs once per day at $checkTimeFull)"
            
                    # Send the message to the admin via the SMTP server (or BLAT etc)
                    send-MailMessage -SmtpServer $smtp -From $from -To $toAdminGroup -Subject $subjectRebootDetected -Body $rebootDescription -BodyAsHtml 
                }
                Write-Host "=> => WARNING: A reboot is required on $domainName\$computerName because of the following reason(s):`n$global:pendingRebootReason" -ForegroundColor Yellow
        }

        ####################################################################################
        # SECTION 3: UPDATE WINDOWS DEFENDER VIRUS DEFINITIONS
        ####################################################################################

        Write-Host "`n[WINDOWS DEFENDER SIGNATURE UPDATE]" -ForegroundColor YELLOW
        $windowsDefenderCheckStartupType = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).StartType  # Get the startup type of the service
        $windowsDefenderCheckRunningStatus = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).Status  # Get the current running status of the service
        $windowsDefenderEnabledCheck = Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue

        If($windowsDefenderEnabledCheck.AntivirusEnabled -eq $true) {
                           $windowsDefenderAntivirusStatus = "Enabled"
                           $windowsDefenderDetectedCheck = $true 
                        }
                        else {
                           $windowsDefenderAntivirusStatus = "DISABLED"
                        }
             
        ###########################################################################################################
        ###  Once Windows Defender is enabled (or if already enabled), ask if want to update the signatures
        ###########################################################################################################

            If(($windowsDefenderCheckRunningStatus -eq "Running") -AND ($windowsDefenderAntivirusStatus -eq "Enabled")){
                        Try {
                            Write-Host "Attempting to update the Windows Defender Signatures.... `nCurrent Signature Version:" $windowsDefenderEnabledCheck.AntivirusSignatureLastUpdated
                            Update-MpSignature

                            Start-Sleep -s 2
                            $windowsDefenderEnabledCheckSignature = Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue
                            Write-Host "Updated Signature Version:" $windowsDefenderEnabledCheckSignature.AntivirusSignatureLastUpdated
                        }
                        Catch {
                            Write-Host "Unable to update the Windows Defender Signature because: $_"
                        }
                    }
            else {
                   Write-Host "`n********* WINDOWS DEFENDER SIGNATURE UPDATES *********`n"  -ForegroundColor GREEN
                   Write-Host "[SKIP] Windows Defender Antivirus is currently set to $windowsDefenderAntivirusStatus... Continuing to next step"
           }

           Start-Sleep -s 2 #To give the system more than enough time to change the fact defender has been updated so its not seen in the Windows pending updates section

        ####################################################################################
        # SECTION 4: CHECK FOR WINDOWS UPDATES [PENDING INSTALLS] (EMAIL REPORT ONCE-A-DAY IF REQUIRED)
        ####################################################################################

        Write-Host "`n[WINDOWS UPDATES]" -ForegroundColor YELLOW
        Import-Module PSWindowsUpdate
        $checkWindowsModule = Get-Module PSWindowsUpdate
        If($checkWindowsModule)
        {
            Write-Host "Windows Update PowerShell Module already installed / imported... Continuing" 
        }
        Else{
            Write-Host "Windows Update PowerShell Module NOT installed or imported... Attempting to import first" 
    
            # It might be that the module is installed, but just not imported for this session. Attempt to import the module first

                    Try {
                        Import-Module PSWindowsUpdate
                        Start-Sleep -s 2
                        $psWindowUpdateVerify = Get-Module PSWindowsUpdate
                    }
                    Catch{
                        Write-Host "Failed to import PSWindowsUpdate because: $_"
                    }


            $checkNugetInstalled = Get-PackageProvider -ListAvailable | Select Name
            If($checkNugetInstalled -match 'NuGet')
            { 
                Write-Host "NuGet already installed... Continuing" 
            }
            Else {

                Try{
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
                    Start-Sleep -s 2
                }
                Catch{
                    Write-Host "Failed to install NuGet package because: $_"
                }
            }
    
            # Verify if PSWindowsUpdate is now present after attempting to import, if not then attempt to install
            If($psWindowUpdateVerify) 
            {
                Write-Host "PSWindowsUpdate has been imported... Continuing" 
            }
            Else {
                    Write-Host "Attempting to install PSWindowsUpdate"
                    Try{

                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
                        Start-Sleep -s 2
                        Write-Host "Installing PowerShellGet"
                        Install-Module PowerShellGet -AllowClobber -Force -Confirm:$false

                        Start-Sleep -s 2
                        Write-Host "Installing NuGet"
                        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
                
                        Start-Sleep -s 2
                        Write-Host "Installing PSWindowsUpdate"
                        Install-Module -Name PSWindowsUpdate -AllowClobber -Force -Confirm:$false
                        Get-Module -Name PSWindowsUpdate

                        Start-Sleep -s 5
                        Write-Host "Setting PSWindowsUpdate Repository"
                        Set-PSRepository -Name PSWindowsUpdate -InstallationPolicy Trusted
                        Write-Host "Setting PSGallery Repository"
                        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                
                        Start-Sleep -s 2

                            Try{
                                Write-Host "Attempting to import the PSWindowsUpdate module"
                                Import-Module PSWindowsUpdate
                                Start-Sleep -s 1
                                Get-Module PSWindowsUpdate
                            }
                            Catch{
                                Write-Host "Failed to import PSWindowsUpdate because: $_"
                            }

                        #Set-PSRepository -Name 'PSWindowsUpdate' -InstallationPolicy UnTrusted
                    }
                    Catch{
                        Write-Host "Failed to install PSWindowsUpdate because: $_"
                    } 
            }       
        }

        Write-Host "Checking for any available Windows Updates for $env:COMPUTERNAME`n"
        $windowsUpdatePowerShellCheck = Get-WindowsUpdate -NotCategory "Drivers"  #We want to exclude the optional drivers section
        ForEach($windowsUpdateTitle in $windowsUpdatePowerShellCheck)
        {
    
            #If($windowsUpdateTitle.title -match 'Framework 3.5')
            If($windowsUpdateTitle.title -match 'Defender Antivirus')
            {    
                Write-Host "*** $($windowsUpdateTitle.title)"
            } 
            Else {
            Write-Host "* $($windowsUpdateTitle.title)"
            $windowsUpdatePowerShellCheckResults += "* $($windowsUpdateTitle.title)<BR/>"
            }

        }

            # If pending updates are discovered (which arent ONLY in the excluded-to-report list), then email the admin(s) with the reason for the reboot
            # ONLY sends on specific days listed in $wsusUpdateReportToEmail
            ####################################################################################

            if(($windowsUpdatePowerShellCheckResults))
            {
                    #Write-Host $windowsUpdatePowerShellCheck  
                    # This time is set in the initial variable section of the script
                    if(($CheckTime -eq $hourForPendingInstallReport) -AND ($wsusUpdateReportToEmailDays -contains $checkday)) {
        
                        $pendingInstallDescription = "Updates requiring installation have been detected on <b>$domainName\$computerName</b><BR /><BR />$windowsUpdatePowerShellCheckResults<BR />Please login to the server to install and reboot as soon as possible (when safe to do so obviously!)<BR /><BR />(This server check runs once per day at $checkTimeFull)"
            
                        # Send the message to the admin via the SMTP server (or BLAT etc)
                        send-MailMessage -SmtpServer $smtp -From $from -To $toAdminGroup -Subject $subjectPendingInstallDetected -Body $pendingInstallDescription -BodyAsHtml 
                    }
            } 
            else {
                Write-Host "PASSED: No Pending 'Critical' Windows Updates Required... ALL GOOD!"       
            }


        ####################################################################################
        # SECTION 5: GENERATE REPORT ON DISK SPACE AND SERVICES (EMAIL REPORT ONCE-A-DAY)
        ####################################################################################

        # We ONLY want this report to be emailed ONCE-A-DAY, so set the 'hour' (24-hour clock) that we want to send this ($hourForDailySpaceCheckReport)
        # This time is set in the initial variable section of the script

            if(($checkTime -eq $hourForDailySpaceCheckReport) -AND ($daysForDailySpaceCheckReport -contains $checkday))
            {
                     $systemCheckDescription = "[Disk Space Information]<BR />" + $totalSpaceAlertReport + $totalSpaceTotals + "<BR />[Recycle Bin Size]<BR />" + $recycleBinSpaceUsedReport + "<BR />[Bitlocker Status]<BR />Bitlocker is currently set to: " + "$($bitlockerOSDriveStatus.ProtectionStatus)" + "<BR /><BR />[Services Running Information]<BR />" + $totalServicesReport + "[Windows Defender Signatures]<BR />Latest Signature Version: " + "$($windowsDefenderEnabledCheckSignature.AntivirusSignatureLastUpdated)" + "<BR /><BR />(This server check runs once per day at $checkTimeFull)"
             
                     # Send the message to the admin via the SMTP server (or BLAT etc)
                     send-MailMessage -SmtpServer $smtp -From $from -To $toAdmin -Subject $subjectDriveServiceReport -Body $systemCheckDescription -BodyAsHtml
            }
    } Else {
      Write-Host "`n***********************************************************`nWARNING: You are not running script as an elevated user,`nwhich is required for Bitlocker Status and Windows Update checks.`nPlease re-run this script as administrator`n***********************************************************"
}

pause