# You need RSAT tools installed on the server: Install-WindowsFeature RSAT-AD-PowerShell
# Make sure that the following is installed: Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
# The limit command is best to be ran on the server that hosts the shares!

$users = ""
$user = ""
$staffQuota = "1GB"
$studentQuota = "500MB"
$studentOU = "OU=Students"
$domain = "enter_domain_name"
$nfsServer = "enter_nfs_server_name"
$homedriveLetter = "P:"

# List all of the OUs that you want to search for users in
$OUs = @("OU=People,DC=$domain,DC=ca","OU=Staff,DC=$domain,DC=ca")
$users = forEach ($OU in $OUs) {
    Get-ADUser -Filter * -Properties GivenName -SearchBase $OU
}
# Then for each user, check if they have a home directory in the correct folder, if not create
# The network file shares in this example are split by folder labelled a,b,c,d,e etc... Then the usernames inside are the full name of the user i.e. joebloggs

ForEach ($User in $Users) {

$FirstInitial = ""
$Username = ""
$HomePath = ""
$HomePathLocal = ""
$acl = ""

    # Get first initial of the user found in the OUs
    $FirstInitial = $User.GivenName.Substring(0,1).ToLower()
    $Username = $User.SamAccountName
    
    # Construct new path: \\SERVER_NAME\SHARE\joebloggs
    $HomePath = "\\$nfsServer\users$\$FirstInitial\$username"
    $HomePathLocal = "D:\users\$FirstInitial\$username"

    # First test the homepath exists or not?
    if (!(Test-Path $homePath)) {
        # 1. Create the home directory for user
        Try{
            New-Item -Path $homePath -ItemType Directory #-whatif
            Write-Host "$homePath did not exist... creating now"
            Start-Sleep -s 0.5
        } Catch {
            Write-Host "Unable to create $homepath because $_"
        }

        # 2. Set the ACL for the folder, allows specific user with modify access to that folder
        Try {
            $acl = Get-Acl $HomePath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $userName, 
            "Modify", 
            "ContainerInherit, ObjectInherit", 
            "None", 
            "Allow")

            $acl.AddAccessRule($accessRule)
            Set-Acl -Path $homePath -AclObject $acl #-WhatIf
        } Catch {
            Write-Host "Unable to set ACL on $homepath because $_"
        }

        # 3. Set the quota, based on if they are staff or student-  this needs a local path (so do it on the NFS server)
        If($user.DistinguishedName -match $studentOU)
        {
           Try {
                Write-Host "$($user.samAccountName) is part of the Student OU, setting quota to $studentQuota"
                New-FSRMQuota -Path "$homePathLocal" -Size 500MB
           } 
           Catch {
                Write-Host "Unable to set $studentQuota for $user because $_"
           }
        }
        Else {
            Try {
                Write-Host "$($user.samAccountName) is part of a non-student OU, setting quota to $staffQuota"
                New-FSRMQuota -Path "$homePathLocal" -Size 1GB
            }
            Catch {
                Write-Host "Unable to set $staffQuota for $user because $_"
            }
        }


        # 4. Set the user home directory path to be the new folder
        Try {          
            Set-ADUser -Identity $User -HomeDirectory $HomePath -HomeDrive "$homedriveLetter" #-WhatIf
            Write-Host "Set $user homedir to $homePath"
        } Catch {
            Write-Host "Unable to set $user to $homepath because $_"
        }
    }
    Else {
        Write-Host "$user already has $homePath assigned"
    }
}

$totalUsage = Get-FsrmQuota | Select-Object Path, @{n='SizeGB';e={$_.Size/1GB}}, @{n='UsageGB';e={$_.Usage/1GB}}, Template
Write-Host "`n*********** User Quotas ***********"
$totalUsage