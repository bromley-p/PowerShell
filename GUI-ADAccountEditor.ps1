[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")  
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[void][System.Windows.Forms.Application]::EnableVisualStyles()  #added for pop out progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$global:progressPreference = 'SilentlyContinue' # This stope the progress / install bar from being displayed
$global:errorActionPreference = 'SilentlyContinue' #Setting a preference variable to set the ErrorAction to SilentlyContinue for the entire session

####################################################################################
## CHECKING THAT ADMINISTRATIVE RIGHTS ARE BEING USED TO RUN THE SCRIPT
####################################################################################

Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$adminStatus = Test-Administrator

If(!($adminStatus)){
        $adminWarning = [System.Windows.Forms.MessageBox]::Show('For making changes to AD account (i.e. Unlock, Force Password) you need to run this GUI with an elevated powershell.','GUI Information','OK','Warning')
}

#################################################################
################ START OF THE GUI FUNCTIONS #####################
#################################################################

Function clearFormAD {

# This function clears out the fields in the form before doing another search

    $outputBoxDisplayName.Clear()
    $outputBoxAliasName.Clear()
    $outputBoxSamAccountName.Clear()
    $outputBoxLastLogon.Clear()
    $outputBoxPasswordLastSet.Clear()
    $outputBoxWhenCreated.Clear()
    $outputBoxUserPrincipalName.Clear()
    $outputBoxMail.Clear()
    $outputBoxCanonicalName.Clear()
    $outputBoxPWDChanged.Checked=$false
    $outputBoxEnabled.Checked=$false
    $outputBoxLocked.Checked=$false
    $outputBoxGroupMemberships.Clear()
    $outputBoxHomeDirectory.Clear()
    $outputBoxLogOnTo.Clear()
    $outputBoxChangePasswordNextLogon.Clear()
    $outputBoxStatusProgress.Clear()
    $outputBoxPasswordLastSet.ReadOnly = $true
    $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
    $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::green
}

Function userInfo {

    $wks=$userInputBox.text;
    $outputBoxStatusWindow.Text = "Retrieving Information..."
    $outputBoxStatusProgress.Text = "ESTABLISHING SESSION"
    $ProgressUpdate = $outputBoxStatusProgress.Text = "PROCESSING TASK ....."
    $outputBoxStatusWindow.Refresh()
    $outputBoxStatusProgress.Refresh()
    Start-Sleep -s 1
    
     
# Try to find the user details from the entered SamAccountName
  
        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
        $outputBoxStatusWindow.BorderStyle = "None"
        $outputBoxStatusWindow.Text = "Retrieving Information..."
        $ProgressUpdate
        $outputBoxStatusWindow.Refresh()
        $outputBoxStatusProgress.Refresh()
        Start-Sleep -s 0.5
        $userResult = Get-ADuser -ErrorAction SilentlyContinue -Filter "samAccountName -eq '$wks'" -properties DisplayName,samAccountName,CanonicalName,userPrincipalName,mail,Department,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordLastSet,pwdLastSet,whenCreated,LogonWorkstations,homeDirectory
        $userSharedMailboxGroupResults = Get-ADPrincipalGroupMembership -ErrorAction SilentlyContinue $wks | Where-Object {$_.SamAccountName -Match "Shared-Mailbox"}  | Sort Name
        $userSharedMailboxGroupResultsComma = $userSharedMailboxGroupResults.name -join ", `r`n"
        $userADGroupResults = Get-ADPrincipalGroupMembership -ErrorAction SilentlyContinue $wks | Where-Object {$_.SamAccountName -NotMatch "Shared-Mailbox"}  | Sort Name
        $userADGroupResultsComma = $userADGroupResults.name -join ", `r`n"
        
        # Check if a user match was found, if not then check if it's a shared mailbox (add MBX)
                  
    If ($userResult -eq $Null) {

            $outputBoxDisplayName.text="No Match Found"
            $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
            $outputBoxStatusWindow.BorderStyle = "None"
            $outputBoxStatusWindow.Text = "No Match - Awaiting Input..."
            $outputBoxStatusProgress.Clear()
            $outputBoxStatusWindow.Refresh()
            $outputBoxStatusProgress.Refresh()
            Write-Host "No Match Found"
            Return           
    }
                            

# Check if more than one user was returned (sometimes user may have more than one associtated employee number per role (very rare). Checks for an array as the userResult.type


    If ($userResult.getType().baseType.name -eq "Array") {
                   $outputBoxDisplayName.text = "More than one entry exists"
                   $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                   $outputBoxStatusWindow.BorderStyle = "None"
                   $outputBoxStatusWindow.Text = "No Match - Awaiting Input..."
                   $outputBoxStatusProgress.Clear()
                   $outputBoxStatusWindow.Refresh()
                   $outputBoxStatusProgress.Refresh()
            Return
        }
              

# Catch if account NEVER logged into (this is for shared mailboxes when the account is disabled automatically in script
  
    
    If ($userResult.LastLogonDate -eq $Null) {
                $outputBoxLastLogon.text="Account Never Logged On"
            
        }
    else {

                $outputBoxLastLogon.text=$userResult.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss")
    }


# Check if the user has AD enabled account

If ($userResult.enabled -eq 'True') {
                $outputBoxEnabled.Checked=$false
            
        }
        else {

                $outputBoxEnabled.Checked=$true
        }


# Check if the user has been locked out due to incorrect passwords etc.... 
        
        If ($userResult.LockedOut -eq 'True') {
                $outputBoxLocked.Checked=$true
            
        }
        else {

                $outputBoxLocked.Checked=$false
        }


# This calcuates the true value of pwdlastset into a readable form from AD


    If ($userResult.PasswordLastSet -eq $Null) {
                $outputBoxPasswordLastSet.ReadOnly = $false
                $outputBoxPasswordLastSet.ForeColor = [System.Drawing.Color]::darkred
                $outputBoxPasswordLastSet.text="Change at Next Login"
                            
        }
    else {
                $outputBoxPasswordLastSet.ReadOnly = $true
                $outputBoxPasswordLastSet.ForeColor = [System.Drawing.Color]::black
                $outputBoxPasswordLastSet.text=$userResult.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss")
    }

# Catch if account has a homeDirectory or not
  
    
    If ($userResult.HomeDirectory -eq $Null) {
                $outputBoxHomeDirectory.text="(No HomeDir Linked)"
                            
        }
    else {

                $outputBoxHomeDirectory.text=$userResult.HomeDirectory
    }

# Checks if user can Log On To ALL WORKSTATIONS, or if they are only allowed to log on to specific computers on campus

    If ($userResult.LogonWorkstations -eq $Null) {
                $outputBoxLogOnTo.ReadOnly = $true
                $outputBoxLogOnTo.ForeColor = [System.Drawing.Color]::black
                $outputBoxLogOnTo.text="All Workstations Allowed"
                            
        }
    else {
                $outputBoxLogOnTo.ReadOnly = $true
                $outputBoxLogOnTo.ForeColor = [System.Drawing.Color]::black
                $outputBoxLogOnTo.text="RESTRICTED - " + $userResult.LogonWorkstations -replace(",",", ")
    }


# Catch if account has a mail (email) attribute set
  
    
    If ($userResult.mail -eq $Null) {
                $outputBoxMail.text="(No Mail Attribute Set)"
                            
        }
    else {

                $outputBoxMail.text=$userResult.mail
    }

# Checks the OU group 


If ($userResult.canonicalName -match "$env:USERDNSDOMAIN/") {
        $userResultCN = $userResult.canonicalName -replace("$env:USERDNSDOMAIN/","")
    }


# Check if the user User must Change Password at Next Login is set (PasswordExpired) 

        If ($userResult.passwordExpired -match 'false') {
                $outputBoxChangePasswordNextLogon.readonly = $true
                $outputBoxChangePasswordNextLogon.ForeColor = [System.Drawing.Color]::black
                $outputBoxChangePasswordNextLogon.Text = "Default Settings (no forced change)"
            
        }
        else {
                $outputBoxChangePasswordNextLogon.readonly = $false
                $outputBoxChangePasswordNextLogon.ForeColor = [System.Drawing.Color]::darkred
                $outputBoxChangePasswordNextLogon.Text = "Change at Next Login"
        }


# Check if the user has any group memberships set 

        If (($userSharedMailboxGroupResultsComma -eq '') -AND ($userADGroupResultsComma -eq '')) {
                $outputBoxGroupMemberships.readonly = $true
                $outputBoxGroupMemberships.ForeColor = [System.Drawing.Color]::black
                $outputBoxGroupMemberships.Text = "No Groups Detected"
            
        }
        else {
                $outputBoxGroupMemberships.readonly = $true
                $outputBoxGroupMemberships.ForeColor = [System.Drawing.Color]::black
                $outputBoxGroupMemberships.Text = $outputBoxGroupMemberships.text=$userSharedMailboxGroupResultsComma + "`n" +$userADGroupResultsComma   
        }


# Populate the rest of the fields on the form with the attributes returned

        $outputBoxDisplayName.text=$userResult.displayName
        $outputBoxSamAccountName.text=$userResult.samAccountName
        $outputBoxWhenCreated.text=$userResult.whenCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $outputBoxUserPrincipalName.text=$userResult.userPrincipalName
        $outputBoxCanonicalName.text=$userResultCN      
        
        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
        $outputBoxStatusWindow.BorderStyle = "None"
        $outputBoxStatusWindow.Text = "Information Retrieved"
        $outputBoxStatusProgress.Clear()
        $outputBoxStatusWindow.Refresh()
        $outputBoxStatusProgress.Refresh()
        Write-Host "Retrieved AD User Information for $wks"

    }

####################################################################################
# This function enables the AD users account in Active Directory.
####################################################################################

Function enableAD {

 $procedureConfirmation = [System.Windows.Forms.MessageBox]::Show('Are you sure you want to toggle Enable/Disable for this user?','GUI Information','YesNo','Question')

     switch  ($procedureConfirmation) {

        'Yes' {

            If(!($adminStatus)){
                $adminWarning = [System.Windows.Forms.MessageBox]::Show('For making changes to AD account (i.e. Unlock, Force Password) you need to run this GUI with an elevated powershell.','GUI Information','OK','Warning')
                Return
            }
                $wks = $outputBoxSamAccountName.text;
                $outputBoxDirSyncNeeded.Clear()
                $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusWindow.Text = "Retrieving Information..."
                $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusProgress.Text = "ESTABLISHING SESSION"
                $ProgressUpdate = $outputBoxStatusProgress.Text = "PROCESSING TASK ....."
                $outputBoxStatusWindow.Refresh()
                $outputBoxStatusProgress.Refresh()
                Start-Sleep -s 1
    
                If ($wks -eq "") {

                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
                        $outputBoxStatusWindow.Text = "User account is not a valid result - No Match Found"
                        $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
                        $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            
                        Write-Host "User account is not a valid result - No Match Found"
                        Return;           
                }

                $userEnableCheck = Get-ADuser -ErrorAction SilentlyContinue -Filter "samAccountName -eq '$wks'" -properties Enabled
                If($userEnableCheck.Enabled -match "True") {

                    Disable-ADAccount -Identity $wks

                    # Change progress bar to inform user that task is done
      
                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                        $outputBoxStatusWindow.BorderStyle = "None"
                        $outputBoxStatusWindow.Text = "AD Account Disabled"
                        $outputBoxEnabled.Checked=$true

                        $outputBoxStatusProgress.Text = "TASK COMPLETED SUCCESSFULLY ....."
        
                        Write-Host "Disabled AD Account for $wks"      
                   }
                   Else {
       
                        Enable-ADAccount -Identity $wks

                        # Change progress bar to inform user that task is done
      
                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                        $outputBoxStatusWindow.BorderStyle = "None"
                        $outputBoxStatusWindow.Text = "AD Account Enabled"
                        $outputBoxEnabled.Checked=$false

                        $outputBoxStatusProgress.Text = "TASK COMPLETED SUCCESSFULLY ....."
        
                        Write-Host "Enabled AD Account for $wks"       
                   } 
    }
    'No' {
            $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusWindow.Text = "Toggle Enable/Disable Account Aborted"
            $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            Return;
      }
   }
 }

####################################################################################
# This function unlocks the AD users account in Active Directory
####################################################################################

Function unlockAD {

    $procedureConfirmation = [System.Windows.Forms.MessageBox]::Show('Are you sure you want to unlock this user?','GUI Information','YesNo','Question')

     switch  ($procedureConfirmation) {

        'Yes' {

                If(!($adminStatus)){
                    $adminWarning = [System.Windows.Forms.MessageBox]::Show('For making changes to AD account (i.e. Unlock, Force Password) you need to run this GUI with an elevated powershell.','GUI Information','OK','Warning')
                    Return
                }

                $wks = $outputBoxSamAccountName.text;
                $outputBoxDirSyncNeeded.Clear()
                $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusWindow.Text = "Retrieving Information..."
                $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusProgress.Text = "ESTABLISHING SESSION"
                $ProgressUpdate = $outputBoxStatusProgress.Text = "PROCESSING TASK ....."
                $outputBoxStatusWindow.Refresh()
                $outputBoxStatusProgress.Refresh()
                Start-Sleep -s 1

                If ($wks -eq "") {

                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
                        $outputBoxStatusWindow.Text = "User account is not a valid result - No Match Found"
                        $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
                        $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            
                        Write-Host "User account is not a valid result - No Match Found"
                        Return;           
                }
     
                Unlock-ADAccount -Identity $wks

                # Change progress bar to inform user that task is done
      
                    $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                    $outputBoxStatusWindow.BorderStyle = "None"
                    $outputBoxStatusWindow.Text = "AD Account Unlocked"
                    $outputBoxLocked.Checked=$false

                    $outputBoxStatusProgress.Text = "TASK COMPLETED SUCCESSFULLY ....."
        
                    Write-Host "Unlocked AD Account for $wks"       
        }
          'No' {

            $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusWindow.Text = "Unlock User Account Aborted"
            $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            Return; 
        }
     }

   }

####################################################################################
# This function toggle the AD 'User must change password at next logon'
####################################################################################

Function forcePasswordChangeAD {  # Toggle AD Force PWD Change

 $outputBoxDirSyncNeeded.Clear()

   # Displays a confirmation box asking if they are sure to continue the procedures. IF 'no' then is cancels out

    $procedureConfirmation = [System.Windows.Forms.MessageBox]::Show('Are you sure you want to toggle "FORCE PWD CHANGE" for this user? If set, the user will be forced to change password at next logon.','GUI Information','YesNo','Question')

     switch  ($procedureConfirmation) {

        'Yes' {
        
                If(!($adminStatus)){
                    $adminWarning = [System.Windows.Forms.MessageBox]::Show('For making changes to AD account (i.e. Unlock, Force Password) you need to run this GUI with an elevated powershell.','GUI Information','OK','Warning')
                    Return
                }

                $wks = $outputBoxSamAccountName.text;
                $forcePWDStatus = Get-ADuser -ErrorAction SilentlyContinue -Filter "samAccountName -eq '$wks'" -properties * #passwordExpired, passwordNeverExpires

                $outputBoxDirSyncNeeded.Clear()
                $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusWindow.Text = "Retrieving Information..."
                $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::green
                $outputBoxStatusProgress.Text = "ESTABLISHING SESSION"
                $ProgressUpdate = $outputBoxStatusProgress.Text = "PROCESSING TASK ....."
                $outputBoxStatusWindow.Refresh()
                $outputBoxStatusProgress.Refresh()
                Start-Sleep -s 1
    
                If ($wks -eq "") {

                    $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
                    $outputBoxStatusWindow.Text = "User account is not a valid result - No Match Found"
                    $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
                    $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            
                    Write-Host "User account is not a valid result - No Match Found"
                    Return;         
                }

                #Write-Host $forcePWDStatus.passwordExpired
        
                If ($forcePWDStatus.passwordExpired -match 'false') {

                        # If the PasswordNeverExpires flag is set then you wont be able to set the changePasswordAtLogon flag. You need to remove the PasswordNeverExpires flag first
                        
                        Try { 
                            If($forcePWDStatus.PasswordNeverExpires -eq $true){ 
                            Write-Host "$wks has PasswordNeverExpires set to TRUE in AD.... Removing now"
                            Set-ADUser -Identity $forcePWDStatus -PasswordNeverExpires:$False
                            Start-Sleep -Milliseconds 500
                            } else { 
                                Write-Host "$wks does not have PasswordNeverExpires set... Continuing procedure" 
                            } 
                            } catch {
                                Write-Host "FAILED to remove PasswordNeverExpires for $wks because: $_"
                        }
    
                        Set-ADUser -Instance $forcePWDStatus # This 'saves' the changes to the user
                        Start-Sleep -Milliseconds 500 
                                      
                        # Issues with the variable not writing properly to AD if PasswordNeverExpires was used. Therefore have set the $oUser instance and created a 'new' instance called $forceChangePWD for the final steps

                        $oUserWks = $outputBoxSamAccountName.text;

                        Set-ADUser -Identity $oUserWks -ChangePasswordAtLogon $true
                        Start-Sleep -Milliseconds 500
                        Write-Host "AD Account - ADDED Change password at next logon for $oUserWks" 
                        
                        $outputBoxChangePasswordNextLogon.readonly=$false
                        $outputBoxChangePasswordNextLogon.ForeColor = [System.Drawing.Color]::darkred
                        $outputBoxChangePasswordNextLogon.Text = "Change Password at Next Logon Set"    
                        
                        # Change progress bar to inform user that task is done

                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                        $outputBoxStatusWindow.BorderStyle = "None"
                        $outputBoxStatusWindow.Text = "Added Change Password At Next Logon"
                        $outputBoxStatusProgress.Text = "TASK COMPLETED SUCCESSFULLY ....."
        
                        Return; 
                }
                else {
                        Set-ADUser -Identity $wks -ChangePasswordAtLogon $false
                        $outputBoxChangePasswordNextLogon.readonly=$true
                        $outputBoxChangePasswordNextLogon.ForeColor = [System.Drawing.Color]::black
                        $outputBoxChangePasswordNextLogon.Text = "Default Settings (no forced change)"  

                        $outputBoxPasswordLastSet.readonly=$true
                        $outputBoxPasswordLastSet.ForeColor = [System.Drawing.Color]::black
                        $outputBoxPasswordLastSet.Text = "(Refresh Search to update)"  

                        # Change progress bar to inform user that task is done

                        $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                        $outputBoxStatusWindow.BorderStyle = "None"
                        $outputBoxStatusWindow.Text = "Removed Change Password At Next Logon"
                        $outputBoxStatusProgress.Text = "TASK COMPLETED SUCCESSFULLY ....."
        
                        Write-Host "AD Account - REMOVED Change password at next logon for $wks"  
                        Return;                  
                }
    }

        'No' {

            $outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusWindow.Text = "Toggle Force PWD Change Aborted"
            $outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::darkred
            $outputBoxStatusProgress.Text = "TASK CANCELLED ...."
            Return; 

        }

  }       
}

#################################################################
################## SETTING THE FORM LAYOUT ######################
#################################################################

$Form = New-Object System.Windows.Forms.Form    
$Form.Size = New-Object System.Drawing.Size(740,480) 
$Form.BackColor = "lightsteelblue"
$Form.StartPosition = "CenterScreen" #loads the window in the center of the screen
$Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow #modifies the window border
$Form.Text = " AD Account Editor " #window description 

#################################################################
############### START OF THE LOCAL AD FIELDS ####################
#################################################################

# Title : Username Description
$userlabel = New-Object System.Windows.Forms.Label
$userlabel.Location = New-Object System.Drawing.Point(20,20)
$userlabel.Size = New-Object System.Drawing.Size(210,20)
$userlabel.Text = 'Enter SamAccountName (username):'
$form.Controls.Add($userlabel)

# Input : Username Prompt
$userInputBox = New-Object System.Windows.Forms.TextBox 
$userInputBox.Location = New-Object System.Drawing.Size(240,20) 
$userInputBox.Size = New-Object System.Drawing.Size(245,20) 
$form.Controls.Add($userInputBox) 

# Button : Search AD button
$searchButton = New-Object System.Windows.Forms.Button 
$searchButton.Location = New-Object System.Drawing.Size(500,18) 
$searchButton.Size = New-Object System.Drawing.Size(80,25) 
$searchButton.Text = "Search" 
$searchButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$searchButton.BackColor = [System.Drawing.Color]::Green
$searchButton.ForeColor = [System.Drawing.Color]::White
$searchButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$searchButton.Add_Click({clearFormAD;userInfo}) 
$Form.Controls.Add($searchButton) 

# Title : AD Disabled
$enabledlabel = New-Object System.Windows.Forms.Label
$enabledlabel.Location = New-Object System.Drawing.Point(20,65)
$enabledlabel.Size = New-Object System.Drawing.Size(60,20)
$enabledlabel.Text = 'Disabled:'
$form.Controls.Add($enabledlabel)

# Output : AD Disabled
$outputBoxEnabled = New-Object System.Windows.Forms.CheckBox 
$outputBoxEnabled.Location = New-Object System.Drawing.Size(78,63) 
$outputBoxEnabled.Size = New-Object System.Drawing.Size(20,20) 
$outputBoxEnabled.Enabled = $false
$form.Controls.Add($outputBoxEnabled) 

# Title : AD Lockout
$lockedOutlabel = New-Object System.Windows.Forms.Label
$lockedOutlabel.Location = New-Object System.Drawing.Point(128,65)
$lockedOutlabel.Size = New-Object System.Drawing.Size(70,20)
$lockedOutlabel.Text = 'Locked Out:'
$form.Controls.Add($lockedOutlabel)

# Output : AD Lockout
$outputBoxLocked = New-Object System.Windows.Forms.CheckBox 
$outputBoxLocked.Location = New-Object System.Drawing.Size(208,63) 
$outputBoxLocked.Size = New-Object System.Drawing.Size(20,20) 
$outputBoxLocked.Enabled = $false
$form.Controls.Add($outputBoxLocked) 

# Title : DisplayName  
$displayNamelabel = New-Object System.Windows.Forms.Label
$displayNamelabel.Location = New-Object System.Drawing.Point(20,110)
$displayNamelabel.Size = New-Object System.Drawing.Size(125,20)
$displayNamelabel.Text = 'Display Name:'
$form.Controls.Add($displayNamelabel)

# Output : DisplayName
$outputBoxDisplayName = New-Object System.Windows.Forms.TextBox 
$outputBoxDisplayName.Location = New-Object System.Drawing.Size(150,110) 
$outputBoxDisplayName.Size = New-Object System.Drawing.Size(180,20) 
$outputBoxDisplayName.ReadOnly = $True 
$outputBoxDisplayName.MultiLine = $True 
$form.Controls.Add($outputBoxDisplayName) 

# Title : SamAccountName  
$samAccountNamelabel = New-Object System.Windows.Forms.Label
$samAccountNamelabel.Location = New-Object System.Drawing.Point(20,140)
$samAccountNamelabel.Size = New-Object System.Drawing.Size(125,20)
$samAccountNamelabel.Text = 'SamAccountName:'
$form.Controls.Add($samAccountNamelabel)

# Output : SamAccountName
$outputBoxSamAccountName = New-Object System.Windows.Forms.TextBox 
$outputBoxSamAccountName.Location = New-Object System.Drawing.Size(150,140) 
$outputBoxSamAccountName.Size = New-Object System.Drawing.Size(180,20) 
$outputBoxSamAccountName.ReadOnly = $True 
$outputBoxSamAccountName.MultiLine = $True 
$form.Controls.Add($outputBoxSamAccountName) 

# Title : Password Last Set  
$passwordLastSetlabel = New-Object System.Windows.Forms.Label
$passwordLastSetlabel.Location = New-Object System.Drawing.Point(20,170)
$passwordLastSetlabel.Size = New-Object System.Drawing.Size(150,20)
$passwordLastSetlabel.Text = 'Password Last Set:'
$form.Controls.Add($passwordLastSetlabel)

# Output : Password Last Set
$outputBoxPasswordLastSet = New-Object System.Windows.Forms.TextBox 
$outputBoxPasswordLastSet.Location = New-Object System.Drawing.Size(170,170) 
$outputBoxPasswordLastSet.Size = New-Object System.Drawing.Size(160,20) 
$outputBoxPasswordLastSet.MultiLine = $True 
$form.Controls.Add($outputBoxPasswordLastSet) 

# Title : Last Logon Date  
$lastLogonlabel = New-Object System.Windows.Forms.Label
$lastLogonlabel.Location = New-Object System.Drawing.Point(20,200)
$lastLogonlabel.Size = New-Object System.Drawing.Size(150,20)
$lastLogonlabel.Text = 'Last Login:'
$form.Controls.Add($lastLogonlabel)

# Output : Last Logon Date 
$outputBoxLastLogon = New-Object System.Windows.Forms.TextBox 
$outputBoxLastLogon.Location = New-Object System.Drawing.Size(170,200) 
$outputBoxLastLogon.Size = New-Object System.Drawing.Size(160,20) 
$outputBoxLastLogon.ReadOnly = $True 
$outputBoxLastLogon.MultiLine = $True 
$form.Controls.Add($outputBoxLastLogon) 

# Title : When Created  
$whenCreatedlabel = New-Object System.Windows.Forms.Label
$whenCreatedlabel.Location = New-Object System.Drawing.Point(20,230)
$whenCreatedlabel.Size = New-Object System.Drawing.Size(150,20)
$whenCreatedlabel.Text = 'Date Created:'
$form.Controls.Add($whenCreatedlabel)

# Output : When Created
$outputBoxWhenCreated = New-Object System.Windows.Forms.TextBox 
$outputBoxWhenCreated.Location = New-Object System.Drawing.Size(170,230) 
$outputBoxWhenCreated.Size = New-Object System.Drawing.Size(160,20) 
$outputBoxWhenCreated.ReadOnly = $True 
$outputBoxWhenCreated.MultiLine = $True 
$form.Controls.Add($outputBoxWhenCreated) 

# Title : UserPrincipalName 
$userPrincipalNamelabel = New-Object System.Windows.Forms.Label
$userPrincipalNamelabel.Location = New-Object System.Drawing.Point(20,260)
$userPrincipalNamelabel.Size = New-Object System.Drawing.Size(35,20)
$userPrincipalNamelabel.Text = 'UPN:'
$form.Controls.Add($userPrincipalNamelabel)

# Output : UserPrincipalName
$outputBoxUserPrincipalName = New-Object System.Windows.Forms.TextBox 
$outputBoxUserPrincipalName.Location = New-Object System.Drawing.Size(84,260) 
$outputBoxUserPrincipalName.Size = New-Object System.Drawing.Size(246,20) 
$outputBoxUserPrincipalName.MultiLine = $True 
$outputBoxUserPrincipalName.ReadOnly = $True 
$form.Controls.Add($outputBoxUserPrincipalName) 

# Title : Email (mail)
$emaillabel = New-Object System.Windows.Forms.Label
$emaillabel.Location = New-Object System.Drawing.Point(20,290)
$emaillabel.Size = New-Object System.Drawing.Size(36,20)
$emaillabel.Text = 'Email:'
$form.Controls.Add($emaillabel)

# Output : Email (mail)
$outputBoxMail = New-Object System.Windows.Forms.TextBox 
$outputBoxMail.Location = New-Object System.Drawing.Size(84,290) 
$outputBoxMail.Size = New-Object System.Drawing.Size(246,20) 
$outputBoxMail.ReadOnly = $True 
$outputBoxMail.MultiLine = $True 
$form.Controls.Add($outputBoxMail) 

# Title : CanonicalName / OU Group
$canonicalNamelabel = New-Object System.Windows.Forms.Label
$canonicalNamelabel.Location = New-Object System.Drawing.Point(20,320)
$canonicalNamelabel.Size = New-Object System.Drawing.Size(60,20)
$canonicalNamelabel.Text = 'OU Group:'
$form.Controls.Add($canonicalNamelabel)

# Output : CanonicalName / OU Group
$outputBoxCanonicalName = New-Object System.Windows.Forms.TextBox 
$outputBoxCanonicalName.Location = New-Object System.Drawing.Size(84,320) 
$outputBoxCanonicalName.Size = New-Object System.Drawing.Size(246,20) 
$outputBoxCanonicalName.ReadOnly = $True 
$outputBoxCanonicalName.MultiLine = $True 
$outputBoxCanonicalName.ScrollBars = "Horizontal" 
$form.Controls.Add($outputBoxCanonicalName) 

# Title : ChangePasswordAtNextLogon
$changePasswordNextLogonlabel = New-Object System.Windows.Forms.Label
$changePasswordNextLogonlabel.Location = New-Object System.Drawing.Point(350,110)
$changePasswordNextLogonlabel.Size = New-Object System.Drawing.Size(110,20)
$changePasswordNextLogonlabel.Text = 'Force PWD Change:'
$form.Controls.Add($changePasswordNextLogonlabel)

# Output : ChangePasswordAtNextLogon
$outputBoxChangePasswordNextLogon = New-Object System.Windows.Forms.TextBox 
$outputBoxChangePasswordNextLogon.Location = New-Object System.Drawing.Size(460,110) 
$outputBoxChangePasswordNextLogon.Size = New-Object System.Drawing.Size(230,20) 
$outputBoxChangePasswordNextLogon.MultiLine = $True 
$outputBoxChangePasswordNextLogon.ReadOnly = $true
$form.Controls.Add($outputBoxChangePasswordNextLogon) 

# Title : HomeDirectory
$homeDirectorylabel = New-Object System.Windows.Forms.Label
$homeDirectorylabel.Location = New-Object System.Drawing.Point(350,140)
$homeDirectorylabel.Size = New-Object System.Drawing.Size(52,20)
$homeDirectorylabel.Text = 'HomeDir:'
$form.Controls.Add($homeDirectorylabel)

# Output : HomeDirectory
$outputBoxHomeDirectory = New-Object System.Windows.Forms.TextBox 
$outputBoxHomeDirectory.Location = New-Object System.Drawing.Size(460,140) 
$outputBoxHomeDirectory.Size = New-Object System.Drawing.Size(246,20) 
$outputBoxHomeDirectory.ReadOnly = $True 
$outputBoxHomeDirectory.MultiLine = $True 
#$outputBoxHomeDirectory.ScrollBars = "Vertical" 
$form.Controls.Add($outputBoxHomeDirectory) 

# Title : Log On To... 
$logOnTolabel = New-Object System.Windows.Forms.Label
$logOnTolabel.Location = New-Object System.Drawing.Point(350,170)
$logOnTolabel.Size = New-Object System.Drawing.Size(45,20)
$logOnTolabel.Text = 'Log On:'
$form.Controls.Add($logOnTolabel)

# Output : Log On To... 
$outputBoxLogOnTo = New-Object System.Windows.Forms.TextBox 
$outputBoxLogOnTo.Location = New-Object System.Drawing.Size(460,170) 
$outputBoxLogOnTo.Size = New-Object System.Drawing.Size(246,48) 
$outputBoxLogOnTo.ReadOnly = $True 
$outputBoxLogOnTo.MultiLine = $True 
$outputBoxLogOnTo.ScrollBars = "Vertical" 
$form.Controls.Add($outputBoxLogOnTo) 

# Title : GroupMemberships
$groupMembershipslabel = New-Object System.Windows.Forms.Label
$groupMembershipslabel.Location = New-Object System.Drawing.Point(350,230)
$groupMembershipslabel.Size = New-Object System.Drawing.Size(45,20)
$groupMembershipslabel.Text = 'Groups:'
$form.Controls.Add($groupMembershipslabel)

# Output : GroupMemberships
$outputBoxGroupMemberships = New-Object System.Windows.Forms.TextBox 
$outputBoxGroupMemberships.Location = New-Object System.Drawing.Size(460,230) 
$outputBoxGroupMemberships.Size = New-Object System.Drawing.Size(246,70) 
$outputBoxGroupMemberships.ReadOnly = $True 
$outputBoxGroupMemberships.MultiLine = $True 
$outputBoxGroupMemberships.ScrollBars = "Vertical" 
$form.Controls.Add($outputBoxGroupMemberships) 

#################################################################
################# START OF THE ACTION BUTTONS  ##################
#################################################################

# Button : Enable AD Account
$enableADButton = New-Object System.Windows.Forms.Button 
$enableADButton.Location = New-Object System.Drawing.Size(360,320) #92
$enableADButton.Size = New-Object System.Drawing.Size(75,75) 
$enableADButton.Text = "Toggle Enable / Disable AD Account" 
$enableADButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$enableADButton.BackColor = [System.Drawing.Color]::Green
$enableADButton.ForeColor = [System.Drawing.Color]::White
$enableADButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$enableADButton.Add_Click({enableAD}) 
$Form.Controls.Add($enableADButton) 

# Button : Unlock AD Account
$unlockADButton = New-Object System.Windows.Forms.Button 
$unlockADButton.Location = New-Object System.Drawing.Size(450,320) #92
$unlockADButton.Size = New-Object System.Drawing.Size(75,75) 
$unlockADButton.Text = "Unlock AD Account" 
$unlockADButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$unlockADButton.BackColor = [System.Drawing.Color]::lightblue
$unlockADButton.ForeColor = [System.Drawing.Color]::black
$unlockADButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$unlockADButton.Add_Click({unlockAD}) 
$Form.Controls.Add($unlockADButton) 

# Button : Toggle AD Change Password at Next Logon
$forcePasswordChangeADButton = New-Object System.Windows.Forms.Button 
$forcePasswordChangeADButton.Location = New-Object System.Drawing.Size(540,320) #92
$forcePasswordChangeADButton.Size = New-Object System.Drawing.Size(75,75) 
$forcePasswordChangeADButton.Text = "Toggle Force Password Change" 
$forcePasswordChangeADButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$forcePasswordChangeADButton.BackColor = [System.Drawing.Color]::green
$forcePasswordChangeADButton.ForeColor = [System.Drawing.Color]::white
$forcePasswordChangeADButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$forcePasswordChangeADButton.Add_Click({forcePasswordChangeAD}) 
$Form.Controls.Add($forcePasswordChangeADButton) 


######################################################
# This is the Status update at the bottom of the page
######################################################

# Title : Status Update
$outputBoxStatusWindowlabel = New-Object System.Windows.Forms.Label
$outputBoxStatusWindowlabel.Location = New-Object System.Drawing.Point(20,415) 
$outputBoxStatusWindowlabel.Size = New-Object System.Drawing.Size(88,20) 
$outputBoxStatusWindowlabel.BackColor = [System.Drawing.Color]::lightsteelblue
$outputBoxStatusWindowlabel.Text = 'Progress Status:'
$form.Controls.Add($outputBoxStatusWindowlabel) 

# Output : Status Update
$outputBoxStatusWindow = New-Object System.Windows.Forms.TextBox
$outputBoxStatusWindow.Location = New-Object System.Drawing.Size(110,415) 
$outputBoxStatusWindow.Size = New-Object System.Drawing.Size(250,20) 
$outputBoxStatusWindow.BackColor = [System.Drawing.Color]::lightsteelblue
$outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
$outputBoxStatusWindow.BorderStyle = "None"
$outputBoxStatusWindow.Text = "Awaiting Input..."
$form.Controls.Add($outputBoxStatusWindow) 

# Output : Status Progress Bar
$outputBoxStatusProgress = New-Object System.Windows.Forms.TextBox
$outputBoxStatusProgress.Location = New-Object System.Drawing.Size(22,395) 
$outputBoxStatusProgress.Size = New-Object System.Drawing.Size(220,20) 
$outputBoxStatusProgress.ForeColor = [System.Drawing.Color]::green
$outputBoxStatusProgress.BackColor = [System.Drawing.Color]::lightsteelblue
$outputBoxStatusProgress.BorderStyle = "None"
$form.Controls.Add($outputBoxStatusProgress) 

#################################################################
################### START OF BUTTON LAYOUT ######################
#################################################################

# Note that the Search AD and Search O365 buttons are in the top section (so the tab works)

$ClearButton = New-Object System.Windows.Forms.Button
$ClearButton.Location = New-Object System.Drawing.Size(590,18)
$ClearButton.Size = New-Object System.Drawing.Size(80,25)
$ClearButton.Text = "Reset Form"
$ClearButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$ClearButton.BackColor = [System.Drawing.Color]::Yellow
$ClearButton.ForeColor = [System.Drawing.Color]::Black
$ClearButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$ClearButton.Add_Click{$userInputBox.Clear()}
$ClearButton.Add_Click{$outputBoxDisplayName.Clear()}
$ClearButton.Add_Click{$outputBoxAliasName.Clear()}
$ClearButton.Add_Click{$outputBoxSamAccountName.Clear()}
$ClearButton.Add_Click{$outputBoxLastLogon.Clear()}
$ClearButton.Add_Click{$outputBoxPasswordLastSet.Clear()}
$ClearButton.Add_Click{$outputBoxPasswordLastSet.ReadOnly = $true}
$ClearButton.Add_Click{$outputBoxWhenCreated.Clear()}
$ClearButton.Add_Click{$outputBoxUserPrincipalName.Clear()}
$ClearButton.Add_Click{$outputBoxMail.Clear()}
$ClearButton.Add_Click{$outputBoxCanonicalName.Clear()}
$ClearButton.Add_Click{$outputBoxEnabled.Checked=$false}
$ClearButton.Add_Click{$outputBoxLocked.Checked=$false}
$ClearButton.Add_Click{$outputBoxGroupMemberships.Clear()}
$ClearButton.Add_Click{$outputBoxHomeDirectory.Clear()}
$ClearButton.Add_Click{$outputBoxLogOnTo.Clear()}
$ClearButton.Add_Click{$outputBoxChangePasswordNextLogon.Clear()}
$ClearButton.Add_Click{$outputBoxStatusWindow.ForeColor = [System.Drawing.Color]::green
                       $outputBoxStatusWindow.BorderStyle = "None"
                       $outputBoxStatusWindow.Text = "Awaiting Input..."}
$ClearButton.Add_Click{$outputBoxStatusProgress.Clear()}
$Form.Controls.Add($ClearButton)

$CancelImageButton = New-Object System.Windows.Forms.Button
$CancelImageButton.Location = New-Object System.Drawing.Point(665,390)
$CancelImageButton.Text = "Exit" 
$CancelImageButton.Size = New-Object System.Drawing.Size(40,40)
$CancelImageButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$CancelImageButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$CancelImageButton.ForeColor = [System.Drawing.Color]::White
$CancelImageButton.BackColor = [System.Drawing.Color]::DarkRed
$CancelImageButton.Add_Click{ClearSessions}
$form.CancelButton = $CancelImageButton
$form.Controls.Add($CancelImageButton)

#################################################################
################### INITIALIZING THE FORM #######################
#################################################################

[void] $Form.ShowDialog() 
$Form.Add_Shown({$Form.Activate()})
clearFormAD 