# This script will parse through all emails in a particular folder in OUTLOOK.
# It can be modified to search through the folder and extract all text/pattern matches using REGEX.
# In this example it's looking for unique email addresses inside email message body in a folder called 'Test'
# OUTLOOK needs to be running, and this needs to be ran as a NORMAL user, not admin/elevated.

$ErrorActionPreference = 'SilentlyContinue'

####################################################################################
## CHECKING THAT ADMINISTRATIVE RIGHTS ARE *NOT* BEING USED TO RUN THE SCRIPT
####################################################################################

Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$adminStatus = Test-Administrator

If($adminStatus){
    Write-Host "`n**************************** IMPORTANT ****************************`nTHIS DOES NOT WORK IF RAN AS ADMINISTRATOR - RUN AS NORMAL USER`n=> Outlook needs to be running and logged in for this to work! <=`n**************************** IMPORTANT ****************************`n" 
} Else {

        #Add-Type -assembly "Microsoft.Office.Interop.Outlook"
        $olFolderInbox = ""
        $outlook = ""
        $nameSpace = ""
        $inbox = ""
        $messages = ""
        $message = ""
        $emailMessageBody = ""
        $emailAddressFound = ""
        $overallNumberEmailAddress = @()
        $overallEmailAddressList = @()
        $overallNumberEmailAddressSplitArray = @()

############################################################################
# Need to provide the NAME of the folder to parse.
# IF POSSIBLE, have the folder directly UNDER the Inbox folder
############################################################################

        $dateBefore = get-date -format HH:mm:ss
        $folder = "Test"
        $olFolderInbox = "6" # 6 = inbox?
        $outlook = new-object -com outlook.application
        $nameSpace = $outlook.GetNameSpace("MAPI")
        $inbox = $namespace.GetDefaultFolder($olFolderInbox)
        $messages = $inbox.folders | Where name -eq $folder | select -ExcludeProperty items
        Write-Host "There are currently" $messages.items.count "emails in the selected $Folder directory`nParsing through the email content for unique email addresses (this may take a while... coffee?)`n"

        foreach($message in $messages.items)
        {

####################################################################################
# This is where you can enter the REGEX expression you require to parse the details
####################################################################################

                $emailMessageBody = $message.body    
                $regex = "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" # Looks for any 'email' address format
                
                $overallEmailAddressList += (Select-String -InputObject $emailMessageBody -Pattern $regex -AllMatches).Matches.Value # Returns the email address (value) from the pattern match
                $overallEmailAddressList += "`n"
        }

        Write-Host "[SUCCESS] Messages have been parsed - looking for unique email addresses now (Be patient, young grasshopper)"

        # Remove duplicate email addresses from the list, convert ALL to lowercase to make sure matches are found
        $overallNumberEmailAddressSplitArray = $overallEmailAddressList -split "`r?`n"
        $overallNumberEmailAddress = $overallNumberEmailAddressSplitArray.ToLower() | select -unique | Sort-Object
    
        $dateafter = get-date -format HH:mm:ss
        Write-Host "[RESULTS] The following unique email addresses have been found:`n"
        $overallNumberEmailAddress
        Write-Host "`nKEEP CALM AND CARRY ON...`nTime Taken To Finish: $dateBefore - $dateAfter`nTotal Emails Checked:"$messages.items.count""

}