# ValidateCredentialsPerDomain.ps1

[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement")

# Sending passwords from the browser to the web server over HTTPS is standard practice. The password is encrypted by virtue of HTTPS as it is sent. 

$domain = ""
$confirmDomain = ""
$credentials = ""
$userNameValidation = ""
$tempPasswordValidation = ""
$principalContext = ""
$validateUser = ""

# Prompt the user to enter the domain that you are verifying against, or use the one detected...

[String]$domain = $env:USERDNSDOMAIN
$confirmDomain = Read-Host -Prompt "`n`nType the FULL domain name to check against i.e testdomain.ca or leave blank to use the default detected domain of $domain"

If($confirmDomain) {
    $domain = $confirmDomain
    Write-Host "The domain being checked against is $confirmDomain`n`n"
}
Else {
    Write-Host "The domain being checked against is $domain`n`n"
}

# Prompt the user to enter the credentials that they want to verify

$credentials = Get-Credential
$userNameValidation = $Credentials.UserName
$tempPasswordValidation = $Credentials.GetNetworkCredential().Password

# Check the username / password credentials against the domain chosen

$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain,$domain)
$validateUser = $principalContext.ValidateCredentials($userNameValidation,$tempPasswordValidation)

# Return the result

If($validateUser -eq $True){
    Write-Host "`n`nCredentials verified"
    $passedVerification = $True
} elseIf($validateUser -eq $False){
    Write-Host "Credentials are incorrect"
    $passedVerification = $False
} else {
    $passedVerification = $False
}

Write-Host "Result: $passedVerification"

# Clear the stored credentials from being used outside of the script

$domain = ""
$confirmDomain = ""
$credentials = ""
$userNameValidation = ""
$tempPasswordValidation = ""