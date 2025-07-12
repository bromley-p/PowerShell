$strReference = ""
$strDifference = ""
$ResultIdentical = ""
$ResultDifferent = ""

$file1 = "C:\temp\file1.txt"
$file2 = "C:\temp\file2.txt"

$strReference = Get-Content $file1
$strDifference = Get-Content $file2

Write-Host "`n****** SETTINGS ******`n`nThis is comparing the following files (you can edit the file name / location in the script)`nFile 1: $file1`nFile 2: $file2"

$ResultIdentical = Compare-Object $strReference $strDifference -IncludeEqual -ExcludeDifferent -PassThru
$ResultDifference =  Compare-Object $strReference $strDifference -PassThru

$identical = "`nIdentical Content Detected:"
$differences = "`nDifferences Detected:"
Write-Output $identical $ResultIdentical $differences $ResultDifference