[CmdletBinding()]
Param (
    [Parameter()]
    [string]$CustomField
)

###################################################################################################
#
# 1. Checks if Windows Update is enabled (option to fix)
# 2. Checks if Windows Defender is enabled/Primary (option to enable)
# 3. Checks if Windows Defender signatures are up to date (option to update)
# 4. Checks .Net Framework 4.8+ (option to update)
# 5. Checks for new Windows Updates (opens Windows Update window)
# 6. Check for any Pending Windows Updates
# 7. Check Windows Firewall is enabled (option to enable)
# 8. Check Firewall Profiles (option to enable)
# 9. Check Windows Firewall Rules (option to save copy)
# 10. Check Windows 11 Compatibility (option to skip)
# 11. Install Windows 11 Bypass Registry Hacks (option to skip)
#
# Gathers and displays all results on screen (option to save to file)
#
###################################################################################################

$ErrorActionPreference = 'SilentlyContinue'

$serviceNameWindowsDefender = "windefend"
$serviceNameWindowsFirewall = "mpssvc"
$serviceNameWindowsUpdate = "wuauserv"

$adminStatus = ""
$computerName = ""
$currentFirewallVersionDetails = ""
$currentFirewallVersionDetailsFinal = ""
$currentFirewallVersionIndividualProfiles = ""
$currentVersionNumbers = ""
$dateFile = get-date -format yyyyMMdd_hh.mm.ss
$differentFirewallFinalVersion = ""
$differentFirewallIndividualProfiles = ""
$differentFirewallVersion = ""
$differentFirewallVersionName = ""
$differentVersion = ""
$enableWindowsDefenderAntivirus = ""
$enableWindowsDefenderSignatureUpdate = ""
$enableWindowsFirewall = ""
$enableWindowsFirewallProfile = ""
$enableWindowsUpdate = ""
$getNETFrameworkDetails = ""
$microsoftUpdateDownloadedResultList = ""
$microsoftUpdateWaitingResultList = ""
$nameOfFile = ""
$netFrameworkDownloadPrompt = ""
$NetVersionResult = ""
$networkConnectionTest = ""
$pathFile = ""
$profileResults = ""
$saveToFilePrompt = ""
$startWindowsFirewall = ""
$startWindowsFirewallRecheck = ""
$startWindowsUpdate = ""
$startWindowsUpdateRecheck = ""
$systemDetailsOverall = ""
$updateResults = ""
$updates = ""
$updatesAlreadyDownloaded = ""
$updatesCount = ""
$updatesName = ""
$checkForWindowsUpdateAvailable = ""
$updatesWaitingDownload = ""
$windowsDefenderAntivirusStatus = ""
$windowsDefenderCheckRunningStatus = ""
$windowsDefenderCheckRunningStatusUpdated = ""
$windowsDefenderCheckStartupType = ""
$windowsDefenderCheckStartupTypeUpdated = ""
$windowsDefenderEnabledCheck = ""
$windowsDefenderEnabledCheckSignature = ""
$windowsDefenderEnabledCheckUpdated = ""
$windowsDefenderMPPreferenceUpdated = ""
$windowsDefenderSignatureResult = ""
$windowsDefenderSignatureText = ""
$windowsFirewallCheckRunningStatus = ""
$windowsFirewallCheckRunningStatusUpdated = ""
$windowsFirewallCheckStartupType = ""
$windowsFirewallCheckStartupTypeUpdated = ""
$windowsFirewallStatus = ""
$windowsFirewallStatusDetails = ""
$windowsFirewallTypeCheck = ""
$windowsFirewallTypeFinalCheck = ""
$windowsFirewallTypeReCheck = ""
$windowsUpdateCheckRunningStatus = ""
$windowsUpdateCheckRunningStatusUpdated = ""
$windowsUpdateCheckStartupType = ""
$windowsUpdateCheckStartupTypeUpdated = ""
$winVER = ""
$global:WINCOMPATIBLERESULT = ""
$global:WINVERFUNCTION = ""
$windows11CompatibilityCheck = ""
$windows11BypassCompatibilityCheck = ""
$windows11RegistryUpgrade = ""
$testExternalInternet = ""
$networkAdapterAddressForReport = ""
$domainORWorkgroupForReport = ""
$systemNameForReport = ""
$networkIPConfiguration = ""
$userConfirmedWIN11BypassOption = ""
$bitlockerOSDriveStatus = ""
$productKeyInfo = ""
$retrieveFirewallRules = ""
$firewallRules = ""
$getLocalFirewallRules = ""

####################################################################################
## FUNCTION - GATHER THE SYSTEM INFORMATION - SCRIPT FROM NINJAONE.COM
####################################################################################

Function Win11Requirements {

Begin {

    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }
    Function Get-HardwareReadiness() {
        # Modified copy of https://aka.ms/HWReadinessScript minus the signature, as of 7/26/2023.
        # Only modification was replacing Get-WmiObject with Get-CimInstance for PowerShell 7 compatibility
        # Source Microsoft article: https://techcommunity.microsoft.com/t5/microsoft-endpoint-manager-blog/understanding-readiness-for-windows-11-with-microsoft-endpoint/ba-p/2770866

        #=============================================================================================================================
        #
        # Script Name:     HardwareReadiness.ps1
        # Description:     Verifies the hardware compliance. Return code 0 for success. 
        #                  In case of failure, returns non zero error code along with error message.

        # This script is not supported under any Microsoft standard support program or service and is distributed under the MIT license

        # Copyright (C) 2021 Microsoft Corporation

        # Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
        # files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
        # modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
        # is furnished to do so, subject to the following conditions:

        # The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

        # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
        # WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
        # COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
        # ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        #=============================================================================================================================

        $exitCode = 0

        [int]$MinOSDiskSizeGB = 64
        [int]$MinMemoryGB = 4
        [Uint32]$MinClockSpeedMHz = 1000
        [Uint32]$MinLogicalCores = 2
        [Uint16]$RequiredAddressWidth = 64

        $PASS_STRING = "[PASS]"
        $FAIL_STRING = "[FAIL]"
        $FAILED_TO_RUN_STRING = "FAILED TO RUN"
        $UNDETERMINED_CAPS_STRING = "UNDETERMINED - You need to run this as Administator (Elevated)"
        $UNDETERMINED_STRING = "Undetermined"
        $CAPABLE_STRING = "Capable"
        $NOT_CAPABLE_STRING = "Not capable"
        $CAPABLE_CAPS_STRING = "[PASS] $env:computerName supports Windows 11 24H2"
        $NOT_CAPABLE_CAPS_STRING = "[FAIL] $env:computerName will NOT run Windows 11 24H2"
        $STORAGE_STRING = "DiskSize"
        $OS_DISK_SIZE_STRING = "OSDiskSize"
        $global:memory_STRING = "Memory"
        $SYSTEM_MEMORY_STRING = "System_Memory"
        $GB_UNIT_STRING = "GB"
        $global:tpm_STRING = "TPM"
        $global:tpm_VERSION_STRING = "TPMVersion"
        $PROCESSOR_STRING = "Processor"
        $SECUREBOOT_STRING = "SecureBoot"
        $I7_7820HQ_CPU_STRING = "i7-7820hq CPU"
        $global:WINVERFUNCTION = ""
        $global:CURRENT_VERSION_WINDOWS = ""
        $global:WINCOMPATIBLERESULT = ""
        $global:OfferRegistryBypass = $false
        $global:OVERALLCOMPATIBLERESULTS = ""
        $cpuSpecification = ""
        $ramSpecification = ""
        $driveSpaceSpecification = ""
        $tpmVersionSpecification = ""
        $global:tpmSTATUS = ""
        $global:UEFIenabled = ""

        # 0=name of check, 1=attribute checked, 2=value, 3=PASS/FAIL/UNDETERMINED
        $logFormat = '{0}: {1}={2}. {3}; '

        # 0=name of check, 1=attribute checked, 2=value, 3=unit of the value, 4=PASS/FAIL/UNDETERMINED
        $logFormatWithUnit = '{0}: {1}={2}{3}. {4}; '

        # 0=name of check.
        $logFormatReturnReason = '{0}, '

        # 0=exception.
        $logFormatException = '{0}; '

        # 0=name of check, 1= attribute checked and its value, 2=PASS/FAIL/UNDETERMINED
        $logFormatWithBlob = '{0}: {1}. {2}; '

        # return returnCode is -1 when an exception is thrown. 1 if the value does not meet requirements. 0 if successful. -2 default, script didn't run.
        $outObject = @{ returnCode = -2; returnResult = $FAILED_TO_RUN_STRING; returnReason = ""; logging = "" }

        # NOT CAPABLE(1) state takes precedence over UNDETERMINED(-1) state
        function Private:UpdateReturnCode {
            param(
                [Parameter(Mandatory = $true)]
                [ValidateRange(-2, 1)]
                [int] $ReturnCode
            )

            Switch ($ReturnCode) {

                0 {
                    if ($outObject.returnCode -eq -2) {
                        $outObject.returnCode = $ReturnCode
                    }
                }
                1 {
                    $outObject.returnCode = $ReturnCode
                }
                -1 {
                    if ($outObject.returnCode -ne 1) {
                        $outObject.returnCode = $ReturnCode
                    }
                }
            }
        }

        $Source = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            if (cpuFamily >= 6 && cpuModel <= 95 && !(cpuFamily == 6 && cpuModel == 85))
                            {
                                cpuFamilyResult.IsValid = false;
                                cpuFamilyResult.Message = "";
                            }
                            else if (cpuFamily == 6 && (cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                            {
                                string registryName = "Platform Specific Field 1";
                                int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);

                                if ((cpuModel == 142 && registryValue != 16) || (cpuModel == 158 && registryValue != 8))
                                {
                                    cpuFamilyResult.IsValid = false;
                                }
                                cpuFamilyResult.Message = "PlatformId " + registryValue;
                            }
                        }
                        catch (Exception ex)
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "Exception:" + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@

        # Storage
        try {
            $osDrive = Get-CimInstance -Class Win32_OperatingSystem | Select-Object -Property SystemDrive
            $global:osDriveSize = Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }  

            if ($null -eq $global:osDriveSize) {
                UpdateReturnCode -ReturnCode 1
                $outObject.returnReason += $logFormatReturnReason -f $STORAGE_STRING
                $outObject.logging += $logFormatWithBlob -f $STORAGE_STRING, "Storage is null", $FAIL_STRING
                $exitCode = 1
            }
            elseif ($global:osDriveSize.SizeGB -lt $MinOSDiskSizeGB) {
                UpdateReturnCode -ReturnCode 1
                $outObject.returnReason += $logFormatReturnReason -f $STORAGE_STRING
                $outObject.logging += $logFormatWithUnit -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, ($global:osDriveSize.SizeGB), $GB_UNIT_STRING, $FAIL_STRING
                $exitCode = 1
            }
            else {
                $outObject.logging += $logFormatWithUnit -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, ($global:osDriveSize.SizeGB), $GB_UNIT_STRING, $PASS_STRING
                UpdateReturnCode -ReturnCode 0
            }
        }
        catch {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormat -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
        }

        # Memory (bytes)
        try {
            $global:memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object @{Name = "SizeGB"; Expression = { $_.Sum / 1GB -as [int] } }

            if ($null -eq $global:memory) {
                UpdateReturnCode -ReturnCode 1
                $outObject.returnReason += $logFormatReturnReason -f $global:memory_STRING
                $outObject.logging += $logFormatWithBlob -f $global:memory_STRING, "Memory is null", $FAIL_STRING
                $exitCode = 1
            }
            elseif ($global:memory.SizeGB -lt $MinMemoryGB) {
                UpdateReturnCode -ReturnCode 1
                $outObject.returnReason += $logFormatReturnReason -f $global:memory_STRING
                $outObject.logging += $logFormatWithUnit -f $global:memory_STRING, $SYSTEM_MEMORY_STRING, ($global:memory.SizeGB), $GB_UNIT_STRING, $FAIL_STRING
                $exitCode = 1
            }
            else {
                $outObject.logging += $logFormatWithUnit -f $global:memory_STRING, $SYSTEM_MEMORY_STRING, ($global:memory.SizeGB), $GB_UNIT_STRING, $PASS_STRING
                UpdateReturnCode -ReturnCode 0
            }
        }
        catch {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormat -f $global:memory_STRING, $SYSTEM_MEMORY_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
        }

        # TPM
        try {
            $global:tpm = Get-Tpm

            if ($null -eq $global:tpm) {
                UpdateReturnCode -ReturnCode 1
                $outObject.returnReason += $logFormatReturnReason -f $global:tpm_STRING
                $outObject.logging += $logFormatWithBlob -f $global:tpm_STRING, "TPM is null", $FAIL_STRING
                $exitCode = 1
            }
            elseif ($global:tpm.TpmPresent) {
                $global:tpmVersion = Get-CimInstance -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm | Select-Object -Property SpecVersion

                if ($null -eq $global:tpmVersion.SpecVersion) {
                    UpdateReturnCode -ReturnCode 1
                    $outObject.returnReason += $logFormatReturnReason -f $global:tpm_STRING
                    $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, "null", $FAIL_STRING
                    $exitCode = 1
                }

                $global:majorVersion = $global:tpmVersion.SpecVersion.Split(",")[0] -as [int]
                if ($global:majorVersion -lt 2) {
                    UpdateReturnCode -ReturnCode 1
                    $outObject.returnReason += $logFormatReturnReason -f $global:tpm_STRING
                    $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, ($global:tpmVersion.SpecVersion), $FAIL_STRING
                    $exitCode = 1
                }
                else {
                    $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, ($global:tpmVersion.SpecVersion), $PASS_STRING
                    UpdateReturnCode -ReturnCode 0
                }
            }
            else {
                if ($global:tpm.GetType().Name -eq "String") {
                    UpdateReturnCode -ReturnCode -1
                    $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
                    $outObject.logging += $logFormatException -f $global:tpm
                }
                else {
                    UpdateReturnCode -ReturnCode 1
                    $outObject.returnReason += $logFormatReturnReason -f $global:tpm_STRING
                    $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, ($global:tpm.TpmPresent), $FAIL_STRING
                }
                $exitCode = 1
            }
        }
        catch {
            UpdateReturnCode -ReturnCode -1
            $outObject.returnReason += $logFormatReturnReason -f $global:tpm_STRING
            #$outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormat -f $global:tpm_STRING, $global:tpm_VERSION_STRING, ($global:tpm.TpmPresent), $FAIL_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
            $global:tpmSTATUS = "No TPM Detected"
        }

        # CPU Details
        try {
            $global:cpuDetails = @(Get-CimInstance -Class Win32_Processor)[0]

            if ($null -eq $global:cpuDetails) {
                UpdateReturnCode -ReturnCode 1
                $exitCode = 1
                $outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
                $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, "CpuDetails is null", $FAIL_STRING
            }
            else {
                $processorCheckFailed = $false

                # AddressWidth
                if ($null -eq $global:cpuDetails.AddressWidth -or $global:cpuDetails.AddressWidth -ne $RequiredAddressWidth) {
                    UpdateReturnCode -ReturnCode 1
                    $processorCheckFailed = $true
                    $exitCode = 1
                }

                # ClockSpeed is in MHz
                if ($null -eq $global:cpuDetails.MaxClockSpeed -or $global:cpuDetails.MaxClockSpeed -le $MinClockSpeedMHz) {
                    UpdateReturnCode -ReturnCode 1;
                    $processorCheckFailed = $true
                    $exitCode = 1
                }

                # Number of Logical Cores
                if ($null -eq $global:cpuDetails.NumberOfLogicalProcessors -or $global:cpuDetails.NumberOfLogicalProcessors -lt $MinLogicalCores) {
                    UpdateReturnCode -ReturnCode 1
                    $processorCheckFailed = $true
                    $exitCode = 1
                }

                # CPU Family
                Add-Type -TypeDefinition $Source
                $cpuFamilyResult = [CpuFamily]::Validate([String]$global:cpuDetails.Manufacturer, [uint16]$global:cpuDetails.Architecture)

                $global:cpuDetailsLog = "{AddressWidth=$($global:cpuDetails.AddressWidth); MaxClockSpeed=$($global:cpuDetails.MaxClockSpeed); NumberOfLogicalCores=$($global:cpuDetails.NumberOfLogicalProcessors); Manufacturer=$($global:cpuDetails.Manufacturer); Caption=$($global:cpuDetails.Caption); $($cpuFamilyResult.Message)}"

                if (!$cpuFamilyResult.IsValid) {
                    UpdateReturnCode -ReturnCode 1
                    $processorCheckFailed = $true
                    $exitCode = 1
                }

                if ($processorCheckFailed) {
                    $outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
                    $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($global:cpuDetailsLog), $FAIL_STRING
                }
                else {
                    $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($global:cpuDetailsLog), $PASS_STRING
                    UpdateReturnCode -ReturnCode 0
                }
            }
        }
        catch {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormat -f $PROCESSOR_STRING, $PROCESSOR_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
        }

        # SecureBoot
        try {
            $isSecureBootEnabled = Confirm-SecureBootUEFI
            $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $CAPABLE_STRING, $PASS_STRING
            UpdateReturnCode -ReturnCode 0
        }
        catch [System.PlatformNotSupportedException] {
            # PlatformNotSupportedException "Cmdlet not supported on this platform." - SecureBoot is not supported or is non-UEFI computer.
            UpdateReturnCode -ReturnCode 1
            $outObject.returnReason += $logFormatReturnReason -f $SECUREBOOT_STRING
            $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $NOT_CAPABLE_STRING, $FAIL_STRING
            $exitCode = 1
        }
        catch [System.UnauthorizedAccessException] {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
        }
        catch {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
            $exitCode = 1
            WRITE-HOST "NO SECURE BOOT FOUND"
        }

        # i7-7820hq CPU
        try {
            $supportedDevices = @('surface studio 2', 'precision 5520')
            $systemInfo = @(Get-CimInstance -Class Win32_ComputerSystem)[0]

            if ($null -ne $global:cpuDetails) {
                if ($global:cpuDetails.Name -match 'i7-7820hq cpu @ 2.90ghz') {
                    $modelOrSKUCheckLog = $systemInfo.Model.Trim()
                    if ($supportedDevices -contains $modelOrSKUCheckLog) {
                        $outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $modelOrSKUCheckLog, $PASS_STRING
                        $outObject.returnCode = 0
                        $exitCode = 0
                    }
                }
            }
        }
        catch {
            if ($outObject.returnCode -ne 0) {
                UpdateReturnCode -ReturnCode -1
                $outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
                $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
                $exitCode = 1
            }
        }

        Switch ($outObject.returnCode) {

            0 { $outObject.returnResult = $CAPABLE_CAPS_STRING }
            1 { $outObject.returnResult = $NOT_CAPABLE_CAPS_STRING
                $global:OfferRegistryBypass = $true}
            -1 { $outObject.returnResult = $UNDETERMINED_CAPS_STRING }
            -2 { $outObject.returnResult = $FAILED_TO_RUN_STRING }
        }

        $outObject | ConvertTo-Json -Compress
    }
}
process {
    $Result = Get-HardwareReadiness | Select-Object -Unique | ConvertFrom-Json

    if ($CustomField -and -not [string]::IsNullOrEmpty($CustomField) -and -not [string]::IsNullOrWhiteSpace($CustomField)) {
        Switch ($Result.returnCode) {
            0 { Ninja-Property-Set -Name $CustomField -Value "Capable" 
                $global:OfferRegistryBypass = $false}
            1 { Ninja-Property-Set -Name $CustomField -Value "Not Capable" 
                $global:OfferRegistryBypass = $true}
            -1 { Ninja-Property-Set -Name $CustomField -Value "Undetermined" }
            -2 { Ninja-Property-Set -Name $CustomField -Value "Failed To Run" }
            default { Ninja-Property-Set -Name $CustomField -Value "Unknown" }
        }
    }

    # Print Return Result
    $giveDesc = $($Result.returnReason)
    If($giveDesc)
    {
       $global:returnReason = $giveDesc 
    } Else {
        $global:returnReason = "No Issues detected! KEEP CALM AND CARRY ON..."
    }

        ####################################################################################
        ## GET THE CURRENT VERSION OF WINDOWS THAT IS INSTALLED ON THE MACHINE
        ####################################################################################

        $global:UEFIenabled = $env:firmware_type
        $cpuSpecification = "CPU Type:`t"+$global:cpuDetails.name + "`nCPU Speed:`t"+$global:cpuDetails.MaxClockSpeed
        $ramSpecification = "RAM Size:`t"+$global:memory.SizeGB+"GB"
        $driveSpaceSpecification = "Disk Size:`t"+$global:osDriveSize.SizeGB+"GB"

        #If($global:majorVersion -eq "")
        If([string]::IsNullOrWhitespace($global:majorVersion))
        {
            $global:majorversion = "N/A"
        }

        # Detect if TPM is present / enabled

        If($global:tpmSTATUS -ne "No TPM Detected"){

            $global:tpmSTATUS = $global:tpm.TpmPresent
        }

        $tpmVersionSpecification = "TPM Status:`t"+$global:tpmSTATUS + " - TPM Version: "+$global:majorVersion

        $global:CURRENT_VERSION_WINDOWS = Get-ComputerInfo | Select-Object OSName,OSDisplayVersion,OsArchitecture,CsProcessors,CsNumberOfLogicalProcessors,WindowsProductName 
        $windowsProductNameOriginal = $global:CURRENT_VERSION_WINDOWS.WindowsProductName 
        $global:WINVERFUNCTION = "[$windowsProductNameOriginal]" + " " + $global:CURRENT_VERSION_WINDOWS.OSName + " " + $global:CURRENT_VERSION_WINDOWS.OSDisplayVersion + " " + $global:CURRENT_VERSION_WINDOWS.OsArchitecture
        $global:WINCOMPATIBLERESULT = $($Result.returnResult)
        If($global:WINCOMPATIBLERESULT -match 'FAIL'){
            Write-Host "`n[$env:COMPUTERNAME] DOES NOT MEET THE REQUIREMENTS FOR WINDOWS 11 24H2" -ForegroundColor RED
        }elseIf($global:WINCOMPATIBLERESULT -match 'PASS'){
            Write-Host "`n[$env:COMPUTERNAME] MEETS THE REQUIREMENTS FOR WINDOWS 11 24H2" -ForegroundColor GREEN
        }else{}

        $global:OVERALLCOMPATIBLERESULTS = "Results:`t$global:WINCOMPATIBLERESULT`nReasons:`t$global:returnReason`nBase OS:`t$global:WINVERFUNCTION`n`nBIOS Mode:`t$global:UEFIenabled`n$driveSpaceSpecification`n$tpmVersionSpecification`n$cpuSpecification`n$ramSpecification" 
        Write-Host $global:OVERALLCOMPATIBLERESULTS
  }
  End {    
 }
}

####################################################################################
## FUNCTION - CHECKING THAT ADMINISTRATIVE RIGHTS ARE BEING USED TO RUN THE SCRIPT
####################################################################################

# For Restarting Services (SECTION 5) the script must be ran under elevated credentials. 
# NOTE: If using the task scheduler to run this script, make sure to choose SYSTEM as the Run-As context

Function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

$adminStatus = Test-Administrator

# Checks if the script is being ran with administrator elevated, otherwise errors will occur
if($adminStatus -eq $false){
      Write-Host "`n***********************************************************`nWARNING: You are not running script as an elevated user,`nwhich is required for Windows Update checks and registry entries.`nPlease re-run this script as administrator`n***********************************************************"
} Else {

        ###########################################################
        # WINDOWS UPDATE DETAILS
        ###########################################################

        Write-Host "`n********* WINDOWS UPDATE SERVICE DETAILS *********`n" -ForegroundColor GREEN

        $windowsUpdateCheckStartupType = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).StartType  # Get the startup type of the service
        $windowsUpdateCheckRunningStatus = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).Status  # Get the current running status of the service

        if (($windowsUpdateCheckStartupType -eq "Manual") -OR ($windowsUpdateCheckStartupType -eq "Automatic") -OR ($windowsUpdateCheckStartupType -eq "AutomaticDelayedStart")) {

            Write-Host "[PASS] Windows Update is currently set to $windowsUpdateCheckStartupType and the current status is $windowsUpdateCheckRunningStatus... All good!"
        }
        elseIf ($windowsUpdateCheckStartupType -eq "Disabled") {
                Write-Host "WARNING - The Windows Update service is $windowsUpdateCheckStartupType"
                $enableWindowsUpdate = ""
                $enableWindowsUpdate = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Update service? (Y or N)"
                if($enableWindowsUpdate -eq "Y")
                {
                    Write-Host "Attempting to enable the Windows Update service...."
                    Try {
                        Set-Service -Name $serviceNameWindowsUpdate -StartupType Manual -Status Running
                        Start-Sleep -Seconds 5
                        $windowsUpdateCheckStartupTypeUpdated = ""
                        $windowsUpdateCheckRunningStatusUpdated = ""

                        $windowsUpdateCheckStartupTypeUpdated = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).StartType  # Get the startup type of the service
                        $windowsUpdateCheckRunningStatusUpdated = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).Status  # Get the current running status of the service
            
                        if(($windowsUpdateCheckRunningStatusUpdated -eq "Manual") -AND ($windowsUpdateCheckRunningStatusUpdated -ne "Running")) {
                            Write-Host "The Windows Update service is now set to $windowsUpdateCheckStartupTypeUpdated `nThe current running Status is $windowsUpdateCheckRunningStatusUpdated`n"
                            $startWindowsUpdate = ""
                            $startWindowsUpdate = Read-Host -Prompt "QUESTION: Would you like to start the Windows Update service? (Y or N)"
                            if($startWindowsUpdate -eq "Y")
                            {
                                Write-Host "Attempting to start the Windows Update service..."
                                Try {
                                    Start-Service $serviceNameWindowsUpdate
                                    Start-Sleep -Seconds 5
                                    $startWindowsUpdateRecheck = ""
                                    $startWindowsUpdateRecheck = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).Status  # Get the current running status of the service

                                    if($startWindowsUpdateRecheck -eq "Running") {
                                        Write-Host "SUCCESS... The Windows Update service is now running and set to Manual (Recommended)!"
                                    }
                                    else {
                                        Write-Host "[FAIL] Mmmm... For some reason the Update service hasn't started running... Please manually check"
                                    }
                                }
                                catch {
                                    Write-Host "Unable to start the Windows Update service because: $_"
                                }
                            }
                            elseif($startWindowsUpdate -eq "N")
                            {
                                Write-Host "You entered NO... Continuing to next step"
                                Start-Sleep -s 2
                            }
                            else
                            {
                                Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                            } 
                        } 
                        elseIf($windowsUpdateCheckRunningStatusUpdated -eq "Running") { 
                            Write-Host "SUCCESS... The Windows Update service is now running!"
                        }
                        else {
                        Write-Host "Getting to HERE... $windowsUpdateCheckRunningStatusUpdated"}
                    }
                    Catch{
                        Write-Host "Unable to change the Windows Update service because: $_"
                    }
                }
                elseif($enableWindowsUpdate -eq "N")
                {
                    Write-Host "You entered NO... Continuing to next step"
                    Start-Sleep -s 2
                }
                else
                {
                    Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                }  
        }
        else {}

        $windowsUpdateCheckStartupType = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).StartType  # Get the startup type of the service
        $windowsUpdateCheckRunningStatus = (Get-Service -Name $serviceNameWindowsUpdate -ErrorAction Stop).Status  # Get the current running status of the service


        ###########################################################
        # WINDOWS DEFENDER DETAILS
        ###########################################################

        Write-Host "`n********* WINDOWS DEFENDER DETAILS *********`n" -ForegroundColor GREEN

        $windowsDefenderCheckStartupType = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).StartType  # Get the startup type of the service
        $windowsDefenderCheckRunningStatus = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).Status  # Get the current running status of the service

        # Next we need to check if the following are running and give option to enable them...

        $windowsDefenderEnabledCheck = Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue
        $windowsDefenderMPPreference = ""
        $windowsDefenderMPPreference = Get-MpPreference | Select-Object -Property DisableRemovableDriveScanning -ErrorAction SilentlyContinue

        ##########################################################
        # GET CURRENT STATUS OF ALL WINDOWS DEFENDER SERVICES
        ##########################################################

         # Get the CURRENT status of the Windows defender services
                        $windowsDefenderDetectedCheck = ""
                        $windowsDefenderAntivirusStatus = ""
                        If($windowsDefenderEnabledCheck.AntivirusEnabled -eq $true) {
                           $windowsDefenderAntivirusStatus = "Enabled"
                           $windowsDefenderDetectedCheck = $true 
                        }
                        else {
                           $windowsDefenderAntivirusStatus = "DISABLED"
                        }
                
                        $windowsDefenderRealTimeProtectionStatus = ""
                        If($windowsDefenderEnabledCheck.RealTimeProtectionEnabled -eq $true) {
                           $windowsDefenderRealTimeProtectionStatus = "Enabled"
                           $windowsDefenderDetectedCheck = $true
                        }
                        else {
                           $windowsDefenderRealTimeProtectionStatus = "DISABLED"
                        }

                        $windowsDefenderTamperProtectionStatus = ""
                        If($windowsDefenderEnabledCheck.IsTamperProtected -eq $true) {
                           $windowsDefenderTamperProtectionStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderTamperProtectionStatus = "DISABLED"
                        }

                        $windowsDefenderRemovableScanStatus = ""
                        If($windowsDefenderMPPreference.DisableRemovableDriveScanning -eq $false) {
                           $windowsDefenderRemovableScanStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderRemovableScanStatus = "DISABLED"
                        }

        If($windowsDefenderDetectedCheck) { # If Windows Defender is detected to be running then can skip the configuration section
            Write-Host "[PASS] Windows Defender Antivirus / Realtime Protection is already RUNNING"
            Write-Host "`n* Windows Defender Service is $windowsDefenderCheckStartupType and $windowsDefenderCheckRunningStatus"
            Write-Host "* Windows Defender Antivirus is $windowsDefenderAntivirusStatus`n* Windows Defender Real-Time Protection is $windowsDefenderRealTimeProtectionStatus`n* Windows Defender Tamper Protection is $windowsDefenderTamperProtectionStatus`n* Windows Defender Removable Drive Scanning is $windowsDefenderRemovableScanStatus"
         
        }
        Else {
         Write-Host ">>> WARNING - WINDOWS DEFENDER NOT RUNNING <<<" -ForegroundColor YELLOW
         Write-Host "Please MANUALLY confirm if you have an Antivirus product already installed and running on this system.`nIf yes, you should SKIP this 'Windows Defender' section.`nThis section is for systems that DO NOT have any Antivirus installed."
 
         $windowsDefenderContinueInstall = ""
         $windowsDefenderContinueInstall = Read-Host -Prompt "`nQUESTION: Would you like to CONTINUE the Windows Defender setup section (Please type either Y or N)"
    
            if($windowsDefenderContinueInstall -eq "Y") {
         
                 Write-Host "`n* Windows Defender Service is $windowsDefenderCheckStartupType and $windowsDefenderCheckRunningStatus"
                 Write-Host "* Windows Defender Antivirus is $windowsDefenderAntivirusStatus`n* Windows Defender Real-Time Protection is $windowsDefenderRealTimeProtectionStatus`n* Windows Defender Tamper Protection is $windowsDefenderTamperProtectionStatus`n* Windows Defender Removable Drive Scanning is $windowsDefenderRemovableScanStatus"
                 Write-Host "`n[WINDOWS DEFENDER REGISTRY KEYS]" -ForegroundColor YELLOW
                 Write-Host "You have selected to continue with the Windows Defender configuration.`nBefore attempting to enable Windows Defender, the following Registry keys need setting:`n`n * DisableAntiSpyware (set to false)`n * DisableAntiVirus (set to false)`n * DisableRealtimeMonitoring (set to false)`n * DisableAntiSpyware (set to false)`n * DisableAntiVirus (set to false)`n * DisableBehaviorMonitoring (set to false)`n * DisableOnAccessProtection (set to false)`n * DisableScanOnRealTimeEnable (set to false)`n * DisableRealtimeMonitoring (set to false)`n"
         
                 # If the registry entries for Windows Defender are detected, it will prompt to have them created
                 $changeWindowsDefenderRegistryItems = ""
                 $changeWindowsDefenderRegistryItems = Read-Host -Prompt "QUESTION: Would you like to SET the Windows Defender Registry entries? (Please type either Y or N)"
                        if($changeWindowsDefenderRegistryItems -eq "Y")
                        {
                          Write-Host "Attempting to CREATE the Windows Defender registry entries if missing or set with wrong values...."
                          Try {
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
		                        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

                                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Seconds 2
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
		                        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Seconds 2

                                Write-Host "==> ==> NOTE: You may have to reboot the computer and run the script again at this stage...`n"
                          }
                          Catch{
                                Write-Host "Unable to change the Windows Defender service because: $_"
                          }
                        }
                        elseif($changeWindowsDefenderRegistryItems -eq "N")
                        {
                           Write-Host "You entered NO... Continuing to next step, HOWEVER install of Windows Defender or it's components may fail!`n"
                           Start-Sleep -s 2
                        }
                        else
                        {
                           Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                        }

                        # Write-Host "The Windows Defender Service is currently set to $windowsDefenderCheckStartupType and the current status is $windowsDefenderCheckRunningStatus"
                        # Attempting to set the Startup Type to Automatic

                        if (($windowsDefenderCheckStartupType -eq "Automatic") -OR ($windowsDefenderCheckStartupType -eq "AutomaticDelayedStart")) {

                            Write-Host "[PASS] Windows Defender is currently set to $windowsDefenderCheckStartupType... All good!"
                        }
                        elseIf (($windowsDefenderCheckStartupType -eq "Manual") -OR ($windowsDefenderCheckStartupType -eq "Disabled")) {
                                Write-Host "WARNING - The Windows Defender SERVICE STATE is set to $windowsDefenderCheckStartupType" -Foregroundcolor YELLOW
                                $changeWindowsDefenderAuto = ""
                                $changeWindowsDefenderAuto = Read-Host -Prompt "QUESTION: Would you like to change the Windows Defender service state to Automatic? (Please type either Y or N)"
                                if($changeWindowsDefenderAuto -eq "Y")
                                {
                                    Write-Host "Attempting to change the Windows Defender service to Automatic...."
                                    Try {
                                        Set-Service -Name $serviceNameWindowsDefender -StartupType Automatic #-Status Running
                                        Start-Sleep -Seconds 5
                                    }
                                    Catch{
                                        Write-Host "Unable to change the Windows Defender service because: $_"
                                    }
                                }
                                elseif($changeWindowsDefenderAuto -eq "N")
                                {
                                    Write-Host "You entered NO... Continuing to next step`n"
                                    Start-Sleep -s 2
                                }
                                else
                                {
                                    Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                }  
                        }
                        else {}

                        # Attempting to set the status to running
                        if ($windowsDefenderCheckRunningStatus -eq "Running") {

                            Write-Host "[PASS] Windows Defender is currently set to $windowsDefenderCheckRunningStatus... All good!"
                        }
                        elseIf ($windowsDefenderCheckRunningStatus -ne "Running") {
                                Write-Host "WARNING - The Windows Defender SERVICE STATE is set to $windowsDefenderCheckRunningStatus" -Foregroundcolor YELLOW
                                $changeWindowsDefenderRunningStatus = ""
                                $changeWindowsDefenderRunningStatus = Read-Host -Prompt "QUESTION: Would you like to change the Windows Defender service state to Running? (Please type either Y or N)"
                                if($changeWindowsDefenderRunningStatus -eq "Y")
                                {
                                    Write-Host "Attempting to change the Windows Defender state to Running...."
                                    Try {
                                        Set-Service -Name $serviceNameWindowsDefender -Status Running
                                        Start-service WinDefend
                                        #Start-service WdNisSvc
                                        Start-Sleep -Seconds 5
                                    }
                                    Catch{
                                        Write-Host "Unable to change the Windows Defender state because: $_"
                                    }
                                }
                                elseif($changeWindowsDefenderRunningStatus -eq "N")
                                {
                                    Write-Host "You entered NO... Continuing to next step"
                                    Start-Sleep -s 2
                                }
                                else
                                {
                                    Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                }  
                        }
                        else {} #NOTHING, WE ARE DONE OTHERWISE! 

                        $windowsDefenderRemovableScanStatus = ""
                        If($windowsDefenderMPPreference.DisableRemovableDriveScanning -eq $false) {
                            $windowsDefenderRemovableScanStatus = "True"
                        }
                        else {
                            $windowsDefenderRemovableScanStatus = "False"
                        }

                        Write-Host "`n[CURRENT FEATURE STATUS]`nThe following Windows Defender features are:`nAntivirus Enabled:`t" $windowsDefenderEnabledCheck.AntivirusEnabled "`nAntiMalware Enabled:" $windowsDefenderEnabledCheck.AMServiceEnabled "`nAntiSpyware Enabled:" $windowsDefenderEnabledCheck.AntispywareEnabled "`nReal-Time Enabled:`t" $windowsDefenderEnabledCheck.RealTimeProtectionEnabled "`nTamperProtection On:" $windowsDefenderEnabledCheck.IsTamperProtected "`nRemovableDrive Scan: $windowsDefenderRemovableScanStatus"

                        # Attempt to start the Antivirus Service
                            If($windowsDefenderEnabledCheck.AntivirusEnabled -eq $false) {
                                Write-Host "`nWARNING - The Windows Defender Antivirus SERVICE is NOT RUNNING" -Foregroundcolor YELLOW
                                $enableWindowsDefenderAntivirus = ""
                                $enableWindowsDefenderAntivirus = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Defender Antivirus? (Please type either Y or N)"
                                if($enableWindowsDefenderAntivirus -eq "Y") {
                                            Try {
                                                Write-Host "Attempting to enable the Windows Defender Antivirus"
                                                & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -wdenable
                                                Start-service WinDefend
                                                #Start-service WdNisSvc
                                                Write-Host "[SUCCESS] Windows Defender Antivirus enabled... Continuing"
                                            }
                                            Catch {
                                                Write-Host "Unable to enable the Windows Defender Antivirus because: $_"
                                            }
                                            Start-Sleep -s 5
                                }
                                elseif($enableWindowsDefenderAntivirus -eq "N")
                                {
                                   Write-Host "You entered NO... Continuing to next step"
                                   Start-Sleep -s 2
                                }
                                else
                                {
                                   Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                }  

                            }

                            # Attempt to start the Real-Time Protection Service
                                If($windowsDefenderEnabledCheck.RealTimeProtectionEnabled -eq $false) {
                                    Write-Host "`nWARNING - The Windows Defender Realtime Protection SERVICE is NOT RUNNING" -Foregroundcolor YELLOW
                                    $enableWindowsDefenderRealTimeProtection = ""
                                    $enableWindowsDefenderRealTimeProtection = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Defender Real-Time Protection? (Please type either Y or N)"
                                    if($enableWindowsDefenderRealTimeProtection -eq "Y") {
                                                Try {
                                                    Write-Host "Attempting to enable the Windows Defender Real-Time Protection"
                                                    Set-MpPreference -DisableRealtimeMonitoring 0 -Force
                                                    Start-Sleep -s 2
                                                    Set-MpPreference -DisableIOAVProtection 0 -Force
                                                    Write-Host "[SUCCESS] Windows Defender Real-Time Protection enabled... Continuing"
                                                }
                                                Catch {
                                                    Write-Host "Unable to enable the Windows Defender Real-Time Protection because: $_"
                                                }

                                                Start-Sleep -s 5
                                    }
                                    elseif($enableWindowsDefenderRealTimeProtection -eq "N")
                                    {
                                       Write-Host "You entered NO... Continuing to next step"
                                       Start-Sleep -s 2
                                    }
                                    else
                                    {
                                       Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                    }  

                                }

                                # Attempt to start the Tamper Protection Service
                                    If($windowsDefenderEnabledCheck.IsTamperProtected -eq $false) {
                                        Write-Host "`nWARNING - The Windows Defender Tamper Protection SERVICE is NOT RUNNING" -Foregroundcolor YELLOW
                                        $enableWindowsDefenderTamperProtection = ""
                                        $enableWindowsDefenderTamperProtection = Read-Host -Prompt "QUESTION: Would you like to MANUALLY enable the Windows Defender Tamper Protection? (Please type either Y or N)"
                                        if($enableWindowsDefenderTamperProtection -eq "Y") {
                                                    Try {
                                                        Write-Host "Opening Windows Defender GUI for manual attempt (check if opened in background/behind this window).`n The option to enable Tamper Protection is under the 'Virus & threat protection => manage settings'...`nScroll down to the end of the 'Windows Security' screen and slde the 'Tamper Protection' tab across."
                                                        Start windowsdefender://enablertp/
                                                    }
                                                    Catch {
                                                        Write-Host "Unable to enable the Windows Defender Tamper Protection because: $_"
                                                    }

                                                    Start-Sleep -s 3
                                        }
                                        elseif($enableWindowsDefenderTamperProtection -eq "N")
                                        {
                                           Write-Host "You entered NO... Continuing to next step"
                                           Start-Sleep -s 2
                                        }
                                        else
                                        {
                                           Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                        }  

                                    }

                                    # Attempt to start the RemovableDrive Scan Service
                                        If($windowsDefenderMPPreference.DisableRemovableDriveScanning -eq $true) {
                                            Write-Host "`nWARNING - The Windows Defender Removable Drive Scan SERVICE is NOT RUNNING" -Foregroundcolor YELLOW
                                            $enableWindowsDefenderRemovableDriveCheck = ""
                                             $enableWindowsDefenderRemovableDriveCheck = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Defender Removable Drive Scan? (Y or N)"
                                            if($enableWindowsDefenderRemovableDriveCheck -eq "Y") {
                                                        Try {
                                                            Write-Host "Attempting to enable the Windows Defender Removable Drive Scan"
                                                            Set-MpPreference -DisableRemovableDriveScanning 0 -Force
                                                            Write-Host "[SUCCESS] Windows Defender Removable Drive Scan enabled... Continuing"
                                                        }
                                                        Catch {
                                                            Write-Host "Unable to enable the Windows Defender Removable Drive Scan because: $_"
                                                        }

                                                        Start-Sleep -s 5
                                            }
                                            elseif($enableWindowsDefenderRemovableDriveCheck -eq "N")
                                            {
                                               Write-Host "You entered NO... Continuing to next step"
                                               Start-Sleep -s 2
                                            }
                                            else
                                            {
                                               Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                                            }  

                                        }
 
              } #This is the end of the 'Y' choice to continue Windows Defender Configuration.
              Elseif($windowsDefenderContinueInstall -eq "N") 
              {
                 Write-Host "You entered NO... Continuing to next step"
                 Start-Sleep -s 2
              }
              else
              {
                 Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
              }

                        # Before Returning the status, this gets the latest state of them after any attempted changes
                        $windowsDefenderCheckStartupTypeUpdated = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).StartType  # Get the startup type of the service
                        $windowsDefenderCheckRunningStatusUpdated = (Get-Service -Name $serviceNameWindowsDefender -ErrorAction Stop).Status  # Get the current running status of the service
                        $windowsDefenderEnabledCheckUpdated = Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue
                        $windowsDefenderMPPreferenceUpdated = Get-MpPreference | Select-Object -Property DisableRemovableDriveScanning -ErrorAction SilentlyContinue

                        $windowsDefenderAntivirusStatus = ""
                        If($windowsDefenderEnabledCheckUpdated.AntivirusEnabled -eq $true) {
                           $windowsDefenderAntivirusStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderAntivirusStatus = "DISABLED"
                        }
                
                        $windowsDefenderRealTimeProtectionStatus = ""
                        If($windowsDefenderEnabledCheckUpdated.RealTimeProtectionEnabled -eq $true) {
                           $windowsDefenderRealTimeProtectionStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderRealTimeProtectionStatus = "DISABLED"
                        }

                        $windowsDefenderTamperProtectionStatus = ""
                        If($windowsDefenderEnabledCheckUpdated.IsTamperProtected -eq $true) {
                           $windowsDefenderTamperProtectionStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderTamperProtectionStatus = "DISABLED"
                        }

                        $windowsDefenderRemovableScanStatus = ""
                        If($windowsDefenderMPPreferenceUpdated.DisableRemovableDriveScanning -eq $false) {
                           $windowsDefenderRemovableScanStatus = "Enabled"
                        }
                        else {
                           $windowsDefenderRemovableScanStatus = "DISABLED"
                        }
                    
                        Write-Host "`n[CURRENT SERVICE STATUS]`nWindows Defender service is $windowsDefenderCheckStartupTypeUpdated and $windowsDefenderCheckRunningStatusUpdated"
                        Write-Host "Windows Defender Antivirus is $windowsDefenderAntivirusStatus"
                        Write-Host "Windows Defender Real-Time Protection is $windowsDefenderRealTimeProtectionStatus"
                        Write-Host "Windows Defender Tamper Protection is $windowsDefenderTamperProtectionStatus"
                        Write-Host "Windows Defender Removable Drive Scanning is $windowsDefenderRemovableScanStatus"

        } # This is the end of the ELSE statement for Windows Defender not running

            ###########################################################################################################
            ###  Once Windows Defender is enabled (or if already enabled), ask if want to update the signatures
            ###########################################################################################################

            If(($windowsDefenderCheckRunningStatus -eq "Running") -OR ($windowsDefenderCheckRunningStatusUpdated -eq "Running") -AND ($windowsDefenderAntivirusStatus -eq "Enabled")){

                Write-Host "`n********* WINDOWS DEFENDER SIGNATURE UPDATES *********`n" -ForegroundColor GREEN
                $enableWindowsDefenderSignatureUpdate = Read-Host -Prompt "QUESTION: Would you like to update the Windows Defender Signatures? (Please type either Y or N)"
                if($enableWindowsDefenderSignatureUpdate -eq "Y") {
                        Try {
                            Write-Host "Attempting to update the Windows Defender Signatures.... `nCurrent Signature Version:" $windowsDefenderEnabledCheck.AntivirusSignatureLastUpdated
                            Update-MpSignature

                            Start-Sleep -s 5
                            $windowsDefenderEnabledCheckSignature = Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue
                            Write-Host "Updated Signature Version:" $windowsDefenderEnabledCheckSignature.AntivirusSignatureLastUpdated
                        }
                        Catch {
                            Write-Host "Unable to update the Windows Defender Signature because: $_"
                        }
                }
                elseif($enableWindowsDefenderSignatureUpdate -eq "N")
                {
                   Write-Host "Current Signature Version:" $windowsDefenderEnabledCheck.AntivirusSignatureLastUpdated
                   Write-Host "You entered NO... Continuing to next step"
                   Start-Sleep -s 2
                }
                else
                {
                   Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                }
            }
            else {
                   Write-Host "`n********* WINDOWS DEFENDER SIGNATURE UPDATES *********`n"  -ForegroundColor GREEN
                   Write-Host "[SKIP] Windows Defender Antivirus is currently set to $windowsDefenderAntivirusStatus... Continuing to next step"
           }

        #############################################################
        # CONFIRM TAMPER PROTECTION
        #############################################################

        # Attempt to start the Tamper Protection Service, ONLY if not already enabled and the user did not SKIP this section
        If(($windowsDefenderTamperProtectionStatus -ne 'Enabled') -AND ($windowsDefenderContinueInstall -eq 'Y'))
        {
                Write-Host "`n********* WINDOWS DEFENDER TAMPER PROTECTION *********`n" -ForegroundColor GREEN
                $finalEnableWindowsDefenderTamperProtection = Read-Host -Prompt "QUESTION: Would you like to MANUALLY confirm the Windows Defender Tamper Protection settings? (Please type either Y or N)"
                if($finalEnableWindowsDefenderTamperProtection -eq "Y") {
                            Try {
                                Write-Host "Opening Windows Defender GUI for manual confirmation, option to enable is under the 'Virus & threat protection => manage settings'...`nScroll down to the end of the 'Windows Security' screen and slide the 'Tamper Protection' tab across."
                                Start windowsdefender://enablertp/
                                pause
                            }
                            Catch {
                                Write-Host "Unable to enable the Windows Defender Tamper Protection because: $_"
                            }

                            Start-Sleep -s 5
                }
                elseif($finalEnableWindowsDefenderTamperProtection -eq "N")
                {
                   Write-Host "You entered NO... Continuing to next step"
                   Start-Sleep -s 2
                }
                else
                {
                   Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                } 
        } 

        #############################################################
        # .NET FRAMEWORK DETAILS
        #############################################################

        Write-Host "`n********* .NET FRAMEWORK UPDATES *********`n" -ForegroundColor GREEN
        $currentVersionNumbers = ""

        $getNETFrameworkDetails = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | sort-Object -property version | Select version
        ForEach($differentVersion in $getNETFrameworkDetails){
            $currentVersionNumbers += $differentVersion.version + ", "
        }

        $currentVersionNumbers = $currentVersionNumbers.TrimEnd(', ')

        If($currentVersionNumbers -match "4.8."){
            $NetVersionResult = "$currentVersionNumbers`n[PASS] Version 4.8 detected"
            Write-Host "Versions Detected: $currentVersionNumbers`n[PASS] Version 4.8 detected...All good!"
        }
        else {
            $NetVersionResult = "$currentVersionNumbers`nWARNING - System is missing .Net Framework Version 4.8`n=> You can download from https://dotnet.microsoft.com/en-us/download/dotnet-framework/thank-you/net48-offline-installer"
            Write-Host "Versions Detected: $currentVersionNumbers`n[FAIL] Version 4.8 NOT detected..."

                $netFrameworkDownloadPrompt = Read-Host -Prompt "QUESTION: Would you like to open the .Net Framework Download page? (Please type either Y or N)"
                if($netFrameworkDownloadPrompt -eq "Y") {
                                Try {
                                    Write-Host "Attempting to open the .Net Framework Download page`n"
                                    Start-Process -FilePath "https://dotnet.microsoft.com/en-us/download/dotnet-framework/thank-you/net48-offline-installer"
                                }
                                Catch {
                                    Write-Host "Unable to open the .Net Framework Download page because: $_"
                                }
                }
                elseif($netFrameworkDownloadPrompt -eq "N")
                {
                  Write-Host "You entered NO... KEEP CALM AND CARRY ON...`n"
                }
                else
                {
                  Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time.`n"
                }

            Write-Host "WARNING - System is missing .Net Framework Version 4.8`n=> You can download from https://dotnet.microsoft.com/en-us/download/dotnet-framework/thank-you/net48-offline-installer"
        }


        #############################################################
        # WINDOWS UPDATE DETAILS
        #############################################################

                Write-Host "`n********* CHECK FOR WINDOWS UPDATES *********`n" -ForegroundColor GREEN
        
                $checkForWindowsUpdateAvailable = ""
                $checkForWindowsUpdateAvailable = Read-Host -Prompt "QUESTION: Would you like to check for any pending or new Windows Updates on this system? (Please type either Y or N)"
                if($checkForWindowsUpdateAvailable -eq "Y") {
                            Try {
                                #############################################################
                                # PENDING WINDOWS UPDATE DETAILS
                                #############################################################

                                $computerName = $env:COMPUTERNAME
                                $networkConnectionTest = Test-Connection 8.8.8.8  # Testing with Google DNS
                                C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate

                                Write-Host "`n********* PENDING WINDOWS UPDATES *********`n" -ForegroundColor GREEN
                                Write-Host "NOTE: This may take a while to process....(2-3 minutes)`nA Windows Update screen should have opened now, please click on the 'check for updates' button (if you want to search for new updates).`n"

                                $updates = (New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0 and Type='Software'").Updates | Select-Object Title
                                    # Type='Driver' #Type='Software' 
                                    # 0 = False | 1 = True 
                                $updatesCount = $Updates.Count
                                $updatesName = $Updates.Name
                                $updates = $updates | Group IsDownloaded

                                    If($updates) # If anything was returned from the $updates search then...
                                    {
                                       Write-Host "MICROSOFT UPDATES:"
                                       [INT]$updatesAlreadyDownloaded = $updates[1].group.count
                                       [INT]$updatesWaitingDownload = $updates[0].group.count

                                       # This displays any updates that have already been downloaded onto the system
                                       If($updatesAlreadyDownloaded -eq 0){
                                         Write-Host "`tUPDATES ALREADY DOWNLOADED: No Updates have been downloaded for install... All good!"
                                       } else {
                                         Write-Host "`tUPDATES ALREADY DOWNLOADED:" -ForegroundColor yellow
                                         $updates[1].group | % { Write-Host "`t *" $_.Title -ForegroundColor yellow}

                                         $microsoftUpdateDownloadedResultList = ($updates[1].group | % {" * " + $_.Title + "`n"})
                                       } 

                                       # This displays any updates that are waiting to be downloaded onto the system
                                       If($updatesWaitingDownload -gt 0){
                                            If(!($networkConnectionTest)){
                                                Write-Host "`tUPDATES AWAITING DOWNLOAD:" 
                                                Write-Host "`t=> No network connectivity detected on $computerName (or script not running as administrator)`n" -ForegroundColor yellow
                                            } elseIf(($updatesCount -eq 1) -AND (!($updatesName))) {
                                                Write-Host "`tUPDATES AWAITING DOWNLOAD: No Updates have been detected for install... All good!"
                                            } else {
                                                Write-Host "`tUPDATES AWAITING DOWNLOAD:" -ForegroundColor yellow
                                                $updates[0].group | % { Write-Host "`t *" $_.Title -ForegroundColor yellow}

                                                $microsoftUpdateWaitingResultList = ($updates[0].group | % {" * " + $_.Title + "`n"})
                                            }
                                       } else {
                                            Write-Host "`tUPDATES AWAITING DOWNLOAD: No Updates are waiting to be downloaded... All good!"
                                       }
                                    }
                                    else {
                                       Write-Host "MICROSOFT UPDATES: No Windows Updates (excluding drivers/optional) detected for install... All good!"
                                    }

                                If(($microsoftUpdateDownloadedResultList -eq "") -AND ($microsoftUpdateWaitingResultList -eq "")){
                                    $microsoftUpdateDownloadedResultList = "`tNo Windows Updates (excluding drivers/optional) detected for install"
                                    $microsoftUpdateWaitingResultList = ""
                                }
                            }
                            Catch {
                                Write-Host "Unable to confirm the Windows Update check selection because: $_ `nTry clicking on the 'Check for Updates' or 'Check online for updates from Microsoft Update' in the separate window."
                                $microsoftUpdateDownloadedResultList = "`tUnable to confirm the Windows Update check selection"
                            }

                            Start-Sleep -s 3
                }
                elseif($checkForWindowsUpdateAvailable -eq "N")
                {
                   Write-Host "You entered NO... Continuing to next step"
                   $microsoftUpdateDownloadedResultList = "`tN/A - Manually Skipped"
                   Start-Sleep -s 2
                }
                else
                {
                   Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                }  

        #############################################################
        # WINDOWS FIREWALL SERVICE ENABLE
        #############################################################

        Write-Host "`n********* WINDOWS FIREWALL DETAILS *********`n" -ForegroundColor GREEN

        $windowsFirewallCheckStartupType = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).StartType  # Get the startup type of the service
        $windowsFirewallCheckRunningStatus = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).Status  # Get the current running status of the service

        if (($windowsFirewallCheckStartupType -eq "Manual") -OR ($windowsFirewallCheckStartupType -eq "Automatic") -OR ($windowsFirewallCheckStartupType -eq "AutomaticDelayedStart")) {
            Write-Host "[PASS] Windows Firewall is currently set to $windowsFirewallCheckStartupType and the current status is $windowsFirewallCheckRunningStatus... All good!"
        }
        elseIf ($windowsFirewallCheckStartupType -eq "Disabled") {
                Write-Host "The Windows Firewall service is $windowsFirewallCheckStartupType"
                $enableWindowsFirewall = ""
                $enableWindowsFirewall = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Firewall service? (Y or N)"
                if($enableWindowsFirewall -eq "Y")
                {
                    Write-Host "Attempting to enable the Windows Firewall service...."
                    Try {
                        Set-Service -Name $serviceNameWindowsFirewall -StartupType Automatic -Status Running
                        Start-Sleep -Seconds 5
                        $windowsFirewallCheckStartupTypeUpdated = ""
                        $windowsFirewallCheckRunningStatusUpdated = ""

                        $windowsFirewallCheckStartupTypeUpdated = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).StartType  # Get the startup type of the service
                        $windowsFirewallCheckRunningStatusUpdated = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).Status  # Get the current running status of the service
            
                        if(($windowsFirewallCheckRunningStatusUpdated -eq "Automatic") -AND ($windowsFirewallCheckRunningStatusUpdated -ne "Running")) {
                            Write-Host "The Windows Firewall service is now set to $windowsFirewallCheckStartupTypeUpdated `nThe current running status is $windowsFirewallCheckRunningStatusUpdated`n"
                            $startWindowsFirewall = ""
                            $startWindowsFirewall = Read-Host -Prompt "QUESTION: Would you like to start the Windows Firewall service? (Y or N)"
                            if($startWindowsFirewall -eq "Y")
                            {
                                Write-Host "Attempting to start the Windows Firewall service..."
                                Try {
                                    Start-Service $serviceNameWindowsFirewall
                                    Start-Sleep -Seconds 5
                                    $startWindowsFirewallRecheck = ""
                                    $startWindowsFirewallRecheck = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).Status  # Get the current running status of the service

                                    if($startWindowsFirewallRecheck -eq "Running") {
                                        Write-Host "[SUCCESS] The Windows Firewall service is now running!"
                                    }
                                    else {
                                        Write-Host "[FAIL] Mmmm... For some reason the Firewall service hasn't started running... Please manually check"
                                    }
                                }
                                catch {
                                    Write-Host "Unable to start the Windows Firewall service because: $_"
                                }
                            }
                            elseif($startWindowsFirewall -eq "N")
                            {
                                Write-Host "You entered NO... Continuing to next step"
                                Start-Sleep -s 2
                            }
                            else
                            {
                                Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                            } 
                        } 
                        elseIf($windowsFirewallCheckRunningStatusUpdated -eq "Running") { 
                            Write-Host "[SUCCESS] The Windows Firewall service is now running!"
                        }
                        else {
                            Write-Host "Getting to HERE... $windowsFirewallCheckRunningStatusUpdated"}
                    }
                    Catch{
                        Write-Host "Unable to change the Windows Firewall status because: $_"
                    }
                }
                elseif($enableWindowsFirewall -eq "N")
                {
                    Write-Host "You entered NO... Continuing to next step"
                    Start-Sleep -s 2
                }
                else
                {
                    Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                }  

        # Run the status check again to use in the Service Report...
        $windowsFirewallCheckRunningStatus = (Get-Service -Name $serviceNameWindowsFirewall -ErrorAction Stop).Status  # Get the updated running status of the service
        }
        else {}

        #############################################################
        # WINDOWS FIREWALL PROFILES ENABLE
        #############################################################

        $windowsFirewallTypeCheck = Get-NetFirewallProfile | Select Name, Enabled

        Write-Host "`n********* WINDOWS FIREWALL PROFILE DETAILS *********`n" -ForegroundColor GREEN

        $currentFirewallVersionDetails = ""
        ForEach($differentFirewallVersion in $windowsFirewallTypeCheck){
            $currentFirewallVersionDetails += $differentFirewallVersion.Name + ":" + $differentFirewallVersion.Enabled + ", "
        }
        $currentFirewallVersionDetails = $currentFirewallVersionDetails.TrimEnd(', ')

        Write-Host "Checking the Current Firewall Profile Status (Domain/Private/Public)...`nWindows Firewall has the following Profiles - $currentFirewallVersionDetails`n"

        If($currentFirewallVersionDetails -match "False")  # so if ANY of the versions aren't enabled....
        {
          $currentFirewallVersionIndividualProfiles = ""
          $differentFirewallIndividualProfiles = ""
    
            ForEach($differentFirewallIndividualProfiles in $windowsFirewallTypeCheck){
                If($differentFirewallIndividualProfiles.Enabled -eq $false){
                    $differentFirewallVersionName = ""
                    $enableWindowsFirewallProfile = ""

                    $differentFirewallVersionName = $differentFirewallIndividualProfiles.Name
                    Write-Host "WARNING - The Firewall Profile '$differentFirewallVersionName' is set to Disabled." 
                    $enableWindowsFirewallProfile = Read-Host -Prompt "QUESTION: Would you like to enable the Windows Firewall Profile '$differentFirewallVersionName'? (Y or N)"

                    if($enableWindowsFirewallProfile -eq "Y") {
                        Try {
                            Write-Host "Attempting to enable Windows Firewall Profile '$differentFirewallVersionName'"
                            Try {
                                Set-NetFirewallProfile -Profile $differentFirewallVersionName -Enabled True
                            }
                            Catch {
                                Write-Host "Unable to enable the Windows Firewall Profile '$differentFirewallVersionName' because: $_`n"
                            }

                            Start-Sleep -s 5
                            $windowsFirewallTypeReCheck = ""
                            $windowsFirewallTypeReCheck = Get-NetFirewallProfile | Select Name, Enabled
                            If($windowsFirewallTypeReCheck.Name -match $differentFirewallVersionName){
                                If($windowsFirewallTypeCheck.Enabled -eq $True){
                                    Write-Host "[SUCCESS] The Windows Firewall Profile '$differentFirewallVersionName' has been Enabled`n"
                                }
                                else {
                                    Write-Host "[FAIL] Unable to enable the Windows Firewall Profile '$differentFirewallVersionName' because: $_`n"
                                }
                            }
                        }
                        Catch {
                            Write-Host "Unable to enable the Windows Firewall Profile '$differentFirewallVersionName' because: $_`n"
                        }
                    }
                    elseif($enableWindowsFirewallProfile -eq "N")
                    {
                       Write-Host "You entered NO to enable Windows Firewall Profile '$differentFirewallVersionName'... Continuing to next step`n"
                       Start-Sleep -s 2
                    }
                    else
                    {
                       Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time.`n"
                    }
                }
            } 

            $windowsFirewallTypeFinalCheck = ""
            $windowsFirewallTypeFinalCheck = Get-NetFirewallProfile | Select Name, Enabled
    
            $currentFirewallVersionDetailsFinal = ""
            ForEach($differentFirewallFinalVersion in $windowsFirewallTypeFinalCheck){
               $currentFirewallVersionDetailsFinal += $differentFirewallFinalVersion.Name + ":" + $differentFirewallFinalVersion.Enabled + ", "
            }
            $currentFirewallVersionDetailsFinal = $currentFirewallVersionDetailsFinal.TrimEnd(', ')
            Write-Host "RESULTS: Windows Firewall has the following Profiles - $currentFirewallVersionDetailsFinal"
            $profileResults = $currentFirewallVersionDetailsFinal
        }
        else {
           Write-Host "[PASS] Windows Firewall has the following Profiles - $currentFirewallVersionDetails"
           $profileResults = $currentFirewallVersionDetails
        }

        #############################################################
        # WINDOWS FIREWALL RULES LIST
        #############################################################

        # Next we get a list of active firewall rules on the system
        Write-Host "`n[WINDOWS FIREWALL RULES]" -Foregroundcolor YELLOW
        $pathFile = [Environment]::GetFolderPath("Desktop")
        $retrieveFirewallRules = (New-object -ComObject HNetCfg.FWPolicy2).rules
        $firewallRules = $retrieveFirewallRules |
        Where-Object {$_.enabled} |
        Sort-Object -Property Direction,Name |
        Select-Object -Property Name, Description, Protocol, LocalPorts, RemotePorts, LocalAddresses, RemoteAddresses, Direction, Action
        Write-Host "There are currently $($FirewallRules.count) locally ENABLED firewall rules on $env:ComputerName (Inbound/Outbound)`n"
        $getLocalFirewallRules = Read-Host -Prompt "QUESTION: Would you like to save the Windows Firewall Rules list to $pathFile (Please type either Y or N)?"
        if($getLocalFirewallRules -eq "Y") {
           Try {
                  $firewallRules | export-csv "$pathFile\$env:COMPUTERNAME-FirewallRules-$dateFile.csv" -NoTypeInformation
                  Write-Host "`n[SUCCESS] Windows Firewall Rules saved to $pathFile\$env:COMPUTERNAME-FirewallRules-$dateFile.csv"
           }
            Catch {
                  Write-Host "Unable to save the Windows Firewall Rules details because: $_"
           }
        }
        elseif($getLocalFirewallRules -eq "N") {
                  Write-Host "You entered NO... Continuing to next step"
                  Start-Sleep -s 2
        }
        else {
                  Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time.`n"
        }

        #############################################################
        # CHECK WIN11 COMPATIBILITY
        #############################################################

        Write-Host "`n********* WINDOWS 11 COMPATIBILITY CHECK *********`n" -ForegroundColor GREEN
        $windows11CompatibilityCheck = Read-Host -Prompt "QUESTION: Would you like to check if this system is able to support Windows 11 24H2?`nNOTE: This does NOT start any upgrade, it ONLY checks if this system will support Windows 11 or not! (Please type either Y or N)"
                if($windows11CompatibilityCheck -eq "Y") {
                            Try {
                                # Call the function that checks if the system will support Windows 11
                                Win11Requirements
                                #$global:WINVERFUNCTION = $true
                            }
                            Catch {
                                Write-Host "Unable to start the Windows 11 compatibility check because: $_"
                            }

                            Start-Sleep -s 3
                }
                elseif($windows11CompatibilityCheck -eq "N")
                {
                   Write-Host "You entered NO... Continuing to next step"
                   $global:WINVERFUNCTION = $false
                   Start-Sleep -s 2
                }
                else
                {
                   Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                } 


        #############################################################
        # CONFIRM TO BYPASS WIN11 REGISTRY CHECKS
        #############################################################

        # This will only show if the user selected to check if Windows 11 was supported on the system and a FAIL was returned.
        # However, if the system is already WIN11 23H2, it will also skip over this section (already upgraded), even if it does not meet the requirements

        If(($global:OfferRegistryBypass -eq $true) -AND ($global:CURRENT_VERSION_WINDOWS.OSDisplayVersion -ne '23H2') -AND ($windows11CompatibilityCheck -eq "Y")) {
            Write-Host "`n********* WINDOWS 11 REGISTRY EDIT TO BYPASS INSTALL REQUIREMENTS *********`n" -ForegroundColor YELLOW
            Write-Host "This system $env:Computername DOES NOT meet the 'official' Windows 11 24H2 requirements.`nThe reason(s) returned is due to $global:returnreason`n"
            Write-Host "[BUILD VERSION INFO]`nWindows 11 23H2 is the LAST build number that allows you to 'bypass' the pre-requisite checks to allow an upgrade.`nBuild 23H2 will continue to recieve official Windows Updates until November 2025 for home users and November 2026 for enterprise users."
            Write-Host "`n[REGISTRY EDIT BYPASS]" -ForegroundColor YELLOW
            Write-Host "The following registry edits will allow certain requirements to be bypassed (for Windows 11 23H2 upgrade):`n`n* BypassTPMCheck (TPM)`n* AllowUpgradesWithUnsupportedTPMOrCPU (Processor)`n* BypassRAMCheck (Memory)`n* BypassSecureBootCheck (SecureBoot)`n`nNOTE: Storage (Disk Size) MUST have at least 64GB disk space, and can't be bypassed.`n"
            $windows11RegistryUpgrade = Read-Host -Prompt "QUESTION: Would you like to add the 'bypass requirements' registry entries to $env:ComputerName (Please type either Y or N)"
                if($windows11RegistryUpgrade -eq "Y") {  # If user selects yes, it will try to install the new registry entries to bypass the Win11 requirements.       
                                $userConfirmedWIN11BypassOption = $true
                                Try {
                                      New-Item -Path "HKLM:\SYSTEM\Setup" -Name "MoSetup" -Force -ErrorAction SilentlyContinue
                                      New-Item -Path "HKLM:\SYSTEM\Setup" -Name "Labconfig" -Force -ErrorAction SilentlyContinue
                                      Write-Host "New-Item -Path 'HKLM:\SYSTEM\Setup' -Name 'MoSetup' -Force -ErrorAction SilentlyContinue`nNew-Item -Path 'HKLM:\SYSTEM\Setup' -Name 'Labconfig' -Force -ErrorAction SilentlyContinue"
                                      Start-Sleep -Seconds 2

                                      New-ItemProperty -Path "HKLM:\SYSTEM\Setup\MoSetup" -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                      New-ItemProperty -Path "HKLM:\SYSTEM\Setup\LabConfig" -Name "BypassTPMCheck" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                      New-ItemProperty -Path "HKLM:\SYSTEM\Setup\LabConfig" -Name "BypassRAMCheck" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                      New-ItemProperty -Path "HKLM:\SYSTEM\Setup\LabConfig" -Name "BypassSecureBootCheck" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
                                      Write-Host "New-ItemProperty -Path 'HKLM:\SYSTEM\Setup\MoSetup' -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue`nNew-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name 'BypassTPMCheck' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue`nNew-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name 'BypassRAMCheck' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue`nNew-ItemProperty -Path 'HKLM:\SYSTEM\Setup\LabConfig' -Name 'BypassSecureBootCheck' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue"
                                      Start-Sleep -Seconds 2

                                      Write-Host "`n[SUCCESS] The registry keys have been modified" -ForegroundColor GREEN
                                      Write-Host "Please make sure the Windows 11 ISO is Build 23H2 and contains the same VERSION of the current OS (i.e. HOME, PRO, ENT etc).`nThis system ($env:ComputerName) is currently reporting as being $global:WINVERFUNCTION"
                                      Write-Host "==> ==> NOTE: You may have to reboot the computer and run the script again at this stage...`n"
                                      pause
                                }
                                Catch {
                                    Write-Host "Unable to add the 'bypass' registry entries because: $_"
                                }

                                Start-Sleep -s 2
                    }
                    elseif($windows11RegistryUpgrade -eq "N")
                    {
                       Write-Host "You entered NO... Continuing to next step"
                       Start-Sleep -s 2
                    }
                    else
                    {
                       Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
                    } 
        }

        #############################################################
        # SYSTEM DETAILS
        #############################################################

        $winVER = systeminfo /fo csv | ConvertFrom-Csv | select "OS Name","OS Version","Domain"
        Write-Host "`n"

        $systemDetailsOverall = ""
        $systemDetailsOverall = "*************************************************`n**************** SYSTEM DETAILS *****************`n*************************************************`n`nUsername:`t $env:UserName`nPC Name:`t $env:COMPUTERNAME`nJoined:`t`t $env:USERDOMAIN`nDomain:`t`t " + $winVer."Domain" + "`nOS Build:`t " + $winVer."OS Name" + " - " + $winVer."OS Version"

        #############################################################
        # OVERALL RESULTS
        #############################################################

        $windowsDefenderSignatureResult = Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated -ErrorAction SilentlyContinue
        if($windowsDefenderSignatureResult.AntivirusSignatureLastUpdated) { 
            $windowsDefenderSignatureText = $windowsDefenderSignatureResult.AntivirusSignatureLastUpdated
        } else {
            $windowsDefenderSignatureText = "N/A"
        }

        # If the user skipped the win11 check, this creates text for the systems results section
        If($WINVERFUNCTION -eq $false)
        {
            $WINVERFUNCTION = "Windows 11 Compatibility Check:`t`tN/A - Manually Skipped`n`n"
        } ELSE
        {
            $WINVERFUNCTION = "$global:OVERALLCOMPATIBLERESULTS`n`n"
        }

        #If the user selected to apply the registry edit for Win11, add that notification to the report)
        If($userConfirmedWIN11BypassOption) {
            $WINVERFUNCTION = $WINVERFUNCTION + "Registry Edit:`t$env:UserName selected to apply the Windows 11 Bypass requirements to the registry`n`n"
        }

        Write-Host "[ALL DETAILS RETRIEVED]`n>>> Gathering all other information...Please wait <<<`n`n" -Foregroundcolor YELLOW

        # Collect the details about the network / IP address of the machine and it it has internet access
        $systemNameForReport = $env:COMPUTERNAME
        $domainORWorkgroupForReport = (Get-WmiObject Win32_ComputerSystem).Domain
        $testExternalInternet = Test-Connection -ComputerName "www.google.com" -quiet
        $networkAdapterAddressForReport = Get-NetIPAddress -AddressFamily IPv4 | Select IPAddress,PrefixOrigin,AddressState | Sort-Object -Property InterfaceIndex | Format-Table | Out-String
        $networkIPConfiguration = Get-NetIPConfiguration | Format-List | Out-String
        $networkIPConfiguration = $networkIPConfiguration.Trim()

        # Get the current product key and activation server (if used)
        $productKeyInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "BackupProductKeyDefault","KeyManagementServiceName","KeyManagementServicePort" -ErrorAction SilentlyContinue | Format-List | Out-String
        $productKeyInfo = $productKeyInfo.Trim()

        # Get the status of Bitlocker on the main drive (C:)
        $bitlockerOSDriveStatus = Get-BitLockerVolume -MountPoint "c:" | Select ProtectionStatus,VolumeStatus,LockStatus -ErrorAction SilentlyContinue | Format-List | Out-String
        $bitlockerOSDriveStatus = $bitlockerOSDriveStatus.Trim()

        $updateResults = "$systemDetailsOverall`n`n==> [PRODUCT KEY DETAILS]`n`n$productKeyInfo`n`n==> [BITLOCKER STATUS]`n`n$bitlockerOSDriveStatus`n`n==> [WINDOWS 11 COMPATIBILITY]`n`n$WINVERFUNCTION==> [SERVICE DETAILS]`n`nWindows Update Startup Type:`t`t$windowsUpdateCheckStartupType`nWindows Update Running Status:`t`t$windowsUpdateCheckRunningStatus`n`nWindows Defender Startup Type:`t`t$windowsDefenderCheckStartupType`nWindows Defender Running Status:`t$windowsDefenderCheckRunningStatus`n`nWindows Antivirus Startup Type:`t`t$windowsDefenderAntivirusStatus`nWindows Real-Time Protection:`t`t$windowsDefenderRealTimeProtectionStatus`nWindows Tamper Protection Status:`t$windowsDefenderTamperProtectionStatus`nWindows Removable Drive Scan:`t`t$windowsDefenderRemovableScanStatus`nLatest Signature Version File:`t`t" + $windowsDefenderSignatureText + "`n`nWindows Firewall Running Status:`t$windowsFirewallCheckRunningStatus`nWindows Firewall Profile Status:`t$profileResults`nWindows Firewall Rules (In/Out):`t$($FirewallRules.count)`n`n.Net Framework Version Numbers:`t`t$NetVersionResult`n`nWindows Updates Pending Download:$microsoftUpdateDownloadedResultList`n$microsoftUpdateWaitingResultList`n==> [NETWORK INFORMATION]`n`n$systemNameForReport is part of $domainOrWorkgroupForReport`nInternet Access is $testExternalInternet`n`nThe Network adapter addresses are: $networkAdapterAddressForReport$networkIPConfiguration"

        Write-Host $updateResults

        Write-Host "`n`n********* SAVE RESULTS *********`n" -ForegroundColor GREEN
        $saveToFilePrompt = Read-Host -Prompt "QUESTION: Would you like to save these results to a text file? (Please type either Y or N)"
        if($saveToFilePrompt -eq "Y") {
                        Try {
                            $pathFile = [Environment]::GetFolderPath("Desktop")
                            $nameOfFile = $pathFile + "\" + $env:COMPUTERNAME + "_" + $dateFile + ".txt"
                    
                            $updateResults | Out-File -Encoding "ascii" -FilePath $nameofFile 
                            Write-Host "File saved to $nameofFile"
                        }
                        Catch {
                            Write-Host "Unable to save file to disk because: $_"
                        }
        }
        elseif($saveToFilePrompt -eq "N")
        {
          Write-Host "You entered NO... KEEP CALM AND CARRY ON..."
        }
        else
        {
          Write-Host "Invalid Character(s) - Please enter 'Y' or 'N' next time."
        }
}
pause