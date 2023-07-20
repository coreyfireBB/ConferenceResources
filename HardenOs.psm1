<#

----HOW TO USE THIS SCRIPT----
- This script is meant to be used to harden a machine. This script can be utilized in a number of fashions. 
-- This script would be best utilized to test the items in a client environment prior to enacting these changes across the board 

- This script requires an administrator account, and an elevated PowerShell session as well. 
- This script should only be ran on a Windows 10 1909+ machine. 
- This script is meant for Server 2016+ 


Review each and every single thing in this script. Use at your own descretion 

You will want to understand what is encompassed inside of a level prior to just unleashing it. 

To run this script simply, import the module. After that run the level you want to accomplish: 
Set-Level1Harden 

That will hit all of the items in the level 1 hardening guidelines. 

This script will hit on some of the highest offenders
- Disable WPAD - {DONE}
- Disable NetBIOS Over TCP {DONE}
- Disable SMBv1 {DONE} 
- Disable LLMNR {DONE}
- Enable SMB signing {DONE}
- Disable PowerShell V2 {DONE}
- Enable Script block logging for PowerShell {DONE}
- Force NTLMv2 or higher {DONE}
--- Deny NTLMv1 + LM Hashes Reg value of 5 does this {DONE}
- Enable Windows Firewall Logging {DONE}
- SMBv3 Check / Close {DONE}
- Enable PowerShell CLM (Constrained Language Mode) {DONE}
- Enable ASR (MS Defender Attack Surface Reduction) with specific sets of policies {DONE}
- Disabling IPv6 {DONE}
- Restrict Null Sessions {DONE}
- Restrict AT (scheduled Tasks to only Administrators) {DONE}
- Enable LSA protection {DONE}
- Disable WDIGEST {DONE}
- Disable Admin Shares {DONE}


#>

# First we will start with writing a function to allow us to find out if a registry key+value combination exist: 
function Test-RegistryValue {

    param (

    [parameter(Mandatory=$true)]

    [ValidateNotNullOrEmpty()]$Path,
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]$Value
    )

try {
    Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
     return $true
    }

catch {
    return $false
    }

}

# WPAD Removal {Requires the Test-Registry function} - {L1}
function Disable-WPAD {
    if(Test-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Value "WpadOverride") {
        Write-Host "This machine already has that value set" 
    }else {
        New-ItemProperty "hkcu:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -PropertyType "DWord" 
    } 
}

# Disable NetBIOS over TCP/IP - {L1}
function Disable-NetBIOSoverTCP {
    $regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
    Write-Host "For each interface found, NetBIOS over TCP/IP has been disabled"
}

# Next we need to know if LLMNR is enabled or not {Requires Test-Registry function} {L1}
function Disable-LLMNR {
    
    if(Test-Path 'HKLM:\SOFTWARE\policies\Microsoft\Windows NT\DNSClient') {
        write-host "Reg Value exists"
        if(Test-RegistryValue -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Value "EnableMulticast") {
            Write-Host "This machine already had LLMNR disabled"
        }else {
            New-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType "DWord" 
            Write-Host "LLMNR has been disabled"
        }
    }else{
        Write-host ""
        REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient”
        REG ADD  “HKLM\Software\policies\Microsoft\Windows NT\DNSClient” /v ” EnableMulticast” /t REG_DWORD /d “0” /f
    }
}



# Disable SMBv1 - {L3}
function Disable-SMBv1 {
    if(Get-SmbServerConfiguration | Select EnableSMB1Protocol) {
        Write-Host "This machine has SMBv1 enabled, we will fix that."
        Set-SmbServerConfiguration -EnableSMB1Protocol $false
        Write-Host "SMBv1 has now been disabled."
    }else {
        Write-Host "This machine already had SMBv1 disabled. Good work!"
    }
}


# Enable SMB Signing and Encryption - {L1}
function Enable-SmbSigning {
    if(Get-SmbServerConfiguration | Select EnableSecuritySignature) {
        Write-Host "This machine already has SMB Signing enabled"
    }else{
        Set-SmbServerConfiguration -RequireSecuritySignature $True -EnableSecuritySignature $True -EncryptData $True -Confirm:$false
        Write-Host "SMB Signing has been enabled"
    }
}

# PowerShellv2 Disable - {L2}
function Disable-PowerShellv2 {
    Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 |fl state 

    if(Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 |fl state) {
        write-host "PowerShellv2 is enabled"    
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
        write-host "PowerShellv2 should now be disabled"
    }else {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
        write-host "PowerShellv2 was already disabled"
    }
}


# PowerShell Script Block Logging {Requires the Test-Registry function} - {L2}
function Enable-PSScriptBlockLogging {
    if(Test-RegistryValue -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -Value 'ScriptBlockLogging') {
        Write-Host "This machine already had Script Block Logging enabled." 
    }else {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force
        Write-Host "Script Block Logging has been enabled!"
    } 
}

# Force NTLMv2 or higher, and deny NTLMv1 + LM {Requires the Test-Registry function} - {L1}
function Enable-NTLMv2Only {
    if(Test-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Value 'LmCompatibilityLevel') {
        Write-Host "This machine already has that NTLMv2 Forced-only" 
    }else {
        New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "LmCompatibilityLevel" -Value 5 -PropertyType "DWord" 
        Write-Host "This machine now has NTLMv2+ enforced."
    } 
}


# Enable Windows Firewall Logging - {L1}
function Set-LogFirewallProfile {
	Set-NetFirewallProfile -LogAllowed True -LogIgnored True -LogBlocked True
	Get-NetFirewallProfile | fl name,LogAllowed,LogBlocked,LogIgnored
}

# Testing for SMBv3 Vulnerability (CVE-2929-0796) {Requires Test-RegistryValue Function} -==-=-= This needs Tested -==-=-= - {L1}
function Test-SMBv3Vuln {
    if(Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Value 'DisableCompression') {
        Write-Host "This machine already had SMBv3 vuln remedied." 
    }else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force 
        Write-Host "This machine now has SMBv3 Vuln remedied."
    } 
}
# Enable Constrained Language Mode (CLM) - {L2}
function Enable-PSCLM {
    [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
}

# Disable Constrained Language Mode (CLM) - {L2}
function Disable-PSCLM {
    [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '8', 'Machine')
}


# Enable ASR Policies: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell
# Additional references: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide
# Guid tells which rule set is being used, notated below
# Enabled = Block, AuditMode = generates an event log 1121/1122, Disabled turns the rule off. 
function Enable-ASRLevel1 {
    # This one blocks untrusted and unsigned processes that run from USB 
    Set-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions enabled
    # This one blocks Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions enabled
    # This one blocks executable content from email client and webmail 
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions enabled
    # This one blocks JavaScript or VBScript from launching downloaded executable content 
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions enabled
    # This one blocks persistence through WMI event subscription
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions enabled
    # This one blocks credential stealing from the Windows local security authority subsystem (LSASS.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions enabled
    # This one blocks Office applications from creating executable content. 
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enabled
}

# This function removes the ASRLevel1 rule sets from that machine. You can grab any specific ones individually from below as well to run just that subset. 
function Disable-ASRLevel1 {
    # This one blocks untrusted and unsigned processes that run from USB 
    Set-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions disabled
    # This one blocks Adobe Reader from creating child processes
    Set-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions disabled
    # This one blocks executable content from email client and webmail 
    Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions disabled
    # This one blocks JavaScript or VBScript from launching downloaded executable content 
    Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions disabled
    # This one blocks persistence through WMI event subscription
    Set-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions disabled
    # This one blocks credential stealing from the Windows local security authority subsystem (LSASS.exe)
    Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions disabled
    # This one blocks Office applications from creating executable content. 
    Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions disabled
}


# Enable ASR Policies: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell
# Additional references: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide
# Guid tells which rule set is being used, notated below
# Enabled = Block, AuditMode = generates an event log 1121/1122, Disabled turns the rule off. 
function Enable-ASRLevel2 {
    # This one blocks Office Applications from injecting code into other Processes 
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enabled
    # This one blocks Win32 API calls from Office macros
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enabled
    # This one blocks all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions enabled
    # This one blocks executiong of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions enabled
}


# This function removes the ASRLevel2 rule sets from that machine. You can grab any specific ones individually from below as well to run just that subset. 
function Disable-ASRLevel2 {
    # This one blocks Office Applications from injecting code into other Processes 
    Set-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions disabled
    # This one blocks Win32 API calls from Office macros
    Set-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions disabled
    # This one blocks all Office applications from creating child processes
    Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions disabled
    # This one blocks executiong of potentially obfuscated scripts
    Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions disabled
}


# Enable ASR Policies: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell
# Additional references: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide
# Guid tells which rule set is being used, notated below
# Enabled = Block, AuditMode = generates an event log 1121/1122, Disabled turns the rule off. 
function Enable-ASRLevel3 {
    # This one adds advanced protection against ransomware
    Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions enabled
    # This one blocks process creations originating from PSExec and WMI commands 
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enabled
    # This one blocks Office communication applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions enabled
}


# Enable ASR Policies: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell
# Additional references: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide
# Guid tells which rule set is being used, notated below
# Enabled = Block, AuditMode = generates an event log 1121/1122, Disabled turns the rule off. 
function Enable-ASRLevel4 {
    # This one blocks executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions enabled
}

function Disable-ASRLevel4 {
    # This one blocks executable files from running unless they meet a prevalence, age, or trusted list criterion
    Set-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions disabled
}



# Disable IPv6 for all network adapters for abuse reasons {L3}
function Disable-IPv6ALL {
    Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

# If issues disabling IPv6 across all adapters, you can re-enable across all adapters: 
function Enable-IPv6ALL {
    Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6
}

# Restrict NULL Sessions{L2}
function Disable-NullSessions{
    $registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa\";
    If ( !(Test-Path $registryPath) ) { New-Item -Path $registryPath -Force; };
    New-ItemProperty -Path $registryPath -Name "RestrictAnonymous" -Value 1 -PropertyType DWORD -Force;
    New-ItemProperty -Path $registryPath -Name "RestrictAnonymousSAM" -Value 1 -PropertyType DWORD -Force;
    New-ItemProperty -Path $registryPath -Name "EveryoneIncludesAnonymous" -Value 0 -PropertyType DWORD -Force;

    <#
    HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymous
        1 – Null sessions can not be used to enumerate shares
    HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM
        1 – Default setting. Null sessions can not enumerate user names
    HKLM\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous
        0 – Default setting. Null sessions have no special rights
    #>
}

# Restrict Scheduled Jobs running from AT.exe, and restrict task scheduler to only be allowed to be change by Administrator {L2}
function Disable-ATAdminPriv{
    $registryPath = "HKLM:SYSTEM\CurrentControlSet\Control\Lsa";
    If ( !(Test-Path $registryPath) ) { New-Item -Path $registryPath -Force; };
    New-ItemProperty -Path $registryPath -Name "SubmitControl" -Value 0 -PropertyType DWORD -Force;
}

# Enable LSA protection {L3}
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL DWORD Value 1 
function Enable-LSAProtect{
    $registryPath = "HKLM:SYSTEM\CurrentControlSet\Control\Lsa";
    If ( !(Test-Path $registryPath) ) { New-Item -Path $registryPath -Force; };
    New-ItemProperty -Path $registryPath -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force;
}


# Disable WDigest {L2}
# HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest
function Disable-WDigestCache{
    $registryPath = "HKLM:System\CurrentControlSet\Control\SecurityProviders";
    If ( !(Test-Path $registryPath) ) { New-Item -Path $registryPath -Force; };
    New-ItemProperty -Path $registryPath -Name "WDigest" -Value 0 -PropertyType DWORD -Force;
}


# Disabling Admin Shares {L4}
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters DWORD = AutoShareWks 0 to disable
function Disable-AdminShares{
    $registryPath = "HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    If ( !(Test-Path $registryPath) ) { New-Item -Path $registryPath -Force; };
    New-ItemProperty -Path $registryPath -Name "AutoShareWks" -Value 0 -PropertyType DWORD -Force;
}



# Going through the Level 1 style hardening scripts
function Set-Level1Harden {
    Disable-WPAD
    Disable-NetBIOSoverTCP
    Disable-LLMNR
    Enable-SmbSigning
    Enable-NTLMv2Only
    Set-LogFirewallProfile
    Test-SMBv3Vuln
    Enable-ASRLevel1
}



# Going through the Level 2 style hardening scripts 
function Set-Level2Harden {
    Disable-PowerShellv2
    Enable-PSScriptBlockLogging
    Enable-PSCLM
    Enable-ASRLevel2
    Disable-NullSessions
    Disable-ATAdminPriv
}

# Undo the Level2Harden scripts
function Disable-Level2Harden {
    Disable-PSCLM
    Disable-ASRLevel2
}



# # Going through the Level 3 style hardening scripts
function Set-Level3Harden {
    Disable-SMBv1
    Disable-IPv6ALL
    Enable-LSAProtect
}

# Unset the Level 3 hardening scripts
function Disable-Level3Harden{
    Enable-IPv6ALL

}


# # Going through the Level 4 style hardening scripts
function Set-Level4Harden {
    Enable-ASRLevel4
    Disable-AdminShares
}



function Disable-Level4Harden{
    Disable-ASRLevel4
}



