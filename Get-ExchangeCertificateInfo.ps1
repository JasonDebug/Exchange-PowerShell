#
# Get-ExchangeCertificateInfo.ps1
#
# CHANGELOG:
# 
# 2021AUG12
# - Checking vdirs must be explicitly set now with -checkVdirs
# - Fixed enum compatibility issue with PS4 and lower
# v1.0.2 - Added permissions check for the MachineKeys folder
# v1.0.1 - Added -skipVdirs switch
# v1.0.0 - Initial commit

<#
    .SYNOPSIS
        Checks for known Exchange-related certificate issues.
    
    .DESCRIPTION
        This will test various attributes of the given certificate against known Exchange-related certificate issues.
        - Key storage location / accessibility (Exchange only supports CSG / X509Certificate2)
        - Revocation check
        - IIS binding
        - Virtual directory names
        - Validity period
    
    .PARAMETER Thumbprint
        The thumbprint of the certificate to test
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()][string]$thumbprint = $(throw "Certificate thumbprint is a mandatory parameter, please provide valid value."),
    [switch]$checkVdirs
)

function LogResult {
    [CmdletBinding()]
    param(
        [string]$Message,
        [switch]$fail,
        [switch]$info,
        [switch]$wait
    )
    
    $color = "Green"
    $status = "[PASS]"
    
    if ($fail) {
        $color = "Red"
        $status = "[FAIL]"
    }
    
    if ($info) {
        $status = "[INFO]"
        $color = "Gray"
    }
    
    Write-Host "    $status $Message" -ForegroundColor $color -NoNewLine:$wait
}

function LogStep {
    [CmdletBinding()]
    param(
        [string]$Message
    )
    
    Write-Host "`n$Message" -ForegroundColor White
}

function LogCertInfo {
    [CmdletBinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$prefix,
        [switch]$extendedInfo
    )
    
    LogResult "$($prefix)Friendly Name : $($cert.FriendlyName)" -Info
    LogResult "$($prefix)Subject       : $($cert.Subject)" -Info
    LogResult "$($prefix)Thumbprint    : $($cert.Thumbprint)" -Info
    
    if ($extendedInfo) {
        LogResult "$($prefix)HasPrivateKey : $($cert.HasPrivateKey)" -Info
        LogResult "$($prefix)NotBefore     : $($cert.NotBefore)" -Info
        LogResult "$($prefix)NotAfter      : $($cert.NotAfter)" -Info
        LogResult "$($prefix)DNS Names     :" -Info
            ForEach ($dnsName in $cert.DnsNameList) {
                LogResult "$($prefix)  $dnsName" -Info
            }
        LogResult "$($prefix)Key Usage     :" -Info
            ForEach ($usage in $cert.EnhancedKeyUsageList) {
                LogResult "$($prefix)  $($usage.FriendlyName)" -Info
            }
    }
}

function LogNewLine {
    Write-Host "`n" -NoNewLine
}

# Maybe a bit brute-force on this first iteration :P
function MatchCert {
    [CmdletBinding()]
    param(
        $domain,
        $certDomains
    )

    if (!$domain) { return $false }
    
    $fullMatch = $false
    foreach ($certName in $certDomains) {
        
        $certSplit = $certName.ToString().Split('.')
        $domainSplit = $domain.ToString().Split('.')

        if ($certSplit.Count -ne $domainSplit.Count -or ($certSplit.Count -lt 2 -or $domainSplit.Count -lt 2)) {
            continue
        }
        else {
            $start = 0;
            if ($certSplit[0] -eq '*') {
                $start = 1;
            }

            $matched = $true
            for ($i = $start; $i -lt $certSplit.Count; $i++) {
                if ($certSplit[$i] -ne $domainSplit[$i]) {
                    $matched = $false
                }
            }

            if ($matched) {
                return $true
                break
            }
        }
    }
    
    return $false
}

# Known string values for the CSPs listed here.  Add as we find more.
# https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-cryptographic-service-providers
$ValidCspProviders = @(
    "Microsoft Enhanced Cryptographic Provider v1.0",
    "Microsoft RSA SChannel Cryptographic Provider"
)

# This needs to be run in an elevated Exchange management shell
if ((Get-Command Get-OwaVirtualDirectory -ErrorAction SilentlyContinue).Count -eq 0) {
    throw "Script must be executed in the Exchange Management Shell as administrator."
}
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script must be executed as administrator, please close and re-run Exchange Mangement Shell as administrator"
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    throw "PowerShell does not meet the minimum requirements, system must have PowerShell 3 or later"
}

# This is needed to access the IIS path
LogStep "Importing WebAdministration module"
Import-Module WebAdministration

# Check local store for certificate
LogStep "Checking 'Certificates (Local Computer)\Personal' for $thumbprint"

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("MY","LocalMachine")
$store.Open("ReadOnly")
$cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }

if ($cert) {
    LogResult "Certificate $thumbprint found"
    LogCertInfo $cert -prefix "  " -extendedInfo
}
else {
    LogResult "Cert $thumbprint not found in cert store" -Fail
    return
}

# Check IIS bindings
LogStep "Checking binding in IIS"

$binding = Get-ChildItem -Path IIS:SSLBindings | ? { $_.Port -eq 443 -and $_.IPAddress.IPAddressToString -eq "0.0.0.0" }

if ($binding.Thumbprint -eq $thumbprint) {
    LogResult "Certificate is bound"
}
else {
    LogResult "Certificate is not bound to 443 on * in IIS" -Fail
    
    $boundCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $binding.Thumbprint }
    
    LogResult "  Currently bound certificate:" -Info
    LogCertInfo $boundCert -prefix "    " -extendedInfo

    LogNewLine

    LogResult "To bind this certificate to IIS, run this in EMS:" -info
    LogResult "    Enable-ExchangeCertificate $thumbprint -Services IIS -Server (hostname)" -info
}

# Check private key
LogStep "Checking key storage provider for private key"

if ($cert.PrivateKey -and $cert.PrivateKey.CspKeyContainerInfo -and $cert.PrivateKey.CspKeyContainerInfo.ProviderName) {
    LogResult "Private key found.  Exportable: $($cert.PrivateKey.CspKeyContainerInfo.Exportable)"

    if ($ValidCspProviders.Contains($cert.PrivateKey.CspKeyContainerInfo.ProviderName)) {
        LogResult "  '$($cert.PrivateKey.CspKeyContainerInfo.ProviderName)' is a valid CSP for Exchange" -Info
    }
    else {
        LogResult "  '$($cert.PrivateKey.CspKeyContainerInfo.ProviderName)' may not be a valid CSP for Exchange" -Fail
    }
}
else {
    LogResult "Private key inaccessible by Exchange." -Fail
}

LogStep "Checking validity period"

if ($cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -lt (Get-Date)) {
    LogResult "Current date and time is outside the period from $($cert.NotBefore) and $($cert.NotAfter)" -Fail
}
else {
    LogResult "Validity period is valid - days left: $(($cert.NotAfter - (Get-Date)).Days)"
}

LogStep "Checking cert against virtual directory settings on $(hostname)"

if ($checkVdirs) {
    $vdirList = @(
        "ActiveSyncVirtualDirectory",
        "EcpVirtualDirectory",
        "MapiVirtualDirectory",
        "OabVirtualDirectory",
        "OwaVirtualDirectory",
        "PowerShellVirtualDirectory",
        "WebServicesVirtualDirectory"
    )
    
    ForEach ($vdir in $vdirList) {
        $vdirTest = Invoke-Expression "Get-$vdir -Server (hostname)"

        $testFailed = !(MatchCert -domain $vdirTest.InternalUrl.Host -certDomains $cert.DnsNameList)
        LogResult "$vdir InternalUrl $($vdirTest.InternalUrl)" -Fail:$testFailed

        $testFailed = !(MatchCert -domain $vdirTest.ExternalUrl.Host -certDomains $cert.DnsNameList)
        LogResult "$vdir ExternalUrl $($vdirTest.ExternalUrl)" -Fail:$testFailed

        LogNewLine
    }

    # Outlook Anywhere (/rpc)
    $vdirTest = Get-OutlookAnywhere -Server (hostname)

    $testFailed = !(MatchCert -domain $vdirTest.InternalHostname -certDomains $cert.DnsNameList)
    LogResult "OutlookAnywhere InternalHostname $($vdirTest.InternalHostname)" -Fail:$testFailed

    $testFailed = !(MatchCert -domain $vdirTest.ExternalHostname -certDomains $cert.DnsNameList)
    LogResult "OutlookAnywhere ExternalHostname $($vdirTest.ExternalHostname)" -Fail:$testFailed

    LogNewLine

    # Autodiscover
    $vdirTest = Get-ClientAccessServer (hostname) -WarningAction:SilentlyContinue

    if ($vdirTest) {
        $testFailed = !(MatchCert -domain $vdirTest.AutoDiscoverServiceInternalUri.Host -certDomains $cert.DnsNameList)
        LogResult "AutoDiscoverServiceInternalUri $($vdirTest.AutoDiscoverServiceInternalUri)" -Fail:$testFailed
    }
}

# Certutil tests
LogStep "Checking certificate revocation status"

$tempCert = "$env:TEMP\$($cert.Thumbprint).crt"
$certExport = certutil -store my $($cert.Thumbprint) $tempCert

if (Test-Path $tempCert) {
    $certTest = certutil -verify -urlfetch $tempCert
    
    $certTest = $certTest | Select-String -Pattern "certificate revocation"
    if ($certTest | Select-String -Pattern "passed") {
        LogResult $certTest
    }
    else {
        LogResult $certTest -Fail
    }
    
    Remove-Item $tempCert
}

# Permissions checks
$keysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
LogStep "Checking ACL for $keysPath"

$keysAcl = Get-Acl $keysPath

$testFailed = $keysAcl.Owner -ne 'NT AUTHORITY\SYSTEM'

LogResult "Owner: $($keysAcl.Owner)" -Fail:$testFailed

if ($testFailed) {
    LogResult "    The owner should be 'NT AUTHORITY\SYSTEM'" -Info
}

# Checking the Everyone ACE
$testAclName = "Everyone"
$testAcl = $keysAcl.Access | where { $_.IdentityReference -eq $testAclName }

if ($testAcl) {
    $expectedRights = [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Read -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize

    LogResult "'$testAclName' ACE found"

    if ($testAcl.FileSystemRights -ne $expectedRights -or
        $testAcl.AccessControlType -ne 'Allow') {
        LogResult "    $($testAcl.FileSystemRights) does not match $expectedRights" -fail
        LogResult "    Add '$testAclName' with Read and Write Special permissions applied to 'This folder only'." -info
    }
}
else {
    LogResult "    Missing '$testAclName' ACE" -fail
    LogResult "    Add '$testAclName' with Read and Write Special permissions applied to 'This folder only'." -info
}

# Checking the built-in admins group ACE
$testAclName = 'BUILTIN\Administrators'
$testAcl = $keysAcl.Access | where { $_.IdentityReference -eq $testAclName }

if ($testAcl) {
    $expectedRights = [System.Security.AccessControl.FileSystemRights]::FullControl

    LogResult "'$testAclName' ACE found"

    if ($testAcl.FileSystemRights -ne $expectedRights -or
        $testAcl.AccessControlType -ne 'Allow') {
        LogResult "    $($testAcl.FileSystemRights) does not match $expectedRights" -fail
        LogResult "    Add '$testAclName' with Full control permissions applied to 'This folder only'." -info
    }
}
else {
    LogResult "    Missing '$testAclName' ACE" -fail
    LogResult "    Add '$testAclName' with Full control permissions applied to 'This folder only'." -info
}

# Check for extra ACEs
foreach ($acl in $keysAcl.Access) {
    if ($acl.IdentityReference -ne 'Everyone' -and
        $acl.IdentityReference -ne 'BUILTIN\Administrators') {
        LogResult "Additional ACE in ACL: $($acl.IdentityReference)" -fail
    }
}

LogNewLine
