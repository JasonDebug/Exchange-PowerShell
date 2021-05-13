#
# Set-OwaSslOffload.ps1
# Modified 2021MAY10
# Last Modifier:  Jason Slaughter
# Project Owner:  Jason Slaughter
# Version: v1.0
#
## Autodownload of URL Rewrite Module pulled from https://github.com/microsoft/CSS-Exchange/blob/c57bbada7d19ebc77c1300fd076ab8ad2ead7ed9/Security/src/ExchangeMitigations.ps1

<#
.SYNOPSIS
    This creates URL Rewrite rules to mitigate issues stemming from the Chromium SameSite=None changes

.DESCRIPTION
    This script will create or remove two URL Rewrite module rules:
    
    1. 'OWA SSL Offload - Cookie Fix' - Sets the HTTPS server variable when the NLB/SSL offloading device sends
    the "X-Forwarded-Proto: https" header (configured separately).  This is the de-facto standard header used
    to identify the protocol (http or https) the client used to connect.

    2. 'OWA SSL Offload - Logout Fix' - Rewrites the logoff redirect to https when logging out of OWA.

    For IIS 10 and higher URL Rewrite Module 2.1 must be installed, you can download version 2.1 (x86 and x64) here:
    * x86 & x64 -https://www.iis.net/downloads/microsoft/url-rewrite
    For IIS 8.5 and lower Rewrite Module 2.0 must be installed, you can download version 2.0 here:
    * x86 - https://www.microsoft.com/en-us/download/details.aspx?id=5747
    * x64 - https://www.microsoft.com/en-us/download/details.aspx?id=7435
    It is important to follow these version guidelines as it was found installing the newer version of the URL rewrite module on older versions of IIS (IIS 8.5 and lower) can cause IIS and Exchange to become unstable.
    If you find yourself in a scenario where a newer version of the IIS URL rewrite module was installed on an older version of IIS, uninstalling the URL rewrite module and reinstalling the recommended version listed above should resolve any instability issues.

.PARAMETER FullPathToMSI
    This is string parameter is used to specify path of MSI file of URL Rewrite Module.

.PARAMETER AutoDownloadURLRewrite
    If set will automatically download/install the IIS URL Rewrite Module.

.PARAMETER DisableSslRequirement
    If set will disable the SSL requirement on the OWA virtual directory.

.PARAMETER Remove
    If set will remove the SSL offload rules.
#>
[CmdLetBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
param(
    [System.IO.FileInfo]$FullPathToMSI,
    [switch]$AutoDownloadURLRewrite,
    [switch]$DisableSslRequirement,
    [switch]$Remove
)

function GetMsiProductVersion {
    param (
        [string]$filename
    )

    try {
        $windowsInstaller = New-Object -com WindowsInstaller.Installer

        $database = $windowsInstaller.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $Null,
            $windowsInstaller, @($filename, 0)
        )

        $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"

        $View = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $Null, $database, ($q)
        )

        try {
            $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) | Out-Null

            $record = $View.GetType().InvokeMember(
                "Fetch", "InvokeMethod", $Null, $View, $Null
            )

            $productVersion = $record.GetType().InvokeMember(
                "StringData", "GetProperty", $Null, $record, 1
            )

            return $productVersion
        } finally {
            if ($View) {
                $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null) | Out-Null
            }
        }
    } catch {
        throw "Failed to get MSI file version the error was: {0}." -f $_
    }
}

function Get-InstalledSoftwareVersion {
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    try {
        $UninstallKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )

        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
            "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        }

        foreach ($UninstallKey in $UninstallKeys) {
            $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue
            foreach ($n in $Name) {
                $SwKeys = $SwKeys | Where-Object { $_.GetValue('DisplayName') -like "$n" }
            }
            if ($SwKeys) {
                foreach ($SwKey in $SwKeys) {
                    if ($SwKey.GetValueNames().Contains("DisplayVersion")) {
                        return $SwKey.GetValue("DisplayVersion")
                    }
                }
            }
        }
    } catch {
        Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
    }
}

function GetURLRewriteLink {
    $DownloadLinks = @{
        "v2.1" = @{
            "x86" = @{
                "de-DE" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-TW.msi"
            }

            "x64" = @{
                "de-DE" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-TW.msi"
            }
        }
        "v2.0" = @{
            "x86" = @{
                "de-DE" = "https://download.microsoft.com/download/0/5/0/05045383-D280-4DC6-AE8C-81764118B0F9/rewrite_x86_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/6/9/C/69C1195A-123E-4BE8-8EDF-371CDCA4EC6C/rewrite_2.0_rtw_x86.msi"
                "es-ES" = "https://download.microsoft.com/download/1/D/9/1D9464B8-9F3B-4A86-97F2-AEC2AB48F481/rewrite_x86_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/1/2/9/129A2686-9654-4B2A-82ED-FC7BCE2BCE93/rewrite_x86_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/2/4/A/24AE553F-CA8F-43B3-ACF8-DAC526FC84F2/rewrite_x86_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/A/6/9/A69D23A5-7CE3-4F80-B5AE-CF6478A5DE19/rewrite_x86_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/2/6/F/26FCA84A-48BC-4AEE-BD6A-B28ED595832E/rewrite_x86_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/B/1/F/B1FDE19F-B4F9-4EBF-9E50-5C9CDF0302D2/rewrite_x86_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/4/9/C/49CD28DB-4AA6-4A51-9437-AA001221F606/rewrite_x86_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/1/9/4/1947187A-8D73-4C3E-B62C-DC6C7E1B353C/rewrite_x86_zh-TW.msi"
            }
            "x64" = @{
                "de-DE" = "https://download.microsoft.com/download/3/1/C/31CE0BF6-31D7-415D-A70A-46A430DE731F/rewrite_x64_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/6/7/D/67D80164-7DD0-48AF-86E3-DE7A182D6815/rewrite_2.0_rtw_x64.msi"
                "es-ES" = "https://download.microsoft.com/download/9/5/5/955337F6-5A11-417E-A95A-E45EE8C7E7AC/rewrite_x64_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/3/D/3/3D359CD6-147B-42E9-BD5B-407D3A1F0B97/rewrite_x64_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/6/8/B/68B8EFA8-9404-45A3-A51B-53D940D5E742/rewrite_x64_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/3/7/5/375C965C-9D98-438A-8F11-7F417D071DC9/rewrite_x64_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/2/A/7/2A746C73-467A-4BC6-B5CF-C4E88BB40406/rewrite_x64_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/7/4/E/74E569F7-44B9-4D3F-BCA7-87C5FE36BD62/rewrite_x64_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/4/E/7/4E7ECE9A-DF55-4F90-A354-B497072BDE0A/rewrite_x64_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/8/2/C/82CE350D-2068-4DAC-99D5-AEB2241DB545/rewrite_x64_zh-TW.msi"
            }
        }
    }

    $IISVersion = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ | Select-Object versionstring

    if ($IISVersion.VersionString -like "* 10.*") {
        $Version = "v2.1"
    } else {
        $Version = "v2.0"
    }

    if ([Environment]::Is64BitOperatingSystem) {
        $Architecture = "x64"
    } else {
        $Architecture = "x86"
    }

    if ((Get-Culture).Name -in @("de-DE", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "ko-KR", "ru-RU", "zn-CN", "zn-TW")) {
        $Language = (Get-Culture).Name
    } else {
        $Language = "en-US"
    }

    return $DownloadLinks[$Version][$Architecture][$Language]
}

function AddOffloadRules {
    Write-Verbose "[INFO] Starting mitigation process on $env:computername" -Verbose

    #Check if IIS URL Rewrite Module 2 is installed
    Write-Verbose "[INFO] Checking for IIS URL Rewrite Module 2 on $env:computername" -Verbose

    #If IIS 10 check for URL rewrite 2.1 else URL rewrite 2.0
    $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"
    $IISVersion = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ | Select-Object versionstring

    $RewriteModuleInstallLog = ($PSScriptRoot + '\' + 'RewriteModuleInstallLog.log')

    #Install module
    if ($RewriteModule) {

        #Throwing an exception if incorrect rewrite module version is installed
        if ($IISVersion.VersionString -like "*10.*" -and ($RewriteModule.Version -eq "7.2.2")) {
            throw "Incorrect IIS URL Rewrite Module 2.0 Installed. You need to install IIS URL Rewrite Module 2.1 to avoid instability issues."
        }
        if ($IISVersion.VersionString -notlike "*10.*" -and ($RewriteModule.Version -eq "7.2.1993")) {
            throw "Incorrect IIS URL Rewrite Module 2.1 Installed. You need to install IIS URL Rewrite Module 2.0 to avoid instability issues."
        }

        Write-Verbose "[INFO] IIS URL Rewrite Module 2 already installed on $env:computername" -Verbose
    } else {

        #IfAutoDownloadURLRewrite
        if ($AutoDownloadURLRewrite) {
            Write-Verbose -Message "Attempting to download and install the IIS URL Rewrite Module on $env:computername" -Verbose
            try {
                # Force TLS1.2 to make sure we can download from HTTPS
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $ProgressPreference = "SilentlyContinue"
                $DownloadDir = Join-Path $env:TEMP "IISUrlRewrite"
                $DownloadLink = GetURLRewriteLink
                $FullPathToMSI = Join-Path $DownloadDir "\$($DownloadLink.Split("/")[-1])"
                if (!(Test-Path $DownloadDir)) {
                    New-Item -ItemType Directory $DownloadDir | Out-Null
                }
                Write-Verbose -Message "Downloading IIS URLRewrite MSI here: $FullPathToMSI" -Verbose
                $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
                [IO.File]::WriteAllBytes($FullPathToMSI, $response.Content)
            } catch {
                throw $_
            }
        }

        if ($FullPathToMSI) {

            $MSIProductVersion = GetMsiProductVersion -filename $FullPathToMSI

            #If IIS 10 assert URL rewrite 2.1 else URL rewrite 2.0
            if ($IISVersion.VersionString -like "*10.*" -and $MSIProductVersion -eq "7.2.2") {
                throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.1"
            }
            if ($IISVersion.VersionString -notlike "*10.*" -and $MSIProductVersion -eq "7.2.1993") {
                throw "Incorrect MSI for IIS $($IISVersion.VersionString), please use URL rewrite 2.0"
            }

            Write-Verbose "[INFO] Installing IIS URL Rewrite Module 2" -Verbose
            $arguments = " /i " + '"' + $FullPathToMSI.FullName + '"' + " /quiet /log " + '"' + $RewriteModuleInstallLog + '"'
            $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"
            Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
            Start-Sleep -Seconds 15
            $RewriteModule = Get-InstalledSoftware -Name *IIS* | Where-Object { $_.Name -like "*URL*" -and $_.Name -like "*2*" }
            if ($RewriteModule) {
                Write-Verbose "[OK] IIS URL Rewrite Module 2 installed on $env:computername"
            } else {
                throw "[ERROR] Issue installing IIS URL Rewrite Module 2, please review $($RewriteModuleInstallLog)"
            }
        } else {
            throw "[ERROR] Unable to proceed on $env:computername, path to IIS URL Rewrite Module MSI not provided and module is not installed."
        }
    }

    Write-Verbose "[INFO] Applying rewrite rule configuration to $env:COMPUTERNAME :: $($owaWebConfig.FullName)"

    try
    {
        if ($DisableSslRequirement) {
            # Remove the HTTPS requirement from OWA
            Set-WebConfigurationProperty -PSPath $iisRoot -location $owaAppInfo.Name -Filter "system.webServer/security/access" -name "sslFlags" -value "None"
        }

        # Enable the HTTPS serverVariable
        if ((Get-WebConfigurationProperty -PSPath $iisRoot -location $owaAppInfo.Name -Filter "system.webServer/rewrite/allowedServerVariables/add" -name "name" | Where-Object { $_.Value -eq "HTTPS" }).Count -eq 0) {
            Add-WebConfigurationProperty -PSPath $iisRoot -location $owaAppInfo.Name -Filter "system.webServer/rewrite/allowedServerVariables" -name "." -value @{name='HTTPS'}
        }

        # Clear old configurations
        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $CookieFixFilter).Name -eq $CookieFixName) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $CookieFixFilter
        }

        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter -Location "auth").Name -eq $LogoutFixName) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter -Location "auth"
        }
		
        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter2 -Location "auth").Name -eq $LogoutFixName2) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter2 -Location "auth"
        }

        # Configure the OWA SSL Offload - Cookie Fix
        Add-WebConfigurationProperty -PSPath $owaRoot -Filter $root -name "." -value @{name=$CookieFixName;patternSyntax='Wildcard'}
        Set-WebConfigurationProperty -PSPath $owaRoot -Filter "$CookieFixFilter/match" -name "url" -value "*"
        Add-WebConfigurationProperty -PSPath $owaRoot -Filter "$CookieFixFilter/conditions" -name "." -value @{input='{HTTP_X_FORWARDED_PROTO}';pattern='https'}
        Add-WebConfigurationProperty -PSPath $owaRoot -Filter "$CookieFixFilter/serverVariables" -name "." -value @{name='HTTPS';value='on'}
        
        # Configure the OWA SSL Offload - Logoff Fix
        Add-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter $root -name "." -value @{name=$LogoutFixName;patternSyntax='Wildcard';stopProcessing='True'}
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter/match" -name "url" -value "auth/logon.aspx"
        Add-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter/conditions" -name "." -value @{input='{QUERY_STRING}';pattern='*url=*%3a80*'}
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter/action" -name "type" -value "Redirect"
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter/action" -name "url" -value "https://{HTTP_HOST}/owa/auth/logon.aspx?{C:1}url={C:2}{C:3}"
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter/action" -name "appendQueryString" -value "False"

		# Configure the OWA SSL Offload - Logoff Fix2 (I don't actually see this behavior in the latest CU/SUs)
        Add-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter $root -name "." -value @{name=$LogoutFixName2;patternSyntax='Wildcard';stopProcessing='True'}
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter2/match" -name "url" -value "auth/logon.aspx"
        Add-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter2/conditions" -name "." -value @{input='{QUERY_STRING}';pattern='*url=http%3a%2f%2f*'}
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter2/action" -name "type" -value "Redirect"
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter2/action" -name "url" -value "https://{HTTP_HOST}/owa/auth/logon.aspx?{C:1}url=https%3a%2f%2f{C:2}"
        Set-WebConfigurationProperty -PSPath $owaRoot -Location "auth" -Filter "$LogoutFixFilter2/action" -name "appendQueryString" -value "False"
        
        # Due to the way OWA uses the same physical path for multiple virtual directories, the location tag is used.  Unfortunately there
        # isn't a great way to handle the location tag with the WebAdministration snapin, since Exchange doesn't use a path attribute.
        # So, we manually move the rules to the system.webServer node under the un-named location tag.  If there are any other custom rules
        # already here, they should be moved to the OWA root too, otherwise they'll throw a 500 error for the other vdirs under /owa.

        # Load the web.config for HttpProxy/owa
        $xmlDoc = New-Object System.Xml.XmlDocument
        $xmlDoc.Load($owaWebConfig.FullName)
        
        # Move the rewrite node to the Location/system.webServer node
        $rewriteNode = $xmlDoc.SelectSingleNode("configuration/system.webServer/rewrite")
        if ($rewriteNode) {
            $xmlDoc.SelectSingleNode("configuration/location/system.webServer").AppendChild($rewriteNode)
            
            # Find and remove the old node that isn't under Location
            $nodeToRemove = $xmlDoc.SelectSingleNode("configuration/system.webServer")
            $xmlDoc.SelectSingleNode("configuration").RemoveChild($nodeToRemove)
            
            # Save the web.config
            $xmlDoc.Save($owaWebConfig.FullName)
        }

        Write-Verbose "[OK] Rewrite rule configuration complete for $env:COMPUTERNAME :: $($owaWebConfig.FullName)"

        Get-WebConfiguration -PSPath $owaRoot -Filter $CookieFixFilter
        Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter -Location "auth"
        Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter2 -Location "auth"
    }
    catch {
        throw $_
    }
}

function RemoveOffloadRules {
    Write-Verbose "[INFO] Removing rewrite rule configuration from $env:COMPUTERNAME :: $($owaWebConfig.FullName)"

    try {
        # Clear old configurations
        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $CookieFixFilter).Name -eq $CookieFixName) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $CookieFixFilter
        }

        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter -Location "auth").Name -eq $LogoutFixName) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter -Location "auth"
        }
		
        if ((Get-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter2 -Location "auth").Name -eq $LogoutFixName2) {
            Clear-WebConfiguration -PSPath $owaRoot -Filter $LogoutFixFilter2 -Location "auth"
        }

        Write-Verbose "[OK] Rewrite rule configuration complete for $env:COMPUTERNAME :: $($owaWebConfig.FullName)"   
    }
    catch {
        throw $_
    }
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Script must be executed as administrator, please close and re-run Exchange Mangement Shell as administrator"
    return
}
if ($PSVersionTable.PSVersion.Major -lt 3) {
    throw "PowerShell does not meet the minimum requirements, system must have PowerShell 3 or later"
}

Import-Module WebAdministration

#Configure Rewrite Rule consts
$CookieFixName = 'OWA SSL Offload - Cookie Fix'
$LogoutFixName = 'OWA SSL Offload - Logout Fix'
$LogoutFixName2 = 'OWA SSL Offload - Logout Fix2'
$root = 'system.webServer/rewrite/rules'
$CookieFixFilter = "{0}/rule[@name='{1}']" -f $root, $CookieFixName
$LogoutFixFilter = "{0}/rule[@name='{1}']" -f $root, $LogoutFixName
$LogoutFixFilter2 = "{0}/rule[@name='{1}']" -f $root, $LogoutFixName2

$owaAppInfo = Get-WebConfigurationLocation | Where-Object { $_.Name.ToLower().EndsWith("owa") -and !$_.Name.ToLower().StartsWith("exchange back end") }
$iisRoot = $owaAppInfo.PSPath
$owaRoot = "$($owaAppInfo.PSPath)/$($owaAppInfo.Name)"
$owaWebConfig = Get-WebConfigFile -PSPath $owaRoot

if ($Remove) {
    RemoveOffloadRules -ErrorAction Stop
}
else {
    AddOffloadRules -ErrorAction Stop
}
