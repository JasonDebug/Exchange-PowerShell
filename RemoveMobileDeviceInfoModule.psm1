# 
# RemoveMobileDeviceInfoModule.psm1
# 
# Copyright (c) Microsoft Corporation
# All rights reserved.
# 
# MIT License
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
# to whom the Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#--------------------------------------------------------------------------------- 
#
# Changelog:
# 
# 2018APR27
# - Initial commit on GitHub/JasonDebug/PS_Remove-MobileDeviceInfo

function Remove-MobileDeviceInfo
{
    <#
    .Synopsis
    Clears ActiveSync mailbox logs and removes orphaned SyncState information from a mailbox

    .Description
    As of Exchange 2010, the MaxSizeOfMailboxLog and NumOfQueuedMailboxLogEntries settings in
    the web.config for ActiveSync are no longer configurable.  This results in possibly bloated EAS
    mailbox log folders in users' mailboxes, and this script can remove those folders.

    In addition, EAS sync states can occasionally get orphaned in the mailbox, and this script
    can also assist in removing stale sync states or sync states that are orphaned.

    .Example
    $cred = Get-Credential
    C:\PS>Remove-MobileDeviceInfo -User 2010user1 -Credential:$cred -PurgeLogs

    This will use the credentials from Get-Credential, and remove both the EAS mailbox logs as well as
      SyncState information from the mailbox.

    .Example
    Remove-MobileDeviceInfo -User 2010user1 -PurgeLogsOnly

    This will remove the EAS mailbox logs only, and not touch the SyncState information in the mailbox.  Since
      credentials were not passed, this will use the currently logged-in user account.

    .Example
    Remove-MobileDeviceInfo -User 2010user1 -DeviceId ABCDEF123456 -PromptForCreds

    This will remove only the mobile device with a DeviceId of ABCDEF123456.  This honors the -PurgeLogs option.
      The script will prompt for the credentials of an account to do the work.

    .Example
    $mbx = Get-Mailbox -Server 2010.contoso.com
    C:\PS>$mbx | Remove-MobileDeviceInfo -Credential:$cred

    This will clean up all mailboxes in $mbx.  Note that in Exchange 2010, you MUST assign the Get-Mailbox output
      to a variable, as remote PowerShell will not allow the Get-Mailbox pipeline run concurrently with this
      script.

    .Parameter User
    The User parameter specifies the target user's alias, email address, user principal name, or Mailbox object
      from Get-Mailbox.
    
    .Parameter Credential
    The Credential parameter specifies the credentials to use for the impersonation account.
    
    .Parameter PromptForCreds
    The PromptForCreds switch will force a prompt for credentials.  If Credential and PromptForCreds are not set
      the script will use the currently logged-in user.

    .Parameter UseDefaultCredentials
    The UseDefaultCredentials parameter specifies whether to use the current user for EWS impersonation.  This
      defaults to $true.

    .Parameter UseLocalHost
    The UseLocalHost parameter specifies whether to use the local machine's hostname for the EWS endpoint.

    .Parameter EwsUrl
    The EwsUrl specifies the EWS URL to use.

    .Parameter TraceEnabled
    The TraceEnabled parameter enables EWS tracing.

    .Parameter IgnoreSsl
    The IgnoreSsl parameter specifies whether to ignore SSL validation errors.

    .Parameter PurgeLogs
    The PurgeLogs parameter specifies whether to purge EAS Mailbox Logs.  Without this parameter or PurgeLogsOnly,
      logs will be left alone.

    .Parameter PurgeLogsOnly
    The PurgeLogsOnly parameter specifies whether to purge EAS Mailbox Logs and not touch the SyncState info.  This
      parameter automatically enabled PurgeLogs.

    .Parameter Force
    The Force parameter specifies whether to purge all SyncState info from the mailbox, ignoring last sync time.

    .Parameter PurgeDays = 30
    The PurgeDays parameter specifies the number of days a SyncState must have been idle to get deleted.
    
    .Parameter EwsModulePath
    The EwsModulePath parameter specifies where the EWS Managed API dll is located.  By default the script will search
      common locations such as current directory, script directory, and the Exchange install folder (on-prem only).

    .Parameter DomainController
    The DomainController parameter specifies the fully qualified domain name (FQDN) of the domain controller that
      retrieves data from Active Directory.

    .Parameter DeviceId
    The DeviceId parameter specifies a device id to singularly act upon.

    .Parameter IgnoreImpersonationFailure
    The IgnoreImpersonationFailure parameter specifies whether the script should continue when the RBAC role
      of ApplicationImpersonation is not found.  This occurs when using an account with full mailbox access but
      no impersonation rights.
    #>

	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [alias('Mailbox')]
        [string]$User,
		
		[Parameter(Mandatory=$false)]
		[System.Net.NetworkCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseDefaultCredentials = $true,

        [Parameter(Mandatory=$false)]
        [switch]$UseLocalHost,
        
        [Parameter(Mandatory=$false)]
        [switch]$PromptForCreds,

        [Parameter(Mandatory=$false)]
        [string]$EwsUrl,

        [Parameter(Mandatory=$false)]
        [switch]$TraceEnabled,
        
        [Parameter(Mandatory=$false)]
        [switch]$IgnoreSsl,
        
        [Parameter(Mandatory=$false)]
        [switch]$PurgeLogs,
        
        [Parameter(Mandatory=$false)]
        [switch]$PurgeLogsOnly,
              
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [int]$PurgeDays = 30,
        
        [Parameter(Mandatory=$false)]
        [string]$EwsModulePath,

        [Parameter(Mandatory=$false)]
        [string]$DomainController,

        [Parameter(Mandatory=$false)]
        [string]$DeviceId,

        [Parameter(Mandatory=$false)]
        [switch]$WhatIf = $false,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreImpersonationFailure
	)
	Process
	{
        $verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent

        if ($WhatIf)
        {
            ## This is prepended any time something drastic would normally happen, i.e. removing a device
            $whatIfText = '[WhatIf] '
        }
        else
        {
            $whatIfText = ''
        }
        
        ## Check that we're in EMS, before spending time doing anything else
        if ((Get-Command Get-ActiveSyncDevice -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Count -eq 0)
        {
            Write-Warning 'This script must be executed in the Exchange Management Shell.  Exiting.'
            return
        }
        
        $PSConnection = Get-PSSession | ? { $_.Availability -eq 'Available' -and $_.State -eq 'Opened' -and $_.ComputerName -eq 'outlook.office365.com' } | Select -First 1 -Expand Runspace | Select -Expand ConnectionInfo
        $IsO365 = $PSConnection.Count -gt 0

        ## Check for credentials next.  There's an arbitrary choice here if the user sets PromptForCreds *and* passes $Credential
        if ($PromptForCreds -eq $true)
        {
            ## Wrapped in a try-catch in case the user hits escape or cancel
            try
            {
                [System.Net.NetworkCredential]$Credential = Get-Credential -ErrorAction SilentlyContinue

                if (@(Get-User $Credential.UserName -ErrorAction SilentlyContinue).Count -eq 0)
                {
                    Write-Warning ('Unable to find user ' + $Credential.UserName + '.  Exiting.')
                    return
                }
            }
            catch
            {
                Write-Warning 'User invalid.  Exiting.'
                return
            }
        }
        elseif ($Credential -eq $null)
        {
            if ($UseDefaultCredentials -eq $true)
            {
                if ($IsO365)
                {
                    $Credential = $PSConnection.Credential
                    $LoggedInIdentity = Get-User | ? { $_.UserPrincipalName -eq $PSConnection.Credential.UserName } | Select Identity
                    
                    Write-Verbose ('Defaulting to ' + $Credential.UserName + ' as service account. Use -PromptForCreds or pass -Credential to override.')
                }
                else
                {
                    $Credential = @{UserName = [Environment]::UserName}
                    Write-Verbose ('Using ' + [Environment]::UserDomainName + '\' + [Environment]::UserName + ' as service account. Use -PromptForCreds or pass -Credentials to override.')
                }
            }
            else
            {
                Write-Warning ('No impersonation user specified. Use -PromptForCreds or pass -Credential when setting -UseDefaultCredentials to $false. Exiting...')
                return
            }
        }
        
        if ($IsO365)
        {
            ## Default creds will not work in O365
            $UseDefaultCredentials = $false
        }

        ## Assign Get-ManagementRoleAssignment in case the user isn't found
        if ($DomainController -ne '')
        {
            ## We can pass in $null here, but '' will break the cmdlet
            $DC = $DomainController

            Write-Verbose ('Using ' + $DC + ' for RBAC rights lookup.  ViewEntireForest in ADServerSettings is set to ' + (Get-ADServerSettings).ViewEntireForest)
        }

        ## DomainController parameter may be RBAC'd out, and definitely is in Office 365
        if ((Get-Command Get-ManagementRoleAssignment).Parameters.ContainsKey('DomainController'))
        {
            $rbac = Get-ManagementRoleAssignment -RoleAssignee ($Credential.UserName) -Role ApplicationImpersonation -DomainController $DC -ErrorAction SilentlyContinue
        }
        else
        {
            ## If we're O365 this won't be null and we'll want to use what we populated above
            if ($LoggedInIdentity -eq $null)
            {
                $LoggedInIdentity = $Credential.UserName
            }

            ## Probably O365, but either way, no access to -DomainController parameter
            $rbac = Get-ManagementRoleAssignment -RoleAssignee ($LoggedInIdentity) -Role ApplicationImpersonation -ErrorAction SilentlyContinue
        }
        
        if ($rbac -eq $null -or $rbac.Count -eq 0)
        {
            Write-Warning ('ApplicationImpersonation rights not found for ' + $Credential.UserName + '.')
            Write-Warning 'Note that if impersonation was recently added, it may take some time to replicate.  Use the -DomainController option to specify a DC for lookup (not available in O365).'

            ## Usage examples -- e.g. New-ManagementRoleAssignment –Name:impersonationAssignmentName –Role:ApplicationImpersonation –User:serviceAccount
            Write-Warning 'For more information on configuring impersonation in Exchange, go to https://msdn.microsoft.com/en-us/library/office/bb204095(v=exchg.140).aspx'

            ## Article about management role assignments
            Write-Warning 'For more information on the ApplicationImpersonation role, go to https://technet.microsoft.com/en-us/library/dd776119(v=exchg.150).aspx'

            if ($IgnoreImpersonationFailure)
            {
                Write-Warning '$IgnoreImpersonationFailure is set to $true, continuing.'
            }
            else
            {
                Write-Warning '$IgnoreImpersonationFailure is set to $false, exiting.'
                return
            }
        }
        
        Write-Verbose ('Using ' + $Credential.UserName + ' as service account.')

        ## Load EWS if not already loaded
        if (@(Get-Module -Name Microsoft.Exchange.WebServices).Count -eq 0)
        {
            ## The EWS module is not already loaded.  Check standard paths and load it.
            if ($EwsModulePath -eq '')
            {
                if (Test-Path '.\Microsoft.Exchange.WebServices.dll')
                {
                    ## Always allow a local copy to override
                    $EwsModulePath = '.\Microsoft.Exchange.WebServices.dll'

                    Write-Verbose('Found WebServices dll in current directory.')
                }
                elseif (Test-Path ((Get-Module RemoveMobileDeviceInfoModule).Path.Substring(0, (Get-Module RemoveMobileDeviceInfoModule).Path.LastIndexOf('\')) + '\Microsoft.Exchange.WebServices.dll'))
                {
                    ## Check the path of the module itself
                    $EwsModulePath = (Get-Module RemoveMobileDeviceInfoModule).Path.Substring(0, (Get-Module RemoveMobileDeviceInfoModule).Path.LastIndexOf('\')) + '\Microsoft.Exchange.WebServices.dll'

                    Write-Verbose('Found WebServices dll in same directory as module.')
                }
                elseif (Test-Path ($exbin + '\Microsoft.Exchange.WebServices.dll'))
                {
                    ## Use the EWS module shipped with later versions of Exchange ($exbin doesn't resolve for O365)
                    $EwsModulePath = ($exbin + '\Microsoft.Exchange.WebServices.dll')
                    
                    Write-Verbose('Using the EWS module shipped with Exchange.')
                }
                elseif (Test-Path 'hklm:\SOFTWARE\Microsoft\Exchange\Web Services')
                {
                    ## Try to find the EWS install path from the registry.  This only exists if the managed API was actually installed.
                    $EwsModulePath = (Get-ItemProperty -ErrorAction SilentlyContinue -Path Registry::$(Get-ChildItem -Recurse -Path 'hklm:\SOFTWARE\Microsoft\Exchange\Web Services' | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name)).'Install Directory' +'\Microsoft.Exchange.WebServices.dll'

                    Write-Verbose('Using EWS module path from registry.')
                }
            }
            else
            {
                if ($EwsModulePath -notlike '*.dll')
                {
                    $EwsModulePath = $EwsModulePath + '\Microsoft.Exchange.WebServices.dll'
                }
            }
        
            ## Test whether the physical path is accessible
            if ($EwsModulePath -ne '' -and (Test-Path $EwsModulePath))
            {
                ## Import the module
                Import-Module $EwsModulePath -Verbose:$verbose
                Write-Verbose ("Loaded EWS module version " + (Get-Module Microsoft.Exchange.WebServices).Version + " at " + $EwsModulePath)
            }
            else
            {
                Write-Warning "This script requires the Exchange Web Services Managed API, which was not found."
                Write-Warning "The current EWS Managed API (2.2) can be downloaded from http://www.microsoft.com/en-us/download/details.aspx?id=42951"
                return
            }
        }
        
        $mbx = (Get-Mailbox $User -ErrorAction SilentlyContinue)
        if ($mbx -eq $null)
        {
            Write-Warning ('Unable to find mailbox ' + $User + '.  Exiting.')
            return
        }
        
        if ($mbx.EmailAddresses.GetType().Name -eq 'ProxyAddressCollection')
        {
            ## On-premise
            if ($mbx.EmailAddresses.Count -gt 0)
            {
                foreach ($proxyAddress in $mbx.EmailAddresses)
                {
                    if ($proxyAddress.SmtpAddress -ne $null -and $proxyAddress.IsPrimaryAddress)
                    {
                        $EmailAddress = $proxyAddress.SmtpAddress
                    }
                }
            }
        }
        elseif ($mbx.EmailAddresses.GetType().Name -eq 'ArrayList')
        {
            ## Office 365
            if ($mbx.EmailAddresses.Count -gt 0)
            {
                foreach ($proxyAddress in $mbx.EmailAddresses)
                {
                    if ($proxyAddress.SubString(0, 5) -ceq 'SMTP:')
                    {
                        $EmailAddress = $proxyAddress.SubString(5, $proxyAddress.Length - 5)
                        break
                    }
                }
            }
        }
        
        if ($EmailAddress -eq $null)
        {
            Write-Warning ('Mailbox ' + $User + ' does not have a primary email address.  Exiting.')
            return
        }

        Write-Host ('Working on ' + $User + '...')
		Write-Host 'Gathering ActiveSync device information...'
        
        ## Get-ActiveSyncDevice* is deprecated, but this script may run in Exchange 2010
        $mobileDevicesFromAd = @(Get-ActiveSyncDevice -Mailbox $mbx.Identity -WarningAction SilentlyContinue)
        $mobileDevicesFromMbx = @(Get-ActiveSyncDeviceStatistics -Mailbox $mbx.Identity -WarningAction SilentlyContinue)

        $devices = @()
        
        if ($mobileDevicesFromAd.Count -eq 0)
        {
            Write-Warning 'No devices found from Get-ActiveSyncDevice.'
        }
        else
        {
            Write-Verbose ('Devices from Get-ActiveSyncDevice:')
            foreach ($device in $mobileDevicesFromAd)
            {
                $hashTable = @{'Identity' = $device.Identity; 'DeviceType' = $device.DeviceType; 'DeviceId' = $device.DeviceID; 'Name' = $device.FriendlyName}
                $devices += $hashTable

                Write-Verbose ('- Added ' + $device.DeviceType + '§' + $device.DeviceID)
            }
        }
        
        if ($mobileDevicesFromMbx.Count -eq 0)
        {
            Write-Warning 'No devices found from Get-ActiveSyncDeviceStatistics.'
        }
        else
        {
            Write-Verbose ('Devices from Get-ActiveSyncDeviceStatistics:')
            foreach ($device in $mobileDevicesFromMbx)
            {
                $found = $false;

                ## For each device, check to see if it was already found with Get-ActiveSyncDevice and just add the LastSyncAttemptTime
                foreach ($hashItem in $devices)
                {
                    if ($hashItem.DeviceType -eq $device.DeviceType -and $hashItem.DeviceID -eq $device.DeviceID)
                    {
                        if ($device.LastSyncAttemptTime -ne $null)
                        {
                            $hashItem.LastSyncAttempt = $device.LastSyncAttemptTime
                        }

                        $found = $true
                        Write-Verbose ('- ' + $device.DeviceType + '§' + $device.DeviceID + ' already in list.')
                        break
                    }
                }

                if (!$found)
                {
                    ## The device is not already in the array, add it now
                    $hashTable = @{'Identity' = $device.Identity; 'DeviceType' = $device.DeviceType; 'DeviceID' = $device.DeviceID; 'Name' = $device.DeviceFriendlyName}
                    $devices += $hashTable

                    Write-Verbose ('- Added ' + $device.DeviceType + '§' + $device.DeviceID)
                }
            }
        }
        
        if ($devices.Count -gt 0)
        {
            Write-Verbose ('Found ' + $devices.Count + ' devices for ' + $User + '.')
        }

        ## Ignore SSL warnings due to self-signed certs 
        if ($IgnoreSsl)
        {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        }

        ## We end up with something that looks like this in the resulting hash table:
        ##
        ## Name                           Lumia 920
        ## DeviceType                     WP8
        ## DeviceId                       F94FFAE074DF7E31135B79C07D792F33
        ## Identity                       contoso.com/Users/2013 User1/ExchangeActiveSyncDevices/WP8§F94FFAE074DF7E31135B79C...

        ################
        ##  EWS Calls ##
        ################

        ## Set Exchange Version
        ## Detect this later through GetUserSettings / UserSettingName.CasVersion or through a try catch?
        ## Only tested on 2010 and higher, but we're not doing anything that requires the newer schemas
        #$ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1
        $ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1
  
        ## Create Exchange Service Object
        $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService($ExchangeVersion)
        
        ## Whether or not to use local credentials.  This will not work with O365.
        $service.UseDefaultCredentials = $UseDefaultCredentials

        ## The credentials are set/checked first-thing in this module.  It'll either be a System.Net.NetworkCredential or $null
        ## If $UseDefaultCredentials is not $true, we have either bailed by this point or we have creds
        if ($UseDefaultCredentials -ne $true)
        {
            Write-Verbose("Setting EWS service to use $($Credential.UserName)")
            $service.Credentials = $Credential
        }

        ## This is the target mailbox
        if (!$IgnoreImpersonationFailure)
        {
            $service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $EmailAddress)
        }

        ## Set this to $true and the API should just output tracing to the window, it's very noisy so it's split out separately from -Verbose
        ## https://msdn.microsoft.com/en-us/library/office/dd633676(v=exchg.80).aspx
        $service.TraceEnabled = $TraceEnabled

        ## Get the target EWS url
        if ($IsO365)
        {
            ## This is fairly static, saves a ton of time though
            $service.url = [System.Uri]('https://outlook.office365.com/EWS/Exchange.asmx')
        }
        elseif ($UseLocalHost -eq $true)
        {
            $service.url = [System.Uri]('https://' + $Env:ComputerName + '/EWS/Exchange.asmx')
        }
        elseif ($EwsUrl -ne '')
        {
            $service.url = [System.Uri]$EwsUrl
        }
        else
        {
            try
            {
                Write-Host ('Getting EWS endpoint via Autodiscover, using email address ''' + $EmailAddress + ''' for lookup')
                
                ## Pull target URL using Autodiscover
                $service.AutodiscoverUrl($EmailAddress, {$true})
            }
            catch
            {
                Write-Warning 'Unable to determine EWS endpoint via Autodiscover.'
                Write-Warning '-   Ensure your credentials are correct.'
                Write-Warning '-   Set -UseLocalHost to use the local machine for EWS calls.'
                Write-Warning '-   Set -EwsUrl to configure the endpoint explicitly.'
                return
            }
        }
        
        Write-Verbose ('Using target EWS url: ' + $service.url)
        
        ## Create a standard view
        $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(10, 0)
        $rootFolder = New-Object Microsoft.Exchange.WebServices.Data.FolderId(
            [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Root, $EmailAddress)

        ## Only look at the EAS mailbox log folders if we're expected to
        if ($PurgeLogs -or $PurgeLogsOnly)
        {
            Write-Host ($whatIfText + 'Removing EAS Mailbox Log folders...')
            
            ## Configure a search filter to search for the "AirSync-" folders off the root.  These store the EAS mailbox logs
	        $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring(
	            [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "AirSync")

            ## Using this to break out of multiple loops.
            $breakOut = $false

            do {
                ## Run the search
                $folderList = $service.FindFolders($rootFolder, $searchFilter, $view)

                if ($folderList -eq $null -or $folderList.TotalCount -eq 0)
                {
                    Write-Warning 'No EAS Mailbox Log folders found.'

                    $breakOut = $true
                    break
                }
                
                foreach ($folder in $folderList)
                {
                    ## ExchangeSyncState\AirSync-WP8-F94FFAE074DF7E31135B79C07D792F33
                    $devInfo = $folder.DisplayName.Split('-')
                    
                    ## WP8
                    $devType = $devInfo[1]
                    
                    ## F94FFAE074DF7E31135B79C07D792F33
                    $devId = $devInfo[2]

                    if ($DeviceId -eq '' -or $DeviceId -eq $devId)
                    {
                        if ($WhatIf)
                        {
                            ## Just display the folder, pretend we're verbose
                            Write-Host ('- ' + $folder.DisplayName + '...') -ForegroundColor yellow
                        }
                        else
                        {
                            ## Delete the folder
                            Write-Verbose ('- ' + $folder.DisplayName + '...')
                            $folder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete)
                        }

                        if ($DeviceId -eq $devId)
                        {
                            $breakOut = $true
                            break
                        }
                    }
                }
                
                $view.Offset = $folderList.NextPageOffset
            }
            while ($folderList.MoreAvailable -and $breakOut -eq $false)
        }

        if ($PurgeLogsOnly)
        {
            ## If $PurgeLogsOnly, we're done by this point
            
            Write-Host 'All done!'
            return
        }

        Write-Host 'Checking sync states in the mailbox...'

        #### Note, we can still sync properly when the device is not in AD, but in the mailbox.
        #### ExchangeSyncData\AirSync-WP8-DeviceId == SyncState
        #### <root>\AirSync WP8_DeviceId == EAS Mailbox logs
        
        #### If the device is not in the mailbox and we have quota room in AD, we'll just recreate (full resync) in the MBX
        #### If the device is not in the mailbox and there is no quota room in AD, we'll throw a 403
        #### If the device is in the mailbox, but not in AD, we'll continue syncing normally

        ## Configure a new search filter to search for the ExchangeSyncData folder
        $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "ExchangeSyncData")

        ## Reset the view's offset, it may have changed when enumerating log folders
        $view.Offset = 0
        
        ## Get the list of ExchangeSyncState folders -- there should only ever be 1
        ## Note that impersonation must be enabled for this to work:
        ## https://msdn.microsoft.com/en-us/library/bb204095.aspx
        try
        {
            $folderList = $service.FindFolders($rootFolder, $searchFilter, $view)
        }
        catch
        {
            if ($Credential.UserName -eq 'administrator' -and $_.Exception.Message -like '*impersonate*')
            {
                ## Administrator seems to have an explicit DENY
                Write-Warning('Impersonation may be blocked for the administrator account with an explicit DENY.')
            }
            
            Write-Error($_.Exception.Message)
        }
        
        if ($folderList -eq $null -or $folderList.TotalCount -eq 0)
        {
            Write-Warning 'Unable to find ExchangeSyncData folder in mailbox.  Exiting.'
            return
        }
        
        $ExchangeSyncDataRootId = $folderList.Folders[0].Id
        
        ## Configure a new search filter so we skip 'AirSyncRoot', which is a sync
        ## state where we put global sync state data, and so we only grab EAS folders
        $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring(
            [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "AirSync-")

        ## Reset to false.  Using this to break out of multiple loops.
        $breakOut = $false

        do {
            ## Use the folder id from the last search to get the list of folders under the ExchangeSyncData folder
            $folderList = $service.FindFolders($ExchangeSyncDataRootId, $searchFilter, $view)

            foreach ($folder in $folderList)
            {
                ## ExchangeSyncState\AirSync-WP8-F94FFAE074DF7E31135B79C07D792F33
                $devInfo = $folder.DisplayName.Split('-')
                    
                ## WP8
                $devType = $devInfo[1]
                    
                ## F94FFAE074DF7E31135B79C07D792F33
                $devId = $devInfo[2]

                Write-Verbose ('- Checking folder ExchangeSyncState\' + $folder.DisplayName)
            
                ## Force will indiscriminately destroy the sync state
                if ($Force)
                {
                    if ($WhatIf)
                    {
                        ## Just display the folder, pretend we're verbose
                        Write-Host ($whatIfText + '- Deleting ' + $folder.DisplayName + '...') -ForegroundColor yellow
                    }
                    else
                    {
                        ## Delete the entire sync state folder for this device
                        Write-Verbose '  - Deleting folder...'
                        $folder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete)
                    }
                }
                elseif ($DeviceId -ne '')
                {
                    ## If DeviceId is specified, don't run the 'else' code at all
                    ## We don't want to delete any non-matching devices in this scenario
                    if ($DeviceId -eq $devId)
                    {
                        if ($WhatIf)
                        {
                            ## Just display the folder, pretend we're verbose
                            Write-Host ($whatIfText + '- Deleting ' + $folder.DisplayName + '...') -ForegroundColor yellow
                        }
                        else
                        {
                            ## Delete the entire sync state folder for this device
                            Write-Verbose '  - Deleting folder...'
                            $folder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete)
                        }
                        
                        $breakOut = $true
                        break
                    }
                }
                else
                {
                    ## Check the device information parsed from the folder against any devices pulled from the cmdlets
                    foreach ($device in $devices)
                    {
                        if ($device.DeviceId -eq $devId)
                        {
                            Write-Verbose '  - Found match from cmdlets'
                        
                            ## $device.LastSyncAttemptTime may have been populated from Get-ActiveSyncDeviceStatistics
                            $syncStateLastSyncTime = $device.LastSyncAttemptTime
                            
                            ## We found the device, no sense in continuing to compare
                            break
                        }
                    }
                    
                    ## There's no match with our cmdlet outputs, but we still have a folder here
                    ## Check to see if it's still active by getting the last sync time property from the \ExchangeSyncData\DeviceIdentity\SyncStatus folder
                    ## or if it's Office 365 (or some future CU on-prem) then the sync item is not under a folder
                    if ($syncStateLastSyncTime -eq $null)
                    {
                        ## Configure a new search filter to get the SyncStatus item (O365/future)
                        $searchFilterSyncStatus = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring(
                            [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject, "SyncStatus")

                        $SyncStateView = New-Object Microsoft.Exchange.WebServices.Data.ItemView -ArgumentList 1
                        $SyncStateView.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.ItemSchema]::LastModifiedTime)

                        $itemListSyncStatus = $service.FindItems($folder.Id, $searchFilterSyncStatus, $SyncStateView)

                        if ($itemListSyncStatus.TotalCount -gt 0)
                        {
                            ## We're using items instead of folders for the sync state
                            #if ($itemListSyncStatus.Items[0].TryGetProperty($psExtended, [ref]$syncStateLastSyncTime))
                            if ($itemListSyncStatus.Items[0].TryGetProperty([Microsoft.Exchange.WebServices.Data.ItemSchema]::LastModifiedTime, [ref]$syncStateLastSyncTime))
                            {
                                Write-Verbose ('  - Pulled LastModificationTime from item: ' + $syncStateLastSyncTime)
                            }
                        }
                        else
                        {
                            ## Configure a new search filter to get the SyncStatus folder, which is modified every sync
                            $searchFilterSyncStatus = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring(
                                [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, "SyncStatus")

                            ## Create the PR_LAST_MODIFICATION_TIME extended property as it's not part of the FolderSchema
                            $psExtended = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition(0x3008, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::SystemTime)

                            $SyncStateView = New-Object Microsoft.Exchange.WebServices.Data.FolderView -ArgumentList 1
                            $SyncStateView.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet($psExtended)

                            ## Use the folderId from the device folder to search for the SyncStatus folder
                            $folderListSyncStatus = $service.FindFolders($folder.Id, $searchFilterSyncStatus, $SyncStateView)
                        
                            if ($folderListSyncStatus.TotalCount -gt 0)
                            {
                                if ($folderListSyncStatus.Folders[0].TryGetProperty($psExtended, [ref]$syncStateLastSyncTime))
                                {
                                    Write-Verbose ('  - Pulled LastModificationTime from folder: ' + $syncStateLastSyncTime)
                                }
                            }
                        }
                    }

                    if ($syncStateLastSyncTime -ne $null)
                    {
                        if ($syncStateLastSyncTime.AddDays($PurgeDays) -le [System.DateTime]::Now)
                        {
                            Write-Verbose ('  - Last sync attempt time: ' + $syncStateLastSyncTime)
                            Write-Verbose ($whatIfText + '  - Device last synced over the threshold of ' + $PurgeDays + ' days ago.  Purging.')
                            if (!$WhatIf)
                            {
                                $folder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::SoftDelete)
                            }
                        }
                        else
                        {
                            Write-Verbose ('  - Device is within the purge threshold.  Last synced: ' + $syncStateLastSyncTime)
                        }
                    }
                    elseif ($syncStateLastSyncTime -eq $null)
                    {
                        Write-Verbose ($whatIfText + '  - Device has an invalid sync state.  Purging.')
                        if (!$WhatIf)
                        {
                            $folder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::SoftDelete)
                        }
                    }
                }
            }
            
            $view.Offset = $folderList.NextPageOffset
        }
        while ($folderList.MoreAvailable -and $breakOut -eq $false)
        
        Write-Host ('All done with ' + $User)
    }
}
