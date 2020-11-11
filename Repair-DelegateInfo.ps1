# 
# Repair-DelegateInfo.ps1
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
# 2020NOV12
# - Initial commit on GitHub/JasonDebug/PS_Repair-DelegateInfo

<#
.Synopsis
Attempts to completely remove the delegate info from a mailbox to resolve any corruption

.Description
This script attempts to remove the delegate information stored in the mailbox.  This assumes the
publicDelegates attribute is correct, and the hidden FREEBUSY item in the mailbox is corrupt and
needs to be removed.

More information:
You experience issues in Outlook when you try to configure
free/busy information or when you try to delegate information
https://support.microsoft.com/en-us/help/958443

.Example
$cred = Get-Credential
C:\PS>Repair-DelegateInfo -Identity 2016user1 -Credential:$cred

This will use the credentials from Get-Credential, and try to remove the delegates by pulling the
  current list of delegates from the publicDelegates attribute on the user and sending a RemoveDelegate
  command via EWS.

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

.Parameter DomainController
The DomainController parameter specifies the fully qualified domain name (FQDN) of the domain controller that
  retrieves data from Active Directory.

.Parameter IgnoreImpersonationFailure
The IgnoreImpersonationFailure parameter specifies whether the script should continue when the RBAC role
  of ApplicationImpersonation is not found.  This occurs when using an account with full mailbox access but
  no impersonation rights.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param
(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [alias('Mailbox')]
    [string]$Identity,

    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$UseDefaultCredentials = $false,

    [Parameter(Mandatory=$false)]
    [switch]$UseLocalHost,

    [Parameter(Mandatory=$false)]
    [string]$EwsUrl,

    [Parameter(Mandatory=$false)]
    [switch]$TraceEnabled,

    [Parameter(Mandatory=$false)]
    [switch]$IgnoreSsl,

    [Parameter(Mandatory=$false)]
    [switch]$RemoveOnly,

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    $DomainController,

    [Parameter(Mandatory=$false)]
    [switch]$IgnoreImpersonationFailure
)

Process
{
    ###################
    ## Session setup ##
    ###################
    
    ## Configure options and credentials

    ## WhatIf and Verbose will automatically be added to things like Set-ADUser
    $verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
    $whatif = $PSCmdlet.MyInvocation.BoundParameters["WhatIf"].IsPresent

    if ($WhatIf)
    {
        ## This is prepended any time something drastic would normally happen, i.e. removing things from AD
        ##
        $whatIfText = 'What if: '
    }
    else
    {
        $whatIfText = ''
    }
    
    ## Check that we have ADUser from the ActiveDirectory module, and we're in EMS, before spending time doing anything else
    
    if ((Get-Command Get-ADUser -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Count -eq 0)
    {
        do {
            Write-Warning "RSAT PowerShell module needs to be installed.  Add Windows Feature now?"
            Write-Warning "Ref: https://docs.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools"
            Write-Host "[Y] Yes  " -NoNewLine -ForegroundColor Yellow
            Write-Host "[N] No  " -NoNewLine
            $installRSAT = Read-Host -Prompt "(default is `"Y`")"
            $installRSAT = $installRSAT.ToLower().Trim()
        } until ( $installRSAT -eq 'y' -or $installRSAT -eq 'n' -or $installRSAT -eq '' )

        $error.Clear()
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        
        if ($error.Count -gt 0)
        {
            Write-Warning "ActiveDirectory module failed to load.  Error:"
            $error
            return
        }
    }
            
    if ((Get-Command Get-Mailbox -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Count -eq 0)
    {
        Write-Warning 'This script must be executed in the Exchange Management Shell.  Exiting.'
        return
    }

    if ($Credential -eq $null)
    {
        if ($UseDefaultCredentials -eq $true)
        {
            $Credential = @{UserName = [Environment]::UserName}
            Write-Verbose ('Using ' + [Environment]::UserDomainName + '\' + [Environment]::UserName + ' as service account. Use -Credentials to override.')
        }
        else
        {
            ## Wrapped in a try-catch in case the user hits escape or cancel
            try
            {
                $Credential = Get-Credential -ErrorAction SilentlyContinue

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
    }

    ## Verify RBAC rights and set a single DC
    if ($DomainController -ne '' -and $DomainController -ne $null)
    {
        if ((Get-ADDomainController $DomainController -ErrorAction SilentlyContinue).Count -ne 1)
        {
            Write-Error "Unable to find Domain Controller $DomainController.  Exiting."
        }
    }
    else
    {
        $DomainController = $null
    }
    
    Write-Verbose "Using '$DomainController' for RBAC rights lookup.  ViewEntireForest in ADServerSettings is set to $((Get-ADServerSettings).ViewEntireForest)"

    ## DomainController parameter may be RBAC'd out, but if it's not the assumption will be we have rights to it for all relevant commands
    if ((Get-Command Get-ManagementRoleAssignment).Parameters.ContainsKey('DomainController'))
    {
        Write-Verbose "Checking ApplicationImpersonation RBAC role for $($Credential.UserName)"
        $rbac = Get-ManagementRoleAssignment -RoleAssignee ($Credential.UserName) -Role ApplicationImpersonation -DomainController $DomainController #-ErrorAction SilentlyContinue
        
        ## Set DomainController to whatever gave us the RBAC rights, so we're at least consistent
        if ($rbac.OriginatingServer -ne $DomainController)
        {
            Write-Verbose "Setting DomainController to '$($rbac.OriginatingServer)'"
            $DomainController = $rbac.OriginatingServer
        }
    }
    else
    {
        ## No access to -DomainController parameter
        Write-Error "No access to DomainController parameter, but this is required to properly re-set delegates."
        return
    }
    
    if ($rbac -eq $null -or $rbac.Count -eq 0)
    {
        Write-Warning ('ApplicationImpersonation rights not found for ' + $Credential.UserName + '.')
        Write-Warning 'Note that if impersonation was recently added, it may take some time to replicate.  Use the -DomainController option to specify a DC for lookup.'
        Write-Warning ""
        
        ## Article about configuring impersonation
        Write-Warning 'For more information on configuring impersonation in Exchange, go to https://msdn.microsoft.com/en-us/library/office/bb204095(v=exchg.140).aspx'
        Write-Warning "Usage example -- New-ManagementRoleAssignment –Name:impersonationAssignmentName –Role:ApplicationImpersonation –User:serviceAccount"
        Write-Warning ""

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
    
    Write-Verbose "Using $($Credential.UserName) as service account."

    #########################################
    ##  Getting Mailbox and Delegate Info  ##
    ##  - Preparing XML for EWS calls      ##
    #########################################

    Write-Host "Gathering mailbox info." -NoNewLine

    ## Get Mailbox Info
    $Mailbox = Get-Mailbox $Identity -DomainController $DomainController
    Write-Host "." -NoNewLine
    $MailboxADUser = Get-ADUser $Mailbox.Alias -Properties publicDelegates -Server $DomainController
    Write-Host "."
    $MailboxRecipient = Get-Recipient $Mailbox.Alias -DomainController $DomainController
    $EmailAddress = $Mailbox.PrimarySmtpAddress
    
    Write-Verbose "Current publicDelegates property:"
    if ( $MailboxADUser.publicDelegates.Count -gt 0)
    {
        $MailboxADUser | Select -ExpandProperty publicDelegates
        $filename = "~\Desktop\$($Mailbox.Alias)_Delegator_$([DateTime]::Now.ToString("yyyyMMdd-HHmmss")).xml"
        Write-Host -ForegroundColor Yellow "Saving current delegates for $($Mailbox.Name) to $filename"
        $MailboxADUser | Export-CliXml $filename
    }
    else
    {
        Write-Verbose "Empty publicDelegates property"
    }

    ## Clear publicDelegates from AD
    Write-Host ($whatIfText + "Clearing delegate info from the mailbox...")

    $delegateXml = ""
    foreach ($pubDel in $MailboxADUser.publicDelegates)
    {
        $currentDelegate = Get-Recipient $pubDel
        $delegateXml += "<t:UserId><t:PrimarySmtpAddress>$($currentDelegate.primarySmtpAddress)</t:PrimarySmtpAddress></t:UserId>`r`n"
        
        ## WhatIf and Verbose are automatic here
        
        ## We go ahead and clear folder permissions and SOB rights here, even
        ## though the RemoveDelegate commands should do this for us
        
        ## We could do a % | ? { $_.User.DisplayName -ne 'Default' } and remove all users with permissions here
        ## but any one-off additions would be lost.  Probably an edge-case, but we'll be explicit anyway
        Write-Verbose "Removing mailbox folder permissions for $($currentDelegate.Alias)"
        if ( (Get-MailboxFolderPermission "$($Mailbox.Alias):\calendar" -DomainController $DomainController | ? { $_.User.ADRecipient.Alias -eq $pubDel.Alias }).Count -gt 0 )
        {
            Remove-MailboxFolderPermission "$($Mailbox.Alias):\calendar" -User $pubDel -DomainController $DomainController
        }
        
        Write-Verbose "Clearing Send-On-Behalf rights for $($currentDelegate.Alias)"
        Set-Mailbox $Mailbox -GrantSendOnBehalfTo @{Remove = $pubDel} -WarningAction SilentlyContinue -DomainController $DomainController
    }

    ## Remove all delegates
    $removalXml = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016"/>
    <t:ExchangeImpersonation>
        <t:ConnectingSID>
            <t:PrimarySmtpAddress>$EmailAddress</t:PrimarySmtpAddress>
        </t:ConnectingSID>
    </t:ExchangeImpersonation>
  </soap:Header>
  <soap:Body>
    <RemoveDelegate xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"
                    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
      <Mailbox>
        <t:EmailAddress>$EmailAddress</t:EmailAddress>
      </Mailbox>
      <UserIds>
$delegateXml
      </UserIds>
    </RemoveDelegate>
  </soap:Body>
</soap:Envelope>
"@

    ##############################
    ##  Preparing EWS settings  ##
    ##############################

    ## Get the target EWS url
    ## For POX, I'm not doing AutoD.  Either specify or it's local :P
    if ($EwsUrl -ne '')
    {
        $uri = [System.Uri]$EwsUrl
    }
    else
    {
        $uri = [System.Uri]('https://' + $Env:ComputerName + '/EWS/Exchange.asmx')
        # If we're local, go ahead and ignore SSL
        $IgnoreSsl = $true
    }

    # Ignore cert errors
    if (-not ([System.Management.Automation.PSTypeName]'CertificateUtils').Type)
    {
    add-type @"
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public static class CertificateUtils {
            public static bool TrustAllCertsCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
                return true;
            }
           
            public static void TrustAllCerts() {
                ServicePointManager.ServerCertificateValidationCallback = CertificateUtils.TrustAllCertsCallback;
            }
        }
"@
    }

    ## Ignore SSL warnings due to self-signed certs 
    if ($IgnoreSsl)
    {
        # This is the normal way to do it, but it has runspace issues
        #[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        [CertificateUtils]::TrustAllCerts()
    }
    
    ## Configure for TLS 1.2
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    ###########################################
    ##  EWS calls using POX / Plain Old XML  ##
    ###########################################

    if ($MailboxADUser.publicDelegates.Count -eq 0)
    {
        Write-Warning "No delegates in publicDelegates property.  No RemoveDelegate XML being sent"
    }
    else
    {
        Write-Verbose ($WhatIfText + "Sending removal XML to $uri`:`r`n$removalXml")

        $retry = 3
    
        do {
            if ($WhatIf -or $MailboxADUser.publicDelegates.count -eq 10)
            {
                break
            }

            $result = $null
            $content = $null
            $error.Clear()

            try {
                if ($UseDefaultCredentials -and !$WhatIf)
                {
                    Write-Host -ForegroundColor Yellow "...using default credentials"
                    $result = Invoke-WebRequest -Uri $uri -Method Post -Body $removalXml -ContentType "text/xml" -Headers @{'X-AnchorMailbox' = $EmailAddress} -UseDefaultCredentials -WebSession $FirstSession
                }
                elseif (!$WhatIf)
                {
                    Write-Host -ForegroundColor Yellow "...using specified credentials"
                    $PSCred = [PSCredential]$Credential
                    $result = Invoke-WebRequest -Uri $uri -Method Post -Body $removalXml -ContentType "text/xml" -Headers @{'X-AnchorMailbox' = $EmailAddress} -Credential:$PSCred -WebSession $FirstSession
                }

                Write-Host "Result: $($result.StatusCode) $($result.StatusDescription)"

                if ($verbose)
                {
                    ## This pretty-prints the headers
                    $result.Headers.GetEnumerator() | % {
                        Write-Host "$($_.Key): $($_.Value)"
                    }
                    Write-Host ""
                    
                    ## This pretty-prints the XML
                    ([xml]$result.Content).Save([Console]::Out)
                    Write-Host ""
                    Write-Host ""
                }
                
                ## Makes it easier to do the retry check since the catch won't have $result.Content
                $content = $result.Content
            }
            catch
            {
                ## We have to pull the response body a bit differently in this case
                $result = $PSItem.Exception.Response
                Write-Host "Result: $([int]$result.StatusCode) $($result.StatusDescription)"
                
                if ([int]$result.StatusCode -eq 0)
                {
                    $result.StatusCode
                    $result.StatusDescription
                    $PSItem.Exception
                    return
                }
                
                ## This pretty-prints the headers
                $result.Headers | % { Write-Host "$_`: $($result.GetResponseHeader($_))" };
                Write-Host ""
                
                $stream = $result.GetResponseStream()
                $stream.Position = 0
                $reader = [System.IO.StreamReader]::new($stream)
                $content = $reader.ReadToEnd()
                
                if ($content.Contains("<?xml"))
                {
                    ([xml]$content).Save([Console]::Out)
                }
                else
                {
                    $content
                }
                Write-Host ""
                Write-Host ""
                
            }
            finally
            {
                $retry--
            }

            if ($result.StatusCode -ne 200 -or $error.Count -gt 0)
            {
                if ($content -match "ErrorImpersonateUserDenied")
                {
                    ## Known permanent failure
                    Write-Warning "Permanent failure.  Impersonation rights not found, but we have the RBAC right.  Likely using an admin user with explicit deny.  Exiting."
                    return
                }

                Write-Warning "EWS call failed."
                if ($retry -gt 0)
                {
                    Write-Warning "Retrying..."
                }
                else
                {
                    Write-Warning "Exiting."
                }
            }
        }
        while ( $retry -ne 0 -and $result.StatusCode -ne 200 -and $error.count -ne 0 )
        
        ## Clear the publicDelegates attribute after the RemoveDelegate command
        Write-Host ($WhatIfText + "Clearing publicDelegates attribute for $($Mailbox.Name)")
        Set-ADUser $Mailbox.Alias -Clear publicDelegates -Server $DomainController
    }
    
    #############################
    ##  EWS Managed API Calls  ##
    #############################

    Write-Verbose "Configuring the EWS Managed API"
    Write-Verbose "NOTE: If you get 401s even though the POX requests were fine, make`r`n  sure the SPN for the URL is configured for the target machine."

    ## Import the Exchange Web Services module from the install directory
    if ((Get-Module Microsoft.Exchange.WebServices).Count -eq 0) {
    Import-Module ($env:ExchangeInstallPath + "Bin\Microsoft.Exchange.WebServices.dll") }

    ## Set Exchange Version
    ## Detect this later through GetUserSettings / UserSettingName.CasVersion or through a try catch?
    ## Only tested on 2010 and higher, but we're not doing anything that requires the newer schemas
    #$ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2013_SP1
    $ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016

    ## Create Exchange Service Object
    $service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService($ExchangeVersion)
    
    ## Whether or not to use local credentials.  This will not work with O365.
    Write-Verbose "Using default creds: $UseDefaultCredentials"
    $service.UseDefaultCredentials = $UseDefaultCredentials

    ## The credentials are set/checked first-thing in this module.  EWS API needs a NetworkCredential vs PSCredential so we make it here
    ## If $UseDefaultCredentials is not $true, we have either bailed by this point or we have creds
    if ($UseDefaultCredentials -ne $true)
    {
        Write-Verbose("Setting EWS service to use $($Credential.UserName)")
        $service.Credentials = [System.Net.NetworkCredential]$Credential.GetNetworkCredential()
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
    ## Unlike POX, it's easy to do AutoD here, so either specify the url or local, or we'll do AutoD
    if ($UseLocalHost -eq $true)
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
            Write-Verbose ('Getting EWS endpoint via Autodiscover, using email address ''' + $EmailAddress + ''' for lookup')
            
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

    ## Remove the extended properties per https://support.microsoft.com/en-us/help/958443

    ## The PR_FREEBUSY_ENTRYIDS extended property is what we'll be clearing.  It needs to be part of the folder bind if we want to remove it
    $PR_FREEBUSY_ENTRYIDS = [Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition]::new(0x36E4, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::BinaryArray)
    $extendedPropertySet = [Microsoft.Exchange.WebServices.Data.PropertySet]::new($PR_FREEBUSY_ENTRYIDS)

    ## Connect to the root folder and remove the property
    Write-Host "Clearing the PR_FREEBUSY_ENTRYIDS property from the root of $($Mailbox.Name)'s mailbox..."
    $rootFolderId = [Microsoft.Exchange.WebServices.Data.FolderId]::new([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Root, $EmailAddress.ToString())
    $rootFolder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service, $rootFolderId, $extendedPropertySet)
    $successRoot = $rootFolder.RemoveExtendedProperty($PR_FREEBUSY_ENTRYIDS)
    $rootFolder.Update()
    
    ## Connect to the Inbox and remove the property
    Write-Host "Clearing the PR_FREEBUSY_ENTRYIDS property from the Inbox of $($Mailbox.Name)'s mailbox..."
    $inboxFolderId = [Microsoft.Exchange.WebServices.Data.FolderId]::new([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, $EmailAddress.ToString())
    $inboxFolder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service, $inboxFolderId, $extendedPropertySet)
    $successInbox = $inboxFolder.RemoveExtendedProperty($PR_FREEBUSY_ENTRYIDS)
    $inboxFolder.Update()
    
    $service = $null
    
    if ($RemoveOnly)
    {
        Write-Host "All done with $($Mailbox.Name)"
        return
    }

    if ($MailboxADUser.publicDelegates.Count -eq 0)
    {
        Write-Warning "No delegates in publicDelegates property.  No AddDelegate XML being sent"
    }
    else
    {
        Write-Host "Re-adding delegates to the mailbox..."
        
        ########################################################
        ##  Back to POX commands for re-adding the delegates  ##
        ########################################################

        ## Prepare the re-add XML

        $addXml = ""
        foreach ($pubDel in $MailboxADUser.publicDelegates)
        {
            $currentDelegate = Get-Recipient $pubDel -DomainController $DomainController -ErrorAction SilentlyContinue
            if ($currentDelegate.Count -ne 1)
            {
                continue
            }

$addXml += @"
              <t:DelegateUser>
                <t:UserId>
                  <t:PrimarySmtpAddress>$($currentDelegate.primarySmtpAddress)</t:PrimarySmtpAddress>
                </t:UserId>
                <t:DelegatePermissions>
                  <t:CalendarFolderPermissionLevel>Editor</t:CalendarFolderPermissionLevel>
                  <t:TasksFolderPermissionLevel>Editor</t:TasksFolderPermissionLevel>
                  <t:InboxFolderPermissionLevel>None</t:InboxFolderPermissionLevel>
                  <t:ContactsFolderPermissionLevel>None</t:ContactsFolderPermissionLevel>
                  <t:NotesFolderPermissionLevel>None</t:NotesFolderPermissionLevel>
                  <t:JournalFolderPermissionLevel>None</t:JournalFolderPermissionLevel>
                </t:DelegatePermissions>
                <t:ReceiveCopiesOfMeetingMessages>true</t:ReceiveCopiesOfMeetingMessages>
                <t:ViewPrivateItems>false</t:ViewPrivateItems>
              </t:DelegateUser>
"@
        }

$addDelegateXml = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
      <t:RequestServerVersion Version="Exchange2016" />
      <t:ExchangeImpersonation>
        <t:ConnectingSID>
          <t:PrimarySmtpAddress>$EmailAddress</t:PrimarySmtpAddress>
        </t:ConnectingSID>
      </t:ExchangeImpersonation>
    </soap:Header>
    <soap:Body>
      <m:AddDelegate>
        <m:Mailbox>
          <t:EmailAddress>$EmailAddress</t:EmailAddress>
        </m:Mailbox>
        <m:DelegateUsers>
$addXml
        </m:DelegateUsers>
        <m:DeliverMeetingRequests>DelegatesOnly</m:DeliverMeetingRequests>
      </m:AddDelegate>
    </soap:Body>
</soap:Envelope>
"@

        ###########################################
        ##  EWS calls using POX / Plain Old XML  ##
        ###########################################

        Write-Verbose ($WhatIfText + "Sending re-addition XML to $uri`:`r`n$addDelegateXml")
        sleep 2

        $retry = 3
        
        do {
            $result = $null
            $error.Clear()

            try {
                if ($UseDefaultCredentials -and !$WhatIf)
                {
                    Write-Host -ForegroundColor Yellow "...using default credentials"
                    $result = Invoke-WebRequest -Uri $uri -Method Post -Body $addDelegateXml -ContentType "text/xml" -Headers @{'X-AnchorMailbox' = $EmailAddress} -UseDefaultCredentials -WebSession $SecondSession
                }
                elseif (!$WhatIf)
                {
                    Write-Host -ForegroundColor Yellow "...using specified credentials"
                    $result = Invoke-WebRequest -Uri $uri -Method Post -Body $addDelegateXml -ContentType "text/xml" -Headers @{'X-AnchorMailbox' = $EmailAddress} -Credential:$Credential -WebSession $SecondSession
                }

                Write-Host "Result: $($result.StatusCode) $($result.StatusDescription)"

                if ($verbose)
                {
                    ## This pretty-prints the headers
                    $result.Headers.GetEnumerator() | % {
                        Write-Host "$($_.Key): $($_.Value)"
                    }
                    Write-Host ""
                    ## This pretty-prints the XML
                    ([xml]$result.Content).Save([Console]::Out)
                    Write-Host ""
                }
            }
            catch
            {
                ## We have to pull the response body a bit differently in this case
                $result = $PSItem.Exception.Response
                Write-Host "Result: $([int]$result.StatusCode) $($result.StatusDescription)"
                
                ## This pretty-prints the headers
                $result.Headers | % { Write-Host "$_`: $($result.GetResponseHeader($_))" };
                Write-Host ""
                
                $stream = $result.GetResponseStream()
                $stream.Position = 0
                $reader = [System.IO.StreamReader]::new($stream)
                $content = $reader.ReadToEnd()
                
                if ($content.Contains("<?xml"))
                {
                    ([xml]$content).Save([Console]::Out)
                }
                else
                {
                    $content
                }
                Write-Host ""
                Write-Host ""
                
            }
            finally
            {
                $retry--
            }
            
            if ($content -match "ErrorDelegateAlreadyExists")
            {
                Write-Verbose "At least one delegate already exists, not retrying."
                retry = 0;
            }


            if ($result.StatusCode -ne 200)
            {
                Write-Warning "EWS call failed."
                if ($retry -gt 0)
                {
                    Write-Warning "Retrying..."
                }
                else
                {
                    Write-Warning "Exiting."
                }
            }
        }
        while ( $retry -ne 0 -and $result.StatusCode -ne 200)
    }
    
    ## We should have editor rights on calendar and SOB rights
    sleep 2
    
    Write-Host "Checking publicDelegates attribute for $($Mailbox.Name)"
    $MailboxADUser = Get-ADUser $Mailbox.Alias -Properties publicDelegates -Server $DomainController
    $MailboxADUser | Select -ExpandProperty publicDelegates
    Write-Host ""
    
    Write-Host "Checking calendar rights"
    Get-MailboxFolderPermission "$($Mailbox.Alias):\calendar" -DomainController $DomainController
    Write-Host ""
    
    Write-Host "Checking Send-On-Behalf rights"
    Get-Mailbox $Mailbox -DomainController $DomainController | Select GrantSendOnBehalfTo
    Write-Host ""

    Write-Host "All done with $($Mailbox.Name)"
}
