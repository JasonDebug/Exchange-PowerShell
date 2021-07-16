# 
# Get-Delegate.ps1
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
# 16JUL2021
# - Initial commit on GitHub/JasonDebug/PS_Get-Delegate

<#
.Synopsis
Gets delegate info for a user

.Description
This script attempts to get a list of delegates for a given user

.Example
$cred = Get-Credential
C:\PS>Get-Delegate -Identity 2016user1 -Credential:$cred

This will use the credentials from Get-Credential, and try to pull the current list of delegates from
  the publicDelegates attribute on the user and sending a GetDelegate command via EWS.

.Parameter Identity
The Identity parameter specifies the target user's alias, email address, user principal name, or Mailbox object
  from Get-Mailbox.

.Parameter Credential
The Credential parameter specifies the credentials to use for the impersonation account.

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

Get-Delegate -Identity 2019user1@exchlab.com -UseDefaultCredentials
	-EwsUrl
	-Credential:$cred
	-User
	-UseLocalHost
	-IgnoreSsl
	-DomainController
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param
(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [string]$Identity,

    [Parameter(Mandatory=$false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$UseDefaultCredentials = $true,

    [Parameter(Mandatory=$false)]
    [switch]$UseLocalHost,

    [Parameter(Mandatory=$false)]
    [string]$EwsUrl,

    [Parameter(Mandatory=$false)]
    [switch]$TraceEnabled,

    [Parameter(Mandatory=$false)]
    [switch]$IgnoreSsl,

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
	if (![string]::IsNullOrEmpty($Credential)) { $UseDefaultCredentials = $false }

    ## WhatIf and Verbose will automatically be added to things like Set-ADUser
    $verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
    
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
            #$Credential = @{UserName = [Environment]::UserName}
			$Credential = New-Object PSCredential("$([Environment]::UserDomainName)\$([Environment]::UserName)", ("password" | ConvertTo-SecureString -asPlainText -Force))
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
    if (![string]::IsNullOrEmpty($DomainController))
    {
		if ((Get-ADDomainController $DomainController -ErrorAction SilentlyContinue).Count -ne 1)
		{
			Write-Verbose "Unable to find specified Domain Controller $DomainController"
			$DomainController = $null
		}
    }
    
    Write-Verbose "Using '$DomainController' for RBAC rights lookup.  ViewEntireForest in ADServerSettings is set to $((Get-ADServerSettings).ViewEntireForest)"

    ## DomainController parameter may be RBAC'd out, but if it's not the assumption will be we have rights to it for all relevant commands
    if ((Get-Command Get-ManagementRoleAssignment).Parameters.ContainsKey('DomainController'))
    {
        Write-Verbose "Checking ApplicationImpersonation RBAC role for $($Credential.UserName)"
        $rbac = Get-ManagementRoleAssignment -RoleAssignee ($Credential.UserName) -Role ApplicationImpersonation -DomainController $DomainController -ErrorAction SilentlyContinue
        
        ## Set DomainController to whatever gave us the RBAC rights, so we're at least consistent
		if ($rbac.OriginatingServer.Count -gt 1)
		{
			$DomainController = $rbac.OriginatingServer[0]
		}
		else
		{
			$DomainController = $rbac.OriginatingServer
		}
		
		## if $rbac is null we still won't have a DC
		if ([string]::IsNullOrEmpty($DomainController))
		{
			$DomainController = (Get-AdServerSettings).DefaultGlobalCatalog
		}
		Write-Verbose "Setting DomainController to '$($rbac.OriginatingServer)'"
	}
	else
	{
		$DomainController = $null
		Write-Verbose "Setting DomainController to `$null.  No access to -DomainController parameter in RBAC"
	}
    
    if ($rbac -eq $null -or $rbac.Count -eq 0)
    {
		#Before warning, see if we have FullAccess rights
		$FARights = Get-MailboxPermission $Identity -User $Credential.UserName | ? { $_.AccessRights -match "FullAccess" }

		if ($FARights -eq $null -or ($FARights | ? { $_.Deny -eq $true }).Count -gt 0)
		{
			Write-Warning ('FullAccess or ApplicationImpersonation rights not found for ' + $Credential.UserName + '.')
			Write-Warning 'Note that if rights were recently added, it may take some time to replicate.  Use the -DomainController option to specify a DC for lookup.'
			Write-Warning ""
			
			## Article about configuring impersonation
			Write-Warning 'For more information on configuring impersonation in Exchange, go to https://msdn.microsoft.com/en-us/library/office/bb204095(v=exchg.140).aspx'
			Write-Warning "Usage example -- New-ManagementRoleAssignment –Name:impersonationAssignmentName –Role:ApplicationImpersonation –User:serviceAccount"
			Write-Warning ""

			## Article about management role assignments
			Write-Warning 'For more information on the ApplicationImpersonation role, go to https://technet.microsoft.com/en-us/library/dd776119(v=exchg.150).aspx'
			
			return
		}
		
		$UseImpersonation = $false
    }
	else
	{
		$UseImpersonation = $true
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
    $EmailAddress = $Mailbox.PrimarySmtpAddress.Address
    
    ##############################
    ##  Preparing EWS settings  ##
    ##############################

	## Get delegates via EWS
	Write-Host "Getting delegates from EWS."
	
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

	if ($UseImpersonation)
	{
		$impersonationXml = @"
        <t:ExchangeImpersonation>
            <t:ConnectingSID>
                <t:PrimarySmtpAddress>$EmailAddress</t:PrimarySmtpAddress>
            </t:ConnectingSID>
        </t:ExchangeImpersonation>
"@
		Write-Verbose "Impersonating $EmailAddress with account $impersonationEmail"
	}
	else
	{
		$impersonationXml = $null
	}
	
	$getDelegateXml = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
        <t:RequestServerVersion Version="Exchange2013_SP1" />
$impersonationXml
    </soap:Header>
    <soap:Body>
        <m:GetDelegate IncludePermissions="true">
            <m:Mailbox>
                <t:EmailAddress>$EmailAddress</t:EmailAddress>
            </m:Mailbox>
        </m:GetDelegate>
    </soap:Body>
</soap:Envelope>
"@

	Write-Verbose "Sending XML to $uri`:`r`n$getDelegateXml"

	$retry = 3

	do {
		$result = $null
		$content = $null
		$error.Clear()

		try {
			if ($UseDefaultCredentials)
			{
				Write-Verbose "...using default credentials"
				$result = Invoke-WebRequest -Uri $uri -Method Post -Body $removalXml -ContentType "text/xml" -Headers @{'X-AnchorMailbox' = $EmailAddress} -UseDefaultCredentials
			}
			else
			{
				Write-Verbose "...using specified credentials"
				$PSCred = [PSCredential]$Credential
				$result = Invoke-WebRequest -Uri $uri -Method Post -Body $getDelegateXml -Headers @{'X-AnchorMailbox' = $EmailAddress} -Credential:$PSCred -ContentType "text/xml"
			}

			Write-Verbose "Result: $($result.StatusCode) $($result.StatusDescription)"
			
			## Makes it easier to do the retry check since the catch won't have $result.Content
			$content = $result.Content

			if ($verbose)
			{
				## This pretty-prints the headers
				$result.Headers.GetEnumerator() | % {
					Write-Host "$($_.Key): $($_.Value)"
				}
				Write-Host ""
				
				## This pretty-prints the XML
				([xml]$content).Save([Console]::Out)
				Write-Host ""
				Write-Host ""
			}
			
			$resultXml = [xml]$content
			
			Write-Host "Delegates listed in EWS GetDelegate:"
			Write-Host $resultXml.Envelope.Body.GetDelegateResponse.ResponseMessages.DelegateUserResponseMessageType.DelegateUser.UserId.DisplayName
			Write-Host ""
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
	while ( $retry -gt 0 -and $result.StatusCode -ne 200 -and $error.count -ne 0 )

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
