# PS_Remove-MobileDeviceInfo
A PowerShell module for Exchange and Office 365 to clear out orphaned MobileDevice objects and associated mailbox logs

 - Requires the EWS Managed API 2.2.  This can be downloaded from http://www.microsoft.com/en-us/download/details.aspx?id=42951
 - Must be run from an Exchange Management Shell / O365 Remote Shell

To import the function, run:

```Import-Module .\RemoveMobileDeviceInfoModule.psm1```

For more detailed info on usage, run:

```Get-Help Remove-MobileDeviceInfo -Full```
