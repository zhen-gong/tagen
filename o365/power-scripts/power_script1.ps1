$password = ConvertTo-SecureString "!o365admin$" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential "kumar_shetty@testappcloud.onmicrosoft.com",$password
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $credential -Authentication Basic -AllowRedirection
$exePolicy = Get-ExecutionPolicy
if ($exePolicy.toString().compareTo("Restricted") -eq 0) { Set-ExecutionPolicy RemoteSigned -force }
Import-PSSession $Session -DisableNameChecking
$prefix = "JK_"
$bkslash = "\"

#Public Folder Actions
New-PublicFolder $prefix"PublicFolderName";
Get-PublicFolder -Recurse;
Set-PublicFolder  $bkslash$prefix"PublicFolderName"  -PerUserReadStateEnabled:$false;
Remove-PublicFolder $bkslash$prefix"PublicFolderName"   -Confirm:$false;

#RoleAssignmentPolicy Actions
New-RoleAssignmentPolicy -Name $prefix"Role_Policy";
Remove-RoleAssignmentPolicy -Identity $prefix"Role_Policy" -Confirm:$false;

# AdminRole/User  Actions
New-RoleGroup -Description New_Admin_Role -Name $prefix"New_Admin_Role" ;
add-RoleGroupMember -Identity $prefix"New_Admin_Role"  -Member test ;
Remove-RoleGroupMember -Identity $prefix"New_Admin_Role"  -Member test -Confirm:$false;
get-RoleGroup -Identity $prefix"New_Admin_Role"
Remove-RoleGroup -Identity $prefix"New_Admin_Role"  -Confirm:$false;

#EDiscovery In Place hold  Actions
New-MailboxSearch -name $prefix"MailBoxSearch";
Set-MailboxSearch -Identity $prefix"MailBoxSearch" -Description "New EDiscovery Inpalce Hold";
Remove-MailboxSearch -Identity $prefix"MailBoxSearch" -Confirm:$false;
New-RetentionPolicy -Name $prefix"Retention_Policy";
Set-RetentionPolicy -Identity $prefix"Retention_Policy" -RetentionPolicyTagLinks "Never Delete";
Get-RetentionPolicy -Identity $prefix"Retention_Policy";
Remove-RetentionPolicy -Identity $prefix"Retention_Policy" -Confirm:$false;
New-ActiveSyncDeviceAccessRule -AccessLevel Allow -Characteristic DeviceOs -QueryString all;
Set-ActiveSyncDeviceAccessRule -AccessLevel Quarantine -Identity "all (DeviceOS)";
Remove-ActiveSyncDeviceAccessRule -Identity  "all (DeviceOS)" -Confirm:$false;
Get-ActiveSyncDevice;

#DLP Policy Action
New-DlpPolicy -Name $prefix"DLP_*Policy";
Set-DlpPolicy -Identity $prefix"DLP_Policy" -State disabled;
Remove-DlpPolicy -Identity $prefix"DLP_Policy" -Confirm:$false;
Search-AdminAuditLog -ResultSize 20 ;
Remove-PSSession $Session;
echo Done;
;