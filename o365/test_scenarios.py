"""
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
Add-PublicFolderClientPermission -Identity $bkslash$prefix"PublicFolderName" -User testnew -AccessRights Owner -Confirm:$false;
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
New-DlpPolicy -Name $prefix"DLP_Policy";
Set-DlpPolicy -Identity $prefix"DLP_Policy" -State disabled;
Remove-DlpPolicy -Identity $prefix"DLP_Policy" -Confirm:$false;

#Malware Policy Action
New-MalwareFilterPolicy -Name $prefix"MalwareFilterPolicy";
Set-MalwareFilterPolicy -Identity $prefix"MalwareFilterPolicy"  -AdminDisplayName $prefix"Filter";
New-MalwareFilterRule -Name $prefix"MalwareFilterRule" -MalwareFilterPolicy $prefix"MalwareFilterPolicy" -RecipientDomainIs palerra.com
Disable-MalwareFilterRule $prefix"MalwareFilterRule" -Confirm:$false;
Remove-MalwareFilterRule $prefix"MalwareFilterRule" -Confirm:$false;
Remove-MalwareFilterPolicy -Identity $prefix"MalwareFilterPolicy"  -Confirm:$false;

#Send email using different credential
$password2 = ConvertTo-SecureString "Pandora2014" -AsPlainText -Force
$credential2 = New-Object System.Management.Automation.PSCredential "test@testappcloud.onmicrosoft.com",$password2
Send-MailMessage –To test@testappcloud.onmicrosoft.com –From test@testappcloud.onmicrosoft.com  –Subject “Test Phishing Email” –Body “Test Phishing Body” -SmtpServer smtp.office365.com -Credential $credential2 -UseSsl -Port 587

Search-AdminAuditLog -ResultSize 20 ;
Remove-PSSession $Session;
echo Done;
;
    commands = {
        'DPL': {

        },
        'Mail': {
            'Send-Mail': {
                'cmd': 'Send-MailMessage',
                'arg_min': ('-From', '-To', '-Subject'),
                'valid_arg': ('-Body', '-From', '-To', '-Subject', '-Encoding')
-Body
-BodyAsHtml
   Indicates that the value of the Body parameter contains HTML.
-Cc string
   Email addresses that you would like to cc.
-Credential PSCredential
   An account that has permission to send the email. The default is the current user.
-DeliveryNotificationOption Option
   Delivery notifications will be sent to the email address specified in the -From parameter.

          None - No notification (default)
          OnSuccess - Notify if the delivery is successful.
          OnFailure - Notify if the delivery is unsuccessful.
          Delay - Notify if the delivery is delayed.
          Never - Never notify.
-Encoding Encoding
   The encoding used for the body and subject.
-From string
   The address from which the mail is sent.
-Priority Priority
   The priority of the email message. Valid values: Low, Normal (default), High
-SmtpServer string
   The name of the SMTP server that sends the email message.
-Subject string
   The subject of the email message.
-To string
   The addresses you wish to send email to.


                )
            }
        },
        'Folder': {}
               }


               """
import os
import traceback

from cutils.cmdctl import LocalExec, expect_line
from cutils.config import load_config
from cutils.others import parse_args
from cutils.test_base import BaseTest, TestBase


class CreateSessionTest(BaseTest):
    conf = None

    def __init__(self, base, altPwd):
        super(CreateSessionTest, self).__init__(CreateSessionTest, base)

    def _run_(self, conf):
        self.conf = conf
        pwd = conf.win_admin_pwd
        cmd_list = list()
        cmd_list.append(["$password = ConvertTo-SecureString \"" + pwd + "\" -AsPlainText -Force", None])
        cmd_list.append(["$credential = New-Object System.Management.Automation.PSCredential \"" + conf.win_admin_user + "\",$password", None])
        cmd_list.append(["$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $credential -Authentication Basic -AllowRedirection", None])
        cmd_list.append(["$exePolicy = Get-ExecutionPolicy", None])
        cmd_list.append(["if ($exePolicy.toString().compareTo(\"Restricted\") -eq 0) { Set-ExecutionPolicy RemoteSigned -force }", None])
        cmd_list.append(["Import-PSSession $Session -DisableNameChecking", "OK"])
        self.cmd_list = cmd_list
        self.set_passed()


    def _shutdown_(self):
        cmd_list = list()
        cmd_list.append(("Remove-PSSession $Session;", None))


    def _get_description_(self):
        return "Create new test session"


class FailUserLoginTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(FailUserLoginTest, self).__init__(FailUserLoginTest, base)

    def _run_(self, conf):
        self.conf = conf

        super(FailUserLoginTest, self).set_passed()


    def _shutdown_(self):


    def _get_description_(self):
        return "Tests new user account creation"

class ATest(BaseTest):
    conf = None

    def __init__(self, base):
        super(BaseTest, self).__init__(ATest, base)

    def _run_(self, conf):
        self.conf = conf

        super(BaseTest, self).set_passed()


    def _shutdown_(self):


    def _get_description_(self):
        return "Tests new user account creation"


"""
Multiple failed logins to the admin account
"""


def win_failed_login_ctl_fn(conf, process):
    auth_cmd = configure_auth_header_cmd(conf, altPwd="test")
    for cmd in auth_cmd:
        os.write(process.stdin, cmd[0])
        (output, match_code, match_res) = expect_line(None, process)
        if cmd[1] is not None and match_code is None:
            # No match
            return -1


def win_bad_logins(conf):
    login_num = 6
    while login_num > 0:
        login_num -= 1
        e = LocalExec(conf)
        e.exec_command("powershell -Command", ctl_fn=win_failed_login_ctl_fn)

"""
Login to the admin account and delete DPL policy
"""


def configure_dpl_del_cmd(conf, cmd_list):
    if cmd_list is None:
        cmd_list = list()
    cmd_list.append(['Get-DplPolicy', "*", None])
    cmd_list.append(['Remove-DplPolicy  -Confirm:$false -Identity %s', "*", -1])
    return cmd_list


def win_rm_dpl_ctl_fn(conf, process):
    auth_cmd = configure_auth_header_cmd(conf)
    match_res_arr = list()
    cur_pos = -1
    for cmd in auth_cmd:
        cur_pos += 1
        cmd = cmd[0]
        if cmd[3] is not None:
            cmd = cmd%match_res_arr[cur_pos - cmd[3]]
        os.write(process.stdin, cmd)
        (output, match_code, match_res) = expect_line(None, process)
        if cmd[1] is not None and match_code is None:
            # No match
            return -1


def win_delete_DPL_policy(conf):
    e = LocalExec(conf)
    e.exec_command("powershell -Command", ctl_fn=win_rm_dpl_ctl_fn)




if __name__ == "__main__":

    args = parse_args()
    print args
    cf = load_config(args.conf_location)
    print "Running test for " + cf.aws_account

    test_base = TestBase()

    # Always test #1

    #
    # Adding tests after this block
    #
    CreateSessionTest(test_base)


    #AddUserToGroupTest(test_base)
    # TODO: write user verification test. Without it, test will continue to fail when it uses new user credentials

    if cf.num_failed_attempts != 0:
        FailUserLoginTest(test_base)

    # Run added tests
    try:
        test_base.exec_tests(cf)
    except:
        traceback.print_exc()
    #exit(1)
    test_base.done()





























