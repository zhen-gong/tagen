import os, time
import argparse
import traceback
import boto3
from boto3.session import Session

from AWS.utils.ui import failUserLogins, attemptToGetUserCredentials
from AWS.utils.common import extractCredentials, loadConfig
from cutils.test_connector import ATest, TestBase


class GetInstanceStatusTest(ATest):

    def __init__(self, base):
        super(GetInstanceStatusTest, self).__init__(GetInstanceStatusTest, base)

    def _run_(self, conf):
        # This test does not work with default credentials. Need investigation.
        # Error: ClientError: An error occurred (AuthFailure) when calling the
        # DescribeInstances operation: AWS was not able to validate the provided access credentials

        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        #iam_clt = session.client('ec2')
        ec2_clt = session.client('ec2')
        response = ec2_clt.describe_instances(
                   DryRun=False,
        )
        print response
        super(GetInstanceStatusTest, self).set_passed()

    def _get_description_(self):
        return "Tests return of status for an instance."


class GrantPublicAccessToBucketTest(ATest):
    conf = None

    def __init__(self, base):
        super(GrantPublicAccessToBucketTest, self).__init__(GrantPublicAccessToBucketTest, base)
        super(GrantPublicAccessToBucketTest, self).add_as_dependent_on(ListCreateDeleteBucketTest)

    def _run_(self, conf):
        self.conf = conf
        bucket_id = conf.test_bucket_name
        session = boto3.session.Session(aws_access_key_id=self.conf.test_user_key_pair.id,
                                        aws_secret_access_key=self.conf.test_user_key_pair.secret,
                                        region_name=self.conf.aws_test_region)
        s3_clt = session.client('s3')
        s3_res = session.resource('s3')
        policy = '''{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"AddPerm",
      "Effect":"Allow",
      "Principal": "*",
      "Action":["s3:*"],
      "Resource":["arn:aws:s3:::%s/*"]
    }
  ]
}''' % conf.test_bucket_name
        response = s3_clt.put_bucket_policy(Bucket=conf.test_bucket_name,
                                            Policy=policy)
        print "Resp: " + str(response)

    def _get_description_(self):
        return "Tests creation/deletion of an S3 bucket"


class ListCreateDeleteBucketTest(ATest):
    conf = None

    def __init__(self, base):
        super(ListCreateDeleteBucketTest, self).__init__(ListCreateDeleteBucketTest, base)
        super(ListCreateDeleteBucketTest, self).add_as_dependent_on(AddUserToGroupTest)

    def _run_(self, conf):
        self.conf = conf
        bucket_id = conf.test_bucket_name
        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        s3_clt = session.client('s3')
        s3_res = session.resource('s3')
        #client = boto3.client('s3')
        response = s3_clt.list_buckets()
        print "List of buckets:"
        print response

        have_bucket = False
        if response is not None:
            for b in response['Buckets']:
                if b['Name'] == bucket_id:
                    have_bucket = True
                    break
        if not have_bucket:
            print "Creating bucket: "
            bucket = s3_res.Bucket(bucket_id)
            response = bucket.create(
                       ACL='private',
                       CreateBucketConfiguration={
                               'LocationConstraint': conf.aws_test_region
                       })
            print response
        super(ListCreateDeleteBucketTest, self).set_passed()

    def _shutdown_(self):
        print "Deleting bucket "
        bucket_id = self.conf.test_bucket_name
        session = boto3.session.Session(aws_access_key_id=self.conf.test_user_key_pair.id,
                                        aws_secret_access_key=self.conf.test_user_key_pair.secret,
                                        region_name=self.conf.aws_test_region)
        s3_clt = session.client('s3')
        response = s3_clt.delete_bucket(Bucket=bucket_id)
        super(ListCreateDeleteBucketTest, self).set_passed()
        print response

    def _get_description_(self):
        return "Tests creation/deletion of an S3 bucket"


class VerifyUserGroupTest(ATest):
    conf = None

    def __init__(self, base):
        super(VerifyUserGroupTest, self).__init__(VerifyUserGroupTest, base)
        super(VerifyUserGroupTest, self).add_as_dependent_on(AddUserToGroupTest)

    def _run_(self, conf):
        self.conf = conf
        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        iam_r = session.resource('iam')

        group = iam_r.Group(conf.aws_admin_group)
        group.load()
        found = False
        for att in range(0, 5):
            try:
                users = group.users.all()
                for u in users:
                    if u.name == conf.test_account:
                        found = True
                        break
                if not found:
                    raise Exception("Group not found")
                break
            except:
                time.sleep(3)
                group.reload()
        if not found:
            print "Group does not have user " + conf.test_account
            return
        super(VerifyUserGroupTest, self).set_passed()

    def _get_description_(self):
        return "Verifies that user has been added to the group"


class AddUserToGroupTest(ATest):
    conf = None

    def __init__(self, base):
        super(AddUserToGroupTest, self).__init__(AddUserToGroupTest, base)
        super(AddUserToGroupTest, self).add_as_dependent_on(CreateTestAccountTest)

    def _run_(self, conf):
        self.conf = conf
        dep_t_cont = super(AddUserToGroupTest, self).get_dep_test_context(CreateTestAccountTest)
        if not dep_t_cont.is_passed():
            print "Dependent test failed"
            return
        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        iam_clt = session.client('iam')
        # Verify group exists
        response = iam_clt.list_groups()
        found = False
        for g in response['Groups']:
            if g['GroupName'] == conf.aws_admin_group:
                found = True
                break
        if not found:
            return
        # Adding user to the group
        iam_clt.add_user_to_group(GroupName=conf.aws_admin_group,
                                  UserName=conf.test_account)
        super(AddUserToGroupTest, self).set_passed()

    def _shutdown_(self):
        if not super(AddUserToGroupTest, self).is_passed():
            return
        # Remove user from group
        session = boto3.session.Session(aws_access_key_id=self.conf.aws_admin_key_id,
                                        aws_secret_access_key=self.conf.aws_admin_key_secret,
                                        region_name=self.conf.aws_test_region)
        iam_clt = session.client('iam')
        iam_clt.remove_user_from_group(GroupName=self.conf.aws_admin_group,
                                       UserName=self.conf.test_account)

    def _get_description_(self):
        return "Tests addition a user to a admin group"


class CreateTestAccountTest(ATest):
    conf = None

    def __init__(self, base):
        super(CreateTestAccountTest, self).__init__(CreateTestAccountTest, base)

    def _run_(self, conf):
        self.conf = conf
        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        iam_r = session.resource('iam')
        current_user = iam_r.CurrentUser()
        print "This account: " + current_user.path + ":" + current_user.user_name + ":" + str(current_user.password_last_used)

        name = conf.test_account
        print "Check if user exists..."
        user = iam_r.User(name)
        conf.test_user_key_pair = None
        try:
            user.load()
            # if we are here,
            print "Clean up needs to be done. User was not removed."
        except:
            # Create a new user
            print "No, creating new test account: " + name
            user.create(Path="/")
            conf.test_user_key_pair = user.create_access_key_pair()
            print "Test user key pair: " + conf.test_user_key_pair.id
        user.reload()
        super(CreateTestAccountTest, self).set_passed()
        # List a new user
        print "New account: " + user.user_id + ":" + user.user_name + ":" + str(user.password_last_used)

    def _shutdown_(self):
        name = self.conf.test_account
        print "Delete test account: " + name
        session = boto3.session.Session(aws_access_key_id=self.conf.aws_admin_key_id,
                                        aws_secret_access_key=self.conf.aws_admin_key_secret,
                                        region_name=self.conf.aws_test_region)
        iam_r = session.resource('iam')
        user = iam_r.User(name)
        try:
            user.load()
        except:
            print "Already deleted."
            return
        # Delete user
        if self.conf.test_user_key_pair is not None:
            self.conf.test_user_key_pair.delete()
        user.delete()

    def _get_description_(self):
        return "Tests new user account creation"


class PrintWaitersTest(ATest):

    def __init__(self, base):
        super(PrintWaitersTest, self).__init__(PrintWaitersTest, base)

    def _run_(self, conf):
        s3 = boto3.client('s3')
        sqs = boto3.client('sqs')

        # List all of the possible waiters for both clients
        print("s3 waiters:")
        s3.waiter_names

        print("sqs waiters:")
        sqs.waiter_names
        super(PrintWaitersTest, self).set_passed()

    def _get_description_(self):
        return "Tests waiters names"



class GetUserCredentialsUITest(ATest):
    crd_list = None

    def __init__(self, base, user, pwd, account, file):
        super(GetUserCredentialsUITest, self).__init__(GetUserCredentialsUITest, base)
        self.user = user
        self.pwd = pwd
        self.account = account
        self.file = file

    def _run_(self, conf):
        if os.path.isfile(self.file):
            os.remove(self.file)
        attemptToGetUserCredentials(conf, self.account, self.user, self.pwd)
        self.crd_list = extractCredentials(self.user, self.file)
        super(GetUserCredentialsUITest, self).set_passed()

    def _get_description_(self):
        return "Tests get user credential by loggin into AWS account through Web UI"



class StartStopInstanceTest(ATest):

    def __init__(self, base):
        super(StartStopInstanceTest, self).__init__(StartStopInstanceTest, base)

    def _run_(self, conf):
        session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        ec2_clt = session.client('ec2')
        #ec2_clt = boto3.client('ec2')
        response = ec2_clt.describe_instances(
                           DryRun=False,
        )
        instance_id = None
        if response is not None:
            if 'Reservations' in response.keys():
                for res in response['Reservations']:
                    if 'Instances' in res.keys():
                        for inst in res['Instances']:
                            instance_id = inst['InstanceId']
                            break
        if instance_id is None:
            return

        ec2_rs = session.resource('ec2')
        instance = ec2_rs.Instance(instance_id)
        instance.load()
        print str(instance)
        if instance is None:
            print "Instance was not found"
        if instance.state['Code'] == 16: # running
            print "Instance is running. Stopping"
            response = instance.stop(DryRun=False)
        else:
            print "Staring instance"
            response = instance.start(DryRun=False)
        self.set_passed()

    def _get_description_(self):
        return "Tests get user credential by log in into AWS account through Web UI"



class FailUserLoginTest(ATest):

    def __init__(self, base):
        super(FailUserLoginTest, self).__init__(FailUserLoginTest, base)

    def _run_(self, conf):
        failUserLogins(conf, conf.aws_account, conf.test_account, conf.num_failed_attempts)

    def _get_description_(self):
        return "Fails user log in multiple times"


class SetUpBoto3DefaultSessionTest(ATest):
    crd_list = None

    def __init__(self, base):
        super(SetUpBoto3DefaultSessionTest, self).__init__(SetUpBoto3DefaultSessionTest, base)

    def _run_(self, conf):
        print "Using key pair to set up default session: " + conf.test_user_key_pair.id + ":" + conf.test_user_key_pair.secret
        boto3.setup_default_session(aws_access_key_id=conf.test_user_key_pair.id,
                                    aws_secret_access_key=conf.test_user_key_pair.secret,
                                    region_name=conf.aws_test_region)
        print "Default session set up to: " + str(boto3._get_default_session())

    def _get_description_(self):
        return "Sets up and test default boto3 session"


def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--c"
                              "onfig", default="config.py", dest="conf_location",
                       help="Location of the configuration file")
    return parser.parse_args()



if __name__ == "__main__":

    args = parseArgs()
    print args
    cf = loadConfig(args.conf_location)
    print "Running test for " + cf.aws_account

    test_base = TestBase()

    # Always test #1

    #
    # Adding tests after this block
    #
    CreateTestAccountTest(test_base)
    AddUserToGroupTest(test_base)
    # TODO: write user verification test. Without it, test will continue to fail when it uses new user credentials

    if cf.num_failed_attempts != 0:
        FailUserLoginTest(test_base)

    SetUpBoto3DefaultSessionTest(test_base)

    #crd_list = None
    #if cf.get_new_credentials:
    #    GetUserCredentialsTest(test_base, cf.aws_admin_user, cf.aws_admin_pwd,
    #                           cf.aws_account, cf.aws_credentials_file)
    #else:
    #    crd_list = extractCredentials(cf.aws_admin_user, cf.aws_credentials_file)

    #cf.has_master_key = True
    VerifyUserGroupTest(test_base)
    GetInstanceStatusTest(test_base)
    StartStopInstanceTest(test_base)
    ListCreateDeleteBucketTest(test_base)
    GrantPublicAccessToBucketTest(test_base)
    PrintWaitersTest(test_base)

    # Run added tests
    try:
        test_base.exec_tests(cf)
    except:
        traceback.print_exc()
    #exit(1)
    test_base.done()
