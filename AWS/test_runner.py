import os
import json
import argparse
import traceback
import boto3
from boto3.session import Session

from AWS.utils.common import extractCredentials, loadConfig
import utils.aws_ui
from cutils.test_connector import ATest, TestBase


class GetInstanceStatusTest(ATest):

    def __init__(self, base):
        super(GetInstanceStatusTest, self).__init__(GetInstanceStatusTest, base)

    def _run_(self, conf):
        print "===> TEST: Getting status for instance: " + conf.aws_instance_id
        ec2_cl = boto3.client('ec2')
        try:
            response = ec2_cl.describe_instances(
                                  DryRun=False,
                                  InstanceIds=[
                                         conf.aws_instance_id,
                                  ]
            )
            print response
        except:
            print "Instance not found."
        print "<===="


class ListCreateDeleteBucketTest(ATest):

    def __init__(self, base):
        super(ListCreateDeleteBucketTest, self).__init__(ListCreateDeleteBucketTest, base)

    def _run_(self, conf):
        bucket_id = conf.test_bucket_name
        print "===> TEST: List/Create/Delete for bucket: " + bucket_id
        client = boto3.client('s3')
        response = client.list_buckets()
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
            s3_res = boto3.resource('s3')
            bucket = s3_res.Bucket(bucket_id)
            response = bucket.create(
                       ACL='private',
                       CreateBucketConfiguration={
                               'LocationConstraint': 'eu-west-1'
                       })
            print response

        print "Deleting bucket "
        response = client.delete_bucket(Bucket=bucket_id)
        print "<===="
        print response

class AssumeRoleAndStartInstaceTest(ATest):
    def __init__(self, base):
        super(AssumeRoleAndStartInstaceTest, self).__init__(AssumeRoleAndStartInstaceTest, base)

    def _assignRole_(self, role_name, role_context, policy_context):
        iam_cl = boto3.client('iam')
        d1 = iam_cl.get_role(RoleName='test')
        d = d1['Role']['AssumeRolePolicyDocument']
        for a2 in d:
            print "    '" + a2 + "': " + str(d[a2])
            role = iam_cl.create_role(RoleName=role_name,
                                      AssumeRolePolicyDocument=json.dumps(role_context))
        role.RolePolicy('more-permissions').put(
                          PolicyDocument=json.dumps(policy_context))

        role.reload()

    def _run_(self, conf):
        print "===> TEST: Assume Role & Start Instance: "
        assume_role = """{
             "Version": "2012-10-17",
             "Statement": {
                 'Effect': 'Allow',
                 'Action': 'sts:AssumeRole',
                 'Principal': {'Service': 'ec2.amazonaws.com'}
             }
        }"""
        policy = """{
            "Version": "2012-10-17",
            "Statement": [
                   {
                   "Action": "ec2:*",
                   "Effect": "Allow",
                   "Resource": "*"
            }
        }"""
        self._assignRole_(conf.test_role_name, assume_role, policy)

        session = boto3.session.Session(aws_access_key_id=conf.test_user_key_pair.id,
                                        aws_secret_access_key=conf.test_user_key_pair.secret)
        ec2_cl = session.client('ec2')
        ec2_cl.stop_instace(conf.aws_instance_id)
        print "<===="


class CreateTestAccountTest(ATest):
    conf = None

    def __init__(self, base):
        super(CreateTestAccountTest, self).__init__(CreateTestAccountTest, base)

    def _run_(self, conf):
        self.conf = conf
        print "===> TEST: Create account "
        iam = boto3.resource('iam')
        current_user = iam.CurrentUser()
        print "This account: " + current_user.path + ":" + current_user.user_name + ":" + str(current_user.password_last_used)

        name = conf.test_account
        print "Creating new test account: " + name
        user = iam.User(name)
        conf.test_user_key_pair = None
        try:
            user.load()
        except:
            # Create a new user
            user.create(Path="/")
            conf.test_user_key_pair = user.create_access_key_pair()
            print "Test user key pair: " + conf.test_user_key_pair.id
        # List a new user
        print "New account: " + user.user_id + ":" + user.user_name + ":" + str(user.password_last_used)
        print "<==="

    def _shutdown_(self):
        print "===> TEST: Delete account "
        name = self.conf.test_account
        print "Delete test account: " + name
        iam = boto3.resource('iam')
        user = iam.User(name)
        try:
            user.load()
        except:
            print "Already deleted."
            return
        # Delete user
        if self.conf.test_user_key_pair is not None:
            self.conf.test_user_key_pair.delete()
        user.delete()
        print "<==="


class PrintWaitersTest(ATest):
    def __init__(self, base):
        super(PrintWaitersTest, self).__init__(PrintWaitersTest, base)

    def _run_(self, conf):
        print "===> TEST: Waiters "
        s3 = boto3.client('s3')
        sqs = boto3.client('sqs')

        # List all of the possible waiters for both clients
        print("s3 waiters:")
        s3.waiter_names

        print("sqs waiters:")
        sqs.waiter_names
        print "<==="


class GetUserCredentialsTest(ATest):
    crd_list = None

    def __init__(self, base, user, pwd, account, file):
        super(GetUserCredentialsTest, self).__init__(GetUserCredentialsTest, base)
        self.user = user
        self.pwd = pwd
        self.account = account
        self.file = file

    def _run_(self, conf):
        print "===> TEST: Get user credential through UI "
        if os.path.isfile(self.file):
            os.remove(self.file)
        utils.aws_ui.attemptToGetUserCredentials(conf, self.account, self.user, self.pwd)
        print "<==="
        self.crd_list = extractCredentials(self.user, self.file)


class StartStopInstanceTest(ATest):

    def __init__(self, base):
        super(StartStopInstanceTest, self).__init__(StartStopInstanceTest, base)

    def _run_(self, conf):
        ec2_rs = boto3.resource('ec2')
        instance = ec2_rs.Instance(conf.aws_instance_id)
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
        print response


class FailUserLoginTest(ATest):

    def __init__(self, base):
        super(FailUserLoginTest, self).__init__(FailUserLoginTest, base)

    def _run_(self, conf):
        utils.aws_ui.failUserLogins(conf, conf.aws_account, conf.aws_admin_user, conf.num_failed_attempts)


class SetUpBoto3DefaultSessionTest(ATest):
    crd_list = None

    def __init__(self, base, crd_list):
        super(SetUpBoto3DefaultSessionTest, self).__init__(SetUpBoto3DefaultSessionTest, base)
        if crd_list is None:
            super(SetUpBoto3DefaultSessionTest, self).add_dependent_test(GetUserCredentialsTest)
            return
        self.crd_list = crd_list

    def _run_(self, conf):
        clist = self.crd_list
        if clist is None:
            dep_t_cont = super(SetUpBoto3DefaultSessionTest, self).get_dep_test_context(GetUserCredentialsTest)
            clist = dep_t_cont.crd_list
        boto3.setup_default_session(aws_access_key_id=clist[1],
                                    aws_secret_access_key=clist[2],
                                    region_name='us-west-2')

def parseArgs():
   parser = argparse.ArgumentParser()
   parser.add_argument("-c", "--config", default="config.py", dest="conf_location",
                       help="Location of the configuration file")
   return parser.parse_args()

if __name__ == "__main__":

    args = parseArgs()
    print args
    cf = loadConfig(args.conf_location)
    print "Running test for " + cf.aws_account + "; user: " + cf.aws_admin_user
    print "Inst: " + cf.aws_instance_id

    test_base = TestBase()

    if cf.num_failed_attempts != 0:
        FailUserLoginTest(test_base)
        #utils.aws_ui.failUserLogins(cf, cf.aws_account, cf.aws_admin_user, cf.num_failed_attempts)

    crd_list = None
    if cf.get_new_credentials:
        GetUserCredentialsTest(test_base, cf.aws_admin_user, cf.aws_admin_pwd,
                               cf.aws_account, cf.aws_credentials_file)
    else:
        crd_list = extractCredentials(cf.aws_admin_user, cf.aws_credentials_file)

    SetUpBoto3DefaultSessionTest(test_base, crd_list)

    cf.has_master_key = True

    CreateTestAccountTest(test_base)
    #AssumeRoleAndStartInstaceTest(test_base)
    GetInstanceStatusTest(test_base)
    StartStopInstanceTest(test_base)
    ListCreateDeleteBucketTest(test_base)
    PrintWaitersTest(test_base)

    try:
        test_base.exec_tests(cf)
    except:
        traceback.print_exc()

    test_base.done()
