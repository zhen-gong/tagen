import os
import time
import traceback

import boto3
from boto3.session import Session

from AWS.utils.ui import failUserLogins, attemptToGetUserCredentials
from AWS.utils.common import extractCredentials
from cutils.config import load_config
from cutils.others import parse_args
from cutils.test_base import BaseTest, TestBase
import boto.rds
import time
import boto.ec2
import boto
import boto.iam

class GetWaitInstanceStatusTest(BaseTest):

    def __init__(self, base):
        super(GetWaitInstanceStatusTest, self).__init__(GetWaitInstanceStatusTest, base)

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
        self.set_passed()

    def _get_description_(self):
        return "Tests return of status for an instance."


class WaitInstanceStatusTest(BaseTest):
    stat_dist = {'running': 16, 'stopped': 22}
    delay = 5000

    def __init__(self, base, wait_for_status='running', delay=5000):
        super(WaitInstanceStatusTest, self).__init__(WaitInstanceStatusTest, base)
        self.wait_for_status = wait_for_status
        self.delay = delay

    def _run_(self, conf):
        session = boto3.session.Session(aws_access_key_id=conf.test_user_key_pair.id,
                                        aws_secret_access_key=conf.test_user_key_pair.secret,
                                        region_name=conf.aws_test_region)
        ec2_rs = session.resource('ec2')
        instance = ec2_rs.Instance(conf.aws_instance_id)
        for t in range(0, 5):
            print "Reloading instance status: " + str(instance)
            instance.reload()
            if instance.state['Code'] != self.stat_dist[self.wait_for_status]:
                time.sleep(self.delay)
                continue
        if instance.state['Code'] == self.stat_dist[self.wait_for_status]:
            self.set_passed()

    def _get_description_(self):
        return "Wait for instance to get a particular status"


class StartStopInstanceTest(BaseTest):

    def __init__(self, base, use_test_acc_cred=True, wait=False, wait_for_status='running'):
        super(StartStopInstanceTest, self).__init__(StartStopInstanceTest, base)
        self.underTestUser = use_test_acc_cred
        self.wait = wait
        self.wait_for_status = wait_for_status

    def _run_(self, conf):
        if not self.underTestUser:
            session = boto3.session.Session(aws_access_key_id=conf.test_user_key_pair.id,
                                        aws_secret_access_key=conf.test_user_key_pair.secret,
                                        region_name=conf.aws_test_region)
        else:
            session = boto3.session.Session(aws_access_key_id=conf.aws_admin_key_id,
                                        aws_secret_access_key=conf.aws_admin_key_secret,
                                        region_name=conf.aws_test_region)
        ec2_clt = session.client('ec2')
        response = ec2_clt.describe_instances(
                           DryRun=False,
        )
        instance_id = None
        if response is not None:
            if 'Reservations' in response.keys():
                for res in response['Reservations']:
                    if 'Instances' in res.keys():
                        for inst in res['Instances']:
                            print "Found instance: " + inst['InstanceId']
                            if inst['InstanceId'] == conf.aws_instance_id:
                                instance_id = inst['InstanceId']
                            break
        if instance_id is None:
            print "No instance found: " + conf.aws_instance_id
            return

        ec2_rs = session.resource('ec2')
        instance = ec2_rs.Instance(instance_id)
        instance.load()
        print str(instance)
        if instance is None:
            print "Instance was not found"
            return
        if instance.state['Code'] == 16: # running
            print "Instance is running. Stopping"
            response = instance.stop(DryRun=False)
        else:
            print "Staring instance"
            response = instance.start(DryRun=False)
        self.set_passed()

    def _get_description_(self):
        return "Tests get user credential by log in into AWS account through Web UI"


class GrantPublicAccessToBucketTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(GrantPublicAccessToBucketTest, self).__init__(GrantPublicAccessToBucketTest, base)
        self.add_as_dependent_on(ListCreateDeleteBucketTest)

    def _run_(self, conf):
        self.conf = conf
        session = boto3.session.Session(aws_access_key_id=self.conf.test_user_key_pair.id,
                                        aws_secret_access_key=self.conf.test_user_key_pair.secret,
                                        region_name=self.conf.aws_test_region)
        s3_clt = session.client('s3')
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
        return "Grant public access to S3 bucket"


class ListCreateDeleteBucketTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(ListCreateDeleteBucketTest, self).__init__(ListCreateDeleteBucketTest, base)
        self.add_as_dependent_on(AddUserToGroupTest)

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
            prl = self.proxy.split(':') if self.proxy else None
            proxy = proxy_port = None
            if prl:
                proxy = ":".join(prl[:2])
                proxy_port = prl[2]
            prl = self.conf.http_proxy.split(':') if self.conf.http_proxy else (None, None)
            s3_connection = boto.connect_s3(aws_access_key_id=conf.aws_admin_key_id,
                                            aws_secret_access_key=conf.aws_admin_key_secret,
                                            proxy=proxy, proxy_port=proxy_port)
            response = s3_connection.create_bucket(bucket_id, location='us-west-1')
            s3_connection.close()
            #bucket = s3_res.Bucket(bucket_id)
            #response = bucket.create(
            #           ACL='private',
            #           CreateBucketConfiguration={
            #                   'LocationConstraint': 'us-west-1'
            #           })
            print response
        with open("/tmp/hello.txt", "w") as text_file:
            text_file.write("Hello test string.")
        for i in range(0, 5):
            s3_res.Object(bucket_id, str(i) + 'hello.txt').put(Body=open('/tmp/hello.txt', 'rb'))
        self.set_passed()

    def _shutdown_(self):
        print "Deleting bucket "
        bucket_id = self.conf.test_bucket_name
        prl = self.conf.http_proxy.split(':') if self.conf.http_proxy else (None, None)
        s3_connection = boto.connect_s3(aws_access_key_id=self.conf.aws_admin_key_id,
                                        aws_secret_access_key=self.conf.aws_admin_key_secret,
                                        proxy=prl[0], proxy_port=prl[1])
        bucket = s3_connection.get_bucket(bucket_id, validate=False)
        print "Bucket: " + str(bucket)
        exists = s3_connection.lookup(bucket_id)
        print "Bucket exists: " + bucket_id
        if exists:
            for key in bucket:
                print "Delete key: " + str(key)
                key.delete()
            bucket.delete()

        #session = boto3.session.Session(aws_access_key_id=self.conf.test_user_key_pair.id,
        #                                aws_secret_access_key=self.conf.test_user_key_pair.secret,
        #                                region_name=self.conf.aws_test_region)
        #s3_clt = session.client('s3')
        #response = s3_clt.delete_bucket(Bucket=bucket_id)
        # Boto 3
        self.set_passed()
        #print response

    def _get_description_(self):
        return "Tests creation/deletion of an S3 bucket"


class VerifyUserGroupTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(VerifyUserGroupTest, self).__init__(VerifyUserGroupTest, base)
        self.add_as_dependent_on(AddUserToGroupTest)

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
        self.set_passed()

    def _get_description_(self):
        return "Verifies that user has been added to the group"


class AddUserToGroupTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(AddUserToGroupTest, self).__init__(AddUserToGroupTest, base)
        self.add_as_dependent_on(CreateTestAccountTest)

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
        self.set_passed()

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


class CreateTestAccountTest(BaseTest):
    conf = None

    def __init__(self, base):
        super(CreateTestAccountTest, self).__init__(CreateTestAccountTest, base)
        print "Self : " + str(self)

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
        self.set_passed()
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


class PrintWaitersTest(BaseTest):

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


class GetUserCredentialsUITest(BaseTest):
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
        self.set_passed()

    def _get_description_(self):
        return "Tests get user credential by loggin into AWS account through Web UI"


class FailUserLoginTest(BaseTest):

    def __init__(self, base):
        super(FailUserLoginTest, self).__init__(FailUserLoginTest, base)

    def _run_(self, conf):
        failUserLogins(conf, conf.aws_account, conf.test_account, conf.num_failed_attempts)

    def _get_description_(self):
        return "Fails user log in multiple times"


class SetUpBoto3DefaultSessionTest(BaseTest):
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

DB_NAME = "db-test"
DB_PASSWORD = 'password'
DB_USER = 'root'
class CreateRDSTest(BaseTest):

    def __init__(self, base):
        super(CreateRDSTest, self).__init__(CreateRDSTest, base)

    def teardown_rds(self, conn):
        try:
            db_inst = conn.get_all_dbinstances(instance_id=DB_NAME)[0]
        except:
            print('There was no RDS instance with name %s' % DB_NAME)
            return
        
        print('Removing RDS instance')
        conn.delete_dbinstance(db_inst.id, skip_final_snapshot=True)
    
        while True:
            try:
                conn.get_all_dbinstances(instance_id=DB_NAME)[0]
            except:
                break
            else:
                time.sleep(30)
                print('Waiting...')
        
        try:
            conn.delete_dbsecurity_group(SG_NAME)
        except:
            print('No DB security group %s to delete' % SG_NAME)
    
    def _run_(self, conf):
        print('Connecting RDS')
        conn = boto.rds.connect_to_region(conf.aws_test_region, aws_access_key_id=conf.test_user_key_pair.id, aws_secret_access_key=conf.test_user_key_pair.secret)

        self.teardown_rds(conn)
    
        print('Creating DB instance')
        db = conn.create_dbinstance(DB_NAME, 5, 'db.m1.small', DB_USER, DB_PASSWORD)
        
        while True:
            try:
                db = conn.get_all_dbinstances(instance_id=DB_NAME)[0]
            except Exception, e:
                print('Unexpected exception "%s"' % e)
            else:
                if db.endpoint is not None and db.status == 'available':
                    break
    
            time.sleep(30)
            print('Waiting...')
        
        print "RDS has been created successfully."
    
        self.teardown_rds(conn)

    def _get_description_(self):
        return "Tests return of status for new RDS setup."
        
SG_NAME = 'lsl-tagen-sg-test'
class CreateEC2SecurityGroupTest(BaseTest):

    def __init__(self, base):
        super(CreateEC2SecurityGroupTest, self).__init__(CreateEC2SecurityGroupTest, base)

    def teardown_ec2_security_group(self, conn):
        for sg in conn.get_all_security_groups():
            if sg.name == SG_NAME:
                print('Delete Security Group')
                conn.delete_security_group(SG_NAME)
                break
    
    def _run_(self, conf):
        print('Connecting EC2')
        conn = boto.ec2.connect_to_region(conf.aws_test_region, aws_access_key_id=conf.test_user_key_pair.id,
                                          aws_secret_access_key=conf.test_user_key_pair.secret)
    
        self.teardown_ec2_security_group(conn)
        
        print('Creating Security Group')
        web = conn.create_security_group(SG_NAME, 'Allow ports 80 and 22.')
        web.authorize('tcp', 80, 80, '0.0.0.0/0')
        web.authorize('tcp', 22, 22, '0.0.0.0/0')
        print "Security Group has been created successfully."
    
        self.teardown_ec2_security_group(conn)
        
    def _get_description_(self):
        return "Tests return of status for new Security Group setup."

IAM_USER = "lsl-iam-test-user"
class CreateIAMUserTest(BaseTest):

    def __init__(self, base):
        super(CreateIAMUserTest, self).__init__(self, base)

    def teardown_iam_user(self, conn):
        try:
            conn.delete_login_profile(IAM_USER)
        except:
            pass
    
        try:
            conn.delete_user(IAM_USER)
            print('Test user removed')
        except:
            pass
    
    def _run_(self, conf):
        print 'Update IAM Password Policy'
        session = boto3.session.Session(aws_access_key_id=conf.test_user_key_pair.id,
                                      aws_secret_access_key=conf.test_user_key_pair.secret)
        iam = session.client('iam')
        iam.update_account_password_policy(MinimumPasswordLength=6,RequireSymbols=False,RequireNumbers=False,RequireUppercaseCharacters=False,RequireLowercaseCharacters=False,AllowUsersToChangePassword=False,MaxPasswordAge=90,PasswordReusePrevention=3,HardExpiry=False)

        print('Connecting IAM')
        conn = boto.iam.IAMConnection(aws_access_key_id=conf.test_user_key_pair.id,
                                      aws_secret_access_key=conf.test_user_key_pair.secret)
        
        self.teardown_iam_user(conn)
    
        print('Creating Test User')
        conn.create_user(IAM_USER)
        conn.create_login_profile(IAM_USER, "nmTGWe9nmTGWe9")
        time.sleep(10) #ensure user creation complete on AWS side
        print "Test user has been created successfully."
    
        print('Connecting IAM via Proxy')
        conn2 = boto.iam.IAMConnection(aws_access_key_id=conf.test_user_key_pair.id,
                                      aws_secret_access_key=conf.test_user_key_pair.secret, is_secure=True, proxy="52.18.122.207", proxy_port="8888")
        self.teardown_iam_user(conn2)
        
    def _get_description_(self):
        return "Tests return of status for new IAM User setup."

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
    GetWaitInstanceStatusTest(test_base)
    StartStopInstanceTest(test_base)
    ListCreateDeleteBucketTest(test_base)
    GrantPublicAccessToBucketTest(test_base)
    # UBA CreateRDSTest(test_base) #to cover UBA test case
    CreateEC2SecurityGroupTest(test_base) #test weak security group and policy violation
    CreateIAMUserTest(test_base) #test weak user password, IP hopping via proxy

    #PrintWaitersTest(test_base)

    # Run added tests
    try:
        test_base.exec_tests(cf)
    except:
        traceback.print_exc()
    #exit(1)
    test_base.done()
