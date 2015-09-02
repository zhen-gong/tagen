import os
import re
import string
import boto3
import json
import traceback
from boto3.session import Session
import utils.aws_ui
import config.config

def getInstanceStatus(conf):
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

def listCreateDeleteBucket(conf):
    bucket_id = conf.test_bucket_name
    print "===> TEST: List/Create/Delete for bucket: " + bucket_id
    client = boto3.client('s3')
    response = client.list_buckets()
    print "List of buckets:"
    print response

    haveBucket = False
    if response != None:
        for b in response['Buckets']:
            if b['Name'] == bucket_id:
                haveBucket = True
                break
    if not haveBucket:
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

def assignRole(role_name, role_context, policy_context):

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

def assumeRoleAndStartInstace(conf):
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
    assignRole(conf.test_role_name, assume_role, policy)

    session = boto3.session.Session(aws_access_key_id=conf.test_user_key_pair.id,
                                    aws_secret_access_key=conf.test_user_key_pair.secret)
    ec2_cl = session.client('ec2')
    ec2_cl.stop_instace(conf.aws_instance_id)
    print "<===="


def createTestAccount(conf):
    print "===> TEST: Create account "
    iam = boto3.resource('iam')
    current_user = iam.CurrentUser()
    print "This account: " + current_user.path + ":" + current_user.user_name + ":" + str(current_user.password_last_used)

    name = conf.test_account
    print "Creating new test account: " + name
    user = iam.User(name)
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

def deleteTestAccount(conf):
    print "===> TEST: Delete account "
    name = conf.test_account
    print "Delete test account: " + name
    iam = boto3.resource('iam')
    user = iam.User(name)
    try:
       user.load()
    except:
        print "Already deleted."
        return
    # Delete user
    if conf.test_user_key_pair != None:
        conf.test_user_key_pair.delete()
    user.delete()
    print "<==="

def printWaiters():

    print "===> TEST: Waiters "
    s3 = boto3.client('s3')
    sqs = boto3.client('sqs')

    # List all of the possible waiters for both clients
    print("s3 waiters:")
    s3.waiter_names

    print("sqs waiters:")
    sqs.waiter_names
    print "<==="

def getUserCredentials(user, pwd, account, file):
    print "===> TEST: Get user credential through UI "
    if os.path.isfile(file):
        os.remove(file)
    utils.aws_ui.attemptToGetUserCredentials(account, user, pwd)
    print "<==="
    return extractCredentials(user, file)

def startStopInstace(conf):
    print "===> TEST: Start Instance: "
    ec2_rs = boto3.resource('ec2')
    instance = ec2_rs.Instance(conf.aws_instance_id)
    instance.load()
    if instance.state['Code'] == 16: # running
        print "Instance is running. Stopping"
        response = instance.stop(DryRun=False)
    else:
        print "Staring instance"
        response = instance.start(DryRun=False)
    print response
    print "<===="

def extractCredentials(user, file):
    pattern = re.compile("^\""+ user +"\",")
    with open(file) as f:
        content = f.readlines()
        for l in content:
            if pattern.match(l):
                return string.split(l, ',')
    return None

def loadConfig():
    with open("config/aws_config.py") as f:
        content = f.readlines()
    conf = config.config.AwsConfig()
    for l in content:
        exec l
    return conf

if __name__ == "__main__":

    cf = loadConfig()
    print "Running test for " + cf.aws_account + "; user: " + cf.aws_user
    print "Inst: " + cf.aws_instance_id

    if cf.num_failed_attempts != 0:
        utils.aws_ui.failUserLogins(cf.aws_account, cf.aws_user, cf.num_failed_attempts)

    if cf.get_new_credentials:
        crd_list = getUserCredentials(cf.aws_user, cf.aws_pwd, cf.aws_account, cf.aws_credentials_file)
    else:
        crd_list = extractCredentials(cf.aws_user, cf.aws_credentials_file)

    if crd_list == None:
        print "Missing credentials"
        exit(1)

    boto3.setup_default_session(aws_access_key_id=crd_list[1],
                                aws_secret_access_key=crd_list[2],
                                region_name='us-west-2')
    try:
        createTestAccount(cf)
        #assumeRoleAndStartInstace(cf)
        getInstanceStatus(cf)
        startStopInstace(cf)
        listCreateDeleteBucket(cf)
    except:
        traceback.print_exc()
    finally:
        deleteTestAccount(cf)
        printWaiters()

