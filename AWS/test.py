import os
import re
import string
import boto3
import json
from boto3.session import Session
import utils.aws_ui

aws_credentials_file="/tmp/webdriver-downloads/credentials.csv"
aws_user = "test1"
aws_pwd = "test1"
aws_account = "test1"
aws_instance = "i-22e071ea"

def getInstanceStatus(id):

    ec2_cl = boto3.client('ec2')

    response = ec2_cl.describe_instances(
             DryRun=False,
             InstanceIds=[
                id,
             ]
    )

    print response

def listCreateDeleteBucket(id):

    client = boto3.client('s3')
    response = client.list_buckets()

    s3_res = boto3.resource('s3')
    bucket = s3_res.Bucket(id)
    response = bucket.create(
                       ACL='private',
                       CreateBucketConfiguration={
                               'LocationConstraint': 'eu-west-1'
                       })
    print response

    response = bucket.delete_bucket(Bucket=id)
    print response

def assignRole(user, role_name, role_context, policy_context):

    iam = boto3.resource("aim")
    role = iam.create_role(RoleName=role_name,
                           AssumeRolePolicyDocument=json.dumps(role_context))
    role.RolePolicy('more-permissions').put(
                          PolicyDocument=json.dumps(policy_context))

    return role

    instance_profile = iam.create_instance_profile('myinstanceprofile')
    role = c.create_role('myrole')
    #c.add_role_to_instance_profile('myinstanceprofile', 'myrole')
    #{u'add_role_to_instance_profile_response': {u'response_metadata': {u'request_id': u'2221d92c-b437-11e1-86e5-c9c4f3b58653'}}}
    #c.put_role_policy('myrole', 'mypolicy', assume_role)
    #{u'put_role_policy_response': {u'response_metadata': {u'request_id': u'2b878c93-b437-11e1-86e5-c9c4f3b58653'}}}
    #c = boto.connect_ec2()
    #c.run_instances('ami-e565ba8c', key_name='mykeyname', security_groups=['mysecuritygroup'], instance_type='t1.micro', instance_profile_name='myinstanceprofile')

def startInstace():
    assume_role = """{
        "Statement": {
             "Effect": "Allow",
             "Principal": {"Service": "ec2.amazonaws.com"},
             "Action": "sts:AssumeRole"
        }
    }"""
    policy = """{
       "Statement": {
          "Effect": "Allow",
          "Action": "ec3:StartInstances, TerminateInstances",
          "Resource": "arn:aws:ec2:::*"
       }
    }"""
    role = assignRole("test_user2", "ec2_access", assume_role, policy)

    ec2_cl = boto3.client('ec2')
    ec2_cl.stop_instace(aws_instance)



def createNewAccount(name):
    iam = boto3.resource('iam')
    current_user = iam.CurrentUser()
    print "This account: " + current_user.path + ":" + current_user.user_name + ":" + str(current_user.password_last_used)

    user = iam.User(name)
    try:
       user.load()
    except:
        # Create a new user
        user.create(Path="/")

    # List a new user
    print "New account: " + user.user_id + ":" + user.user_name + ":" + str(user.password_last_used)

    # Delete user
    user.delete()

def printWaiters():

    s3 = boto3.client('s3')
    sqs = boto3.client('sqs')

    # List all of the possible waiters for both clients
    print("s3 waiters:")
    s3.waiter_names

    print("sqs waiters:")
    sqs.waiter_names

def extractCredentials():
    pattern = re.compile("^\""+ aws_user +"\",")
    with open(aws_credentials_file) as f:
        content = f.readlines()
        for l in content:
            if pattern.match(l):
                return string.split(l, ',')
    return None

if __name__ == "__main__":


    if os.path.isfile(aws_credentials_file):
       os.remove(aws_credentials_file)
    utils.aws_ui.attemptToGetUserCredentials(aws_account, aws_user, aws_pwd)
    crd_list = extractCredentials()

    if crd_list == None:
        print "Missing credentials"
        exit(1)

    boto3.setup_default_session(aws_access_key_id=crd_list[1],
                                aws_secret_access_key=crd_list[2],
                                region_name='us-west-2')

    createNewAccount('tagen-tester')
    getInstanceStatus("i-22e071ea")
    listCreateDeleteBucket('tagen-test-bucket')
    #printWaiters()

