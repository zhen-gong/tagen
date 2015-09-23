
class AwsConfig(object):
    """
# FROM ---->>>
#
# Default configuration file was not checked is to avoid leaks of credentials.
#
# Copy this block of python code (FROM --->>> <<<---TO) into config file. Default config file name is "./config.py".
# If location of the config is different from the default, use -c <file name> option to specify a new location/file.

#
# NOTE:
#      ! This is python code. Should comply with language syntax. !
#      ! Make sure that "conf." precedes every variable. !
#      ! Values are enclosed in the double or single quotes. !
#

# AWS account been tested. Most of the time the corporate account would have a name, like "palerra-dev", but a
# a personal would be a 10-12 digits number.
conf.aws_account = "111111111111111"

# Secret and Key of an test admin and name of administrator group
conf.aws_admin_key_id = "id"
conf.aws_admin_key_secret = "key"
conf.aws_admin_group = "admins"

# Should be True for the first time.
# If True, gets new credential(pair of new keys) for admin test account specified in conf.aws_admin_user variable.
# If False, will bypass the test and use already obtained keys from conf.aws_credentials_file variable.
conf.get_new_credentials = False

# Enables tests that simulate password brute-force attempt. The value is the number of times simulation is ran.
conf.num_failed_attempts = 0

# Instance ID that will be crated and used to testing
conf.aws_instance_name = "test"

# Test user account and role name created to run tests.
conf.test_account = "tagen-tester"
conf.test_role_name = "tagen-role"

# Test S3 bucket name.
conf.test_bucket_name = "tagen-s3-bucket"

#
# Variables most likely will not be changed
#

# UI download destination variables. Unlikely require any changes, unless tests would be run on Windows.
conf.web_download_dir = "/tmp/webdriver-downloads"
conf.aws_credentials_file = conf.web_download_dir + "/credentials.csv"
# <<<--- TO
"""
    def __init__(self):
        self.web_download_dir = "/tmp/webdriver-downloads"
        self.aws_credentials_file = self.web_download_dir + "credentials.csv"
        self.aws_admin_user = "test1"
        self.aws_admin_pwd = "test1"
        self.aws_account = "test1"
        self.aws_instance_id = "i-22e071ea"
        self.get_new_credentials = True
        self.num_failed_attempts = 0
        self.test_account = "tagen-tester"
        self.test_role_name = "tagen-role"
        self.test_bucket_name = "tagen-s3-bucket"
        self.has_master_key = False
