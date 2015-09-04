# tagen
Application Thread Activities Generator

Generates activities for a set of applications

Configuration:
# FROM ->
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
conf.aws_account = "aws_test_instance"

# A name and a password of the user with admin privileges that will be running the set of tests.
conf.aws_admin_user = "admin_user"
conf.aws_admin_pwd = "admin_user_password"

# Should be True for the first time.
# If True, gets new credential(pair of new keys) for admin test account specified in conf.aws_admin_user variable.
# If False, will bypass the test and use already obtained keys from conf.aws_credentials_file variable.
conf.get_new_credentials = True

# Enables tests that simulate password brute-force attempt. The value is the number of times simulation is ran.
conf.num_failed_attempts = 0

# Instance ID that will be crated and used to testing
conf.aws_instance_id = "i-22e071ea"

# Test user account and role name created to run tests.
conf.test_account = "tagen-tester"
conf.test_role_name = "tagen-role"

# Test S3 bucket name.
conf.test_bucket_name = "tagen-s3-bucket"

#
# This section list variables that most likely do not require any changes.
#

# UI download destination variables. Unlikely require any changes, unless tests would be run on Windows.
conf.web_download_dir = "/tmp/webdriver-downloads"
conf.aws_credentials_file = conf.web_download_dir + "/credentials.csv"
# <<<--- TO
