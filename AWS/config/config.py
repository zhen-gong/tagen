

class AwsConfig(object):

    def __init__(self):
        self.aws_credentials_file = "/tmp/webdriver-downloads/credentials.csv"
        self.aws_user = "test1"
        self.aws_pwd = "test1"
        self.aws_account = "test1"
        self.aws_instance = "i-22e071ea"
        self.get_new_credentials = True
        self.num_failed_attempts = 0
        self.test_account = "tagen-tester"
        self.test_role_name = "tagen-role"
        self.test_bucket_name = "tagen-s3-bucket"
