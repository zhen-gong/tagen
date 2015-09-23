import re
import string

from AWS.config.config import AwsConfig

__author__ = 'avolkov'


def extractCredentials(user, file):
    pattern = re.compile("^\""+ user +"\",")
    with open(file) as f:
        content = f.readlines()
        for l in content:
            if pattern.match(l):
                return string.split(l, ',')
    return None


def loadConfig(location):
    with open(location) as f:
        content = f.readlines()
    conf = AwsConfig()
    for l in content:
        exec l
    return conf