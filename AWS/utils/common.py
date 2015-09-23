import re
import string

__author__ = 'avolkov'


def extractCredentials(user, file):
    pattern = re.compile("^\""+ user +"\",")
    with open(file) as f:
        content = f.readlines()
        for l in content:
            if pattern.match(l):
                return string.split(l, ',')
    return None


