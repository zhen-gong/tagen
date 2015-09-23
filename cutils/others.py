import argparse

__author__ = 'avolkov'


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--c"
                              "onfig", default="config.py", dest="conf_location",
                       help="Location of the configuration file")
    return parser.parse_args()