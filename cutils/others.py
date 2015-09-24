import argparse

__author__ = 'avolkov'


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="config.py", dest="conf_location",
                       help="Location of the configuration file")
    parser.add_argument("-s", "--sequence", dest="threat_sequence", action='store_true')

    return parser.parse_args()