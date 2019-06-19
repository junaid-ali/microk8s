#!/usr/bin/python3
import getopt
import requests
import urllib3
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CLUSTER_API = "cluster/api/v1.0"
snapdata_path = os.environ.get('SNAP_DATA')
callback_tokens_file = "{}/credentials/callback-tokens.txt".format(snapdata_path)


def do_op(op_str):
    with open(callback_tokens_file, "r+") as fp:
        for _, line in enumerate(fp):
            parts = line.split()
            host = parts[0]
            token = parts[1]
            res = requests.post("https://{}:5000/{}/configure".format(host, CLUSTER_API),
                                {"callback": token, "configuration": op_str},
                                verify=False)
            if res.status_code != 200:
                print("Failed to do {} on {}".format(op_str, host))


def restart(service):
    restart_str = "{{\"service\": [{{\"name\": \"{}\", \"restart\": \"yes\"}}]}}".format(service)
    do_op(restart_str)


def update_argument(service, key, value):
    op_str = "{{\"service\": [{{\"name\":\"{}\", \"arguments_update\": [{{\"{}\": \"{}\"}}] }}]}}".format(service, key,
                                                                                                          value)
    do_op(op_str)


def remove_argument(service, key):
    op_str = "{{\"service\": [{{\"name\":\"{}\", \"arguments_remove\": [\"{}\"] }}]}}".format(service, key)
    do_op(op_str)


def usage():
    print("usage: dist_refresh_opt [OPERATION] [SERVICE] (ARGUMENT) (value)")
    print("OPERATION is one of restart, update_argument, remove_argument")


def main():
    if not os.path.isfile(callback_tokens_file):
        print("No callback tokens file.")
        return

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            assert False, "unhandled option"

    operation = args[0]
    service = args[1]
    if operation == "restart":
        restart(service)
    if operation == "update_argument":
        update_argument(service, args[2], args[3])
    if operation == "remove_argument":
        remove_argument(service, args[2])


if __name__ == "__main__":
    main()
