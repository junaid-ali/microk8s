#!/usr/bin/python3
import getopt
import subprocess

import requests
import urllib3
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CLUSTER_API = "cluster/api/v1.0"
snapdata_path = os.environ.get('SNAP_DATA')
snap_path = os.environ.get('SNAP')
callback_tokens_file = "{}/credentials/callback-tokens.txt".format(snapdata_path)


def do_op(op_str):
    """
    Perform an operation on a remote node
    :param op_str: the operation json string
    """
    with open(callback_tokens_file, "r+") as fp:
        for _, line in enumerate(fp):
            parts = line.split()
            node_ep = parts[0]
            host = node_ep.split(":")[0]
            print("Applying to node {}.".format(host))
            try:
                # Make sure this node exists
                subprocess.check_call("{}/microk8s-kubectl.wrapper get no {}".format(snap_path, host).split(),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                token = parts[1]
                res = requests.post("https://{}/{}/configure".format(node_ep, CLUSTER_API),
                                    {"callback": token, "configuration": op_str},
                                    verify=False)
                if res.status_code != 200:
                    print("Failed to do {} on {}".format(op_str, node_ep))
            except subprocess.CalledProcessError:
                print("Node {} not present".format(host))


def restart(service):
    """
    Restart service on all nodes
    :param service: the service name
    """
    print("Restarting nodes.")
    restart_str = "{{\"service\": [{{\"name\": \"{}\", \"restart\": \"yes\"}}]}}".format(service)
    do_op(restart_str)


def update_argument(service, key, value):
    """
    Configure an argument on all nodes

    :param service: the service we configure
    :param key: the argument we configure
    :param value: the value we set
    """
    print("Adding argument {} to nodes.".format(key))
    op_str = "{{\"service\": [{{\"name\":\"{}\", \"arguments_update\": [{{\"{}\": \"{}\"}}] }}]}}".format(service, key,
                                                                                                          value)
    do_op(op_str)


def remove_argument(service, key):
    """
    Drop an argument from all nodes

    :param service: the service we configure
    :param key: the argument we configure
    """
    print("Removing argument {} from nodes.".format(key))
    op_str = "{{\"service\": [{{\"name\":\"{}\", \"arguments_remove\": [\"{}\"] }}]}}".format(service, key)
    do_op(op_str)


def set_addon(addon, state):
    """
    Enable or disable an add-on across all nodes

    :param addon: the add-on name
    :param state: 'enable' or 'disable'
    """
    print("Set add-on {} to {} on nodes.".format(addon, state))
    op_str = "{{\"addon\": [{{\"name\":\"{}\", \"{}\": \"true\" }}]}}".format(addon, state)
    do_op(op_str)


def usage():
    print("usage: dist_refresh_opt [OPERATION] [SERVICE] (ARGUMENT) (value)")
    print("OPERATION is one of restart, update_argument, remove_argument, set_addon")


if __name__ == "__main__":
    if not os.path.isfile(callback_tokens_file):
        print("No callback tokens file.")
        exit(1)

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
    if operation == "set_addon":
        set_addon(service, args[2])
    exit(0)
