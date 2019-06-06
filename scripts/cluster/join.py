#!/usr/bin/python3
import base64
import subprocess
import os
import getopt
import sys
import requests
import socket
import json
import shutil


CLUSTER_API="cluster/api/v1.0"


def get_connection_info(master_ep, token):
    connection_info = requests.get("http://{}/{}/join".format(master_ep, CLUSTER_API),
                                   {'token': token, "hostname" : socket.gethostname()})
    assert connection_info.status_code == 200
    return connection_info.content.decode('utf-8')


def usage():
    print("usage: microk8s.join --token=<token> <master:port>")


def set_arg(arg, value, file):
    snapdata_path = os.environ.get('SNAP_DATA')
    filename = "{}/args/{}".format(snapdata_path, file)
    filename_remote = "{}/args/{}.remote".format(snapdata_path, file)
    with open(filename_remote, 'w+') as back_fp:
        with open(filename, 'r+') as fp:
            for _, line in enumerate(fp):
                if line.startswith(arg):
                    if value is not None:
                        back_fp.write("{} {}\n".format(arg, value))
                else:
                    back_fp.write("{}".format(line))
    shutil.copyfile(filename, "{}.backup".format(filename))
    shutil.copyfile(filename_remote, filename)
    os.remove(filename_remote)


def update_flannel(etcd, master_ip):
    etcd = etcd.replace("0.0.0.0", master_ip)
    set_arg("-etcd-endpoints", etcd, "flanneld")
    subprocess.check_call("systemctl restart snap.microk8s.daemon-flanneld.service".split())


def ca_one_line(ca):
    return base64.b64encode(ca.encode('utf-8')).decode('utf-8')


def create_kubeconfig(token, ca, master_ip, api_port, user):
    snapdata_path = os.environ.get('SNAP_DATA')
    snap_path = os.environ.get('SNAP')
    config_template = "{}/{}".format(snap_path, "kubelet.config.template")
    config = "{}/credentials/{}.config".format(snapdata_path, user)
    shutil.copyfile(config, "{}.backup".format(config))
    ca_line = ca_one_line(ca)
    with open(config_template, 'r') as tfp:
        with open(config, 'w+') as fp:
            config_txt = tfp.read()
            config_txt = config_txt.replace("CADATA", ca_line)
            config_txt = config_txt.replace("NAME", user)
            config_txt = config_txt.replace("TOKEN", token)
            config_txt = config_txt.replace("127.0.0.1", master_ip)
            config_txt = config_txt.replace("16443", api_port)
            fp.write(config_txt)


def update_kubeproxy(token, ca, master_ip, api_port):
    create_kubeconfig(token, ca, master_ip, api_port, "kubeproxy")
    set_arg("--master", None, "kube-proxy")
    subprocess.check_call("systemctl restart snap.microk8s.daemon-proxy.service".split())


def update_kubelet(token, ca, master_ip, api_port):
    create_kubeconfig(token, ca, master_ip, api_port, "kubelet")
    set_arg("--client-ca-file", "${SNAP_DATA}/certs/ca.remote.crt", "kubelet")
    subprocess.check_call("systemctl restart snap.microk8s.daemon-kubelet.service".split())


def store_remote_ca(ca):
    snapdata_path = os.environ.get('SNAP_DATA')
    ca_file = "{}/certs/ca.remote.crt".format(snapdata_path)
    with open(ca_file, 'w+') as fp:
        fp.write(ca)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:", ["help", "token="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    token = None
    for o, a in opts:
        if o in ("-t", "--token"):
            token = a
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            assert False, "unhandled option"

    if token is None:
        print("Please provide a token.")
        usage()
        sys.exit()

    if len(args) <= 0:
        print("Please provide a master endpoint.")
        usage()
        sys.exit()

    master_ep = args[0]
    master_ip = master_ep.split(":")[0]
    connection_info_json = get_connection_info(master_ep, token)
    info = json.loads(connection_info_json)
    store_remote_ca(info["ca"])
    update_flannel(info["etcd"], master_ip)
    update_kubeproxy(info["kubeproxy"], info["ca"], master_ip, info["apiport"])
    update_kubelet(info["kubelet"], info["ca"], master_ip, info["apiport"])


if __name__ == "__main__":
    main()
