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
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CLUSTER_API = "cluster/api/v1.0"
snapdata_path = os.environ.get('SNAP_DATA')
ca_cert_file = "{}/certs/ca.remote.crt".format(snapdata_path)
server_cert_file = "{}/certs/server.remote.crt".format(snapdata_path)


def get_connection_info(master_ep, token):
    connection_info = requests.post("https://{}/{}/join".format(master_ep, CLUSTER_API),
                                    {'token': token, "hostname": socket.gethostname()},
                                    verify=False)
    if connection_info.status_code != 200:
        print("Failed to join cluster. {}".format(connection_info.content.decode('utf-8')))
        exit(1)
    return connection_info.content.decode('utf-8')


def usage():
    print("usage: microk8s.join --token=<token> <master:port>")


def set_arg(arg, value, file):
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
    set_arg("--etcd-endpoints", etcd, "flanneld")
    set_arg("--etcd-cafile", ca_cert_file, "flanneld")
    set_arg("--etcd-certfile", server_cert_file, "kube-apiserver")
    set_arg("--etcd-keyfile", "${SNAP_DATA}/certs/server.key", "kube-apiserver")

    subprocess.check_call("systemctl restart snap.microk8s.daemon-flanneld.service".split())


def ca_one_line(ca):
    return base64.b64encode(ca.encode('utf-8')).decode('utf-8')


def create_kubeconfig(token, ca, master_ip, api_port, user):
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
    with open(ca_cert_file, 'w+') as fp:
        fp.write(ca)


def get_etcd_client_cert(token, master_ep):
    cer_req_file = "{}/certs/server.remote.csr".format(snapdata_path)
    cmd_cert = "openssl req -new -key {SNAP_DATA}/certs/server.key -out {csr} " \
               "-config {SNAP_DATA}/certs/csr.conf".format(SNAP_DATA=snapdata_path, csr=cer_req_file)
    subprocess.check_call(cmd_cert.split())
    with open(cer_req_file) as fp:
        csr = fp.read()
        signed = requests.post("https://{}/{}/sign-cert".format(master_ep, CLUSTER_API),
                               {'token': token, 'request': csr},
                               verify=False)
        info_json = signed.content.decode('utf-8')
        info = json.loads(info_json)
        with open(server_cert_file, "w") as cert_fp:
            cert_fp.write(info["certificate"])


def update_kubeapi(token, etcd, master_ip, master_ep):
    etcd = etcd.replace("0.0.0.0", master_ip)
    set_arg("--etcd-servers", etcd, "kube-apiserver")
    set_arg("--etcd-cafile", "${SNAP_DATA}/certs/ca.remote.crt", "kube-apiserver")
    get_etcd_client_cert(token, master_ep)
    set_arg("--etcd-certfile", server_cert_file, "kube-apiserver")
    set_arg("--etcd-keyfile", "${SNAP_DATA}/certs/server.key", "kube-apiserver")
    subprocess.check_call("systemctl restart snap.microk8s.daemon-apiserver.service".split())


def mark_cluster_node():
    lock_file = "{}/var/lock/clustered.lock".format(snapdata_path)
    open(lock_file, 'a').close()
    os.chmod(lock_file, 0o700)
    services = ['etcd', 'apiserver', 'apiserver-kicker', 'controller-manager', 'scheduler']
    for service in services:
        subprocess.check_call("systemctl restart snap.microk8s.daemon-{}.service".format(service).split())


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
    update_kubeapi(token, info["etcd"], master_ip, master_ep)
    update_kubeproxy(info["kubeproxy"], info["ca"], master_ip, info["apiport"])
    update_kubelet(info["kubelet"], info["ca"], master_ip, info["apiport"])
    mark_cluster_node()


if __name__ == "__main__":
    main()
