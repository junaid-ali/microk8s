#!flask/bin/python
import os
import string
import random
import subprocess

from flask import Flask, jsonify, request, abort


app = Flask(__name__)
CLUSTER_API="cluster/api/v1.0"


@app.route('/{}/join'.format(CLUSTER_API), methods=['GET'])
def join_node():

    token = request.args.get('token')
    hostname = request.args.get('hostname')

    if not is_valid(token):
        abort(404)

    ca = getCA()
    etcd_ep = get_arg('--listen-client-urls', 'etcd')
    api_port = get_arg('--secure-port', 'kube-apiserver')
    proxy_token = get_token('kube-proxy')
    kubelet_token = add_kubelet_token(hostname)
    subprocess.check_call("systemctl restart snap.microk8s.daemon-apiserver.service".split())

    return jsonify(ca=ca,
                   etcd=etcd_ep,
                   kubeproxy=proxy_token,
                   apiport=api_port,
                   kubelet=kubelet_token,)


def get_token(name):
    snapdata_path = os.environ.get('SNAP_DATA')
    file = "{}/credentials/known_tokens.csv".format(snapdata_path)
    with open(file) as fp:
        line = fp.readline()
        if name in line:
            parts = line.split(',')
            return parts[0].rstrip()
    return None


def add_kubelet_token(hostname):
    snapdata_path = os.environ.get('SNAP_DATA')
    file = "{}/credentials/known_tokens.csv".format(snapdata_path)
    alpha = string.ascii_letters + string.digits
    token = ''.join(random.SystemRandom().choice(alpha) for _ in range(32))
    uid = ''.join(random.SystemRandom().choice(string.digits) for _ in range(8))
    with open(file, 'a') as fp:
        # TODO double check this format. Why is userid unique?
        line = "{},system:node:{},kubelet,kubelet-{},\"system:nodes\"".format(token, hostname, uid)
        fp.write(line + os.linesep)
    return token.rstrip()


def getCA():
    # TODO get the CA path properly
    snapdata_path = os.environ.get('SNAP_DATA')
    ca_file = "{}/certs/ca.crt".format(snapdata_path)
    with open(ca_file) as fp:
        ca = fp.read()
    return ca


def get_arg(arg, file):
    print("Get argument {} from {}".format(arg, file))
    snapdata_path = os.environ.get('SNAP_DATA')
    filename = "{}/args/{}".format(snapdata_path, file)
    print("Opening file {}".format(filename))
    with open(filename) as fp:
        for _, line in enumerate(fp):
            print("{} starts with {}".format(line, arg))
            if line.startswith(arg):
                print("Yes")
                args = line.split(' ')
                args = args[-1].split('=')
                return args[-1].rstrip()
    return None


def is_valid(token):
    snapdata_path = os.environ.get('SNAP_DATA')
    cluster_tokens_file = "{}/credentials/cluster-tokens.txt".format(snapdata_path)
    print("File: {}".format(cluster_tokens_file))
    with open(cluster_tokens_file) as fp:
        line = fp.readline()
        print("{} vs {}".format(line, token))
        if token in line:
            return True
    return False


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)

