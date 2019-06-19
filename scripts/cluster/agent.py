#!flask/bin/python
import os
import shutil
import string
import random
import subprocess

from flask import Flask, jsonify, request, abort, Response

app = Flask(__name__)
CLUSTER_API="cluster/api/v1.0"
snapdata_path = os.environ.get('SNAP_DATA')
cluster_tokens_file = "{}/credentials/cluster-tokens.txt".format(snapdata_path)
certs_request_tokens_file = "{}/credentials/certs-request-tokens.txt".format(snapdata_path)


@app.route('/{}/join'.format(CLUSTER_API), methods=['POST'])
def join_node():

    token = request.form['token']
    hostname = request.form['hostname']

    if not is_valid(token):
        return Response("Invalid token provided.", mimetype='text/html', status=500)

    add_token_to_certs_request(token)
    remove_token_from_cluster(token)

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


@app.route('/{}/sign-cert'.format(CLUSTER_API), methods=['POST'])
def sign_cert():

    token = request.form['token']
    cert_request = request.form['request']

    if not is_valid(token, certs_request_tokens_file):
        return Response("Invalid token provided.", mimetype='text/html', status=500)

    remove_token_from_file(token, certs_request_tokens_file)
    signed_cert = sign_client_cert(cert_request, token)
    return jsonify(certificate=signed_cert)


def sign_client_cert(cert_request, token):
    req_file = "{}/certs/request.{}.csr".format(snapdata_path, token)
    sign_cmd = "openssl x509 -req -in {csr} -CA {SNAP_DATA}/certs/ca.crt -CAkey" \
               " {SNAP_DATA}/certs/ca.key -CAcreateserial -out {SNAP_DATA}/certs/server.{token}.crt" \
               " -days 100000".format(csr=req_file, SNAP_DATA=snapdata_path, token=token)

    with open(req_file, 'w') as fp:
        fp.write(cert_request)
    subprocess.check_call(sign_cmd.split())
    with open("{SNAP_DATA}/certs/server.{token}.crt".format(SNAP_DATA=snapdata_path, token=token)) as fp:
        cert = fp.read()
    return cert


def add_token_to_certs_request(token):
    with open(certs_request_tokens_file, "a+") as fp:
        fp.write("{}\n".format(token))


def remove_token_from_file(token, file):
    backup_file = "{}.backup".format(file)
    # That is a critical section. We need to protect it.
    # We are safe sor now because flask serves one request at a time.
    with open(backup_file, 'w') as back_fp:
        with open(file, 'r') as fp:
            for _, line in enumerate(fp):
                if line.startswith(token):
                    continue
                back_fp.write("{}".format(line))

    shutil.copyfile(backup_file, file)


def remove_token_from_cluster(token):
    remove_token_from_file(token, cluster_tokens_file)


def get_token(name):
    file = "{}/credentials/known_tokens.csv".format(snapdata_path)
    with open(file) as fp:
        line = fp.readline()
        if name in line:
            parts = line.split(',')
            return parts[0].rstrip()
    return None


def add_kubelet_token(hostname):
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
    ca_file = "{}/certs/ca.crt".format(snapdata_path)
    with open(ca_file) as fp:
        ca = fp.read()
    return ca


def get_arg(arg, file):
    print("Get argument {} from {}".format(arg, file))
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


def is_valid(token, token_type=cluster_tokens_file):
    with open(token_type) as fp:
        for _, line in enumerate(fp):
            if line.startswith(token):
                return True
    return False


if __name__ == '__main__':
    server_cert = "{SNAP_DATA}/certs/server.crt".format(SNAP_DATA=snapdata_path)
    server_key = "{SNAP_DATA}/certs/server.key".format(SNAP_DATA=snapdata_path)
    app.run(host="0.0.0.0", port=5000, ssl_context=(server_cert, server_key))
