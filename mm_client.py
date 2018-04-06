import socket
import ssl
import sys
import os
import argparse
from threading import Thread
from key_converter import encode_key
import requests

def client(host, port, keyfile, certfile):

    with open(keyfile, 'rb') as f:
        b64 = encode_key(f)

    print(str(b64, encoding='utf-8'))
    exit()

    # Created unencrypted socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    # Wrap the socket to encrypt
    wrap = ssl.wrap_socket(sock, keyfile=keyfile, certfile=certfile, ssl_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_REQUIRED)
    wrap.connect((host, port))

    while True:
        msg = input('Enter your message: ')

        wrap.send(msg.encode('utf-8'))

        if msg == 'exit':
            wrap.close()
            break


def server_handle_client(clientsock, address):
    while True:
        out = clientsock.recv(1024)
        print(clientsock.getpeercert())
        print('{0}: {1}'.format(address, str(out, encoding='utf-8')))
        if str(out, encoding='utf-8') == 'exit':
            clientsock.close()
            exit()

def register(kns_host, b64_hash, host, port):
    r = requests.post(kns_host + '/' + b64_hash, data={'method': 'set', 'host': host, 'port': port})
    print(r.text)
    r = requests.get(kns_host + '/' + b64_hash)
    print(r.text)

def server(host, port, keyfile, certfile):

    with open(keyfile, 'rb') as f:
        register('http://127.0.0.1:1234', encode_key(f), host, port)

    exit()

    # Created unencrypted socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    # Wrap the socket to encrypt
    wrap = ssl.wrap_socket(sock, keyfile=keyfile, certfile=certfile, ssl_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_REQUIRED, server_side=True)

    wrap.bind((host, port))

    wrap.listen(5)

    while True:
        (clientsock, address) = wrap.accept()
        handle_thread = Thread(target=server_handle_client, args=(clientsock, address))
        handle_thread.start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', help='address to connect to or listen on')
    parser.add_argument('port', help='port to connect to or listen on', type=int)
    parser.add_argument('keyfile', help='RSA private key to use for connections')
    parser.add_argument('certfile', help='certificate to use for connections')
    parser.add_argument('--server', help='run in server mode', action='store_true')

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print('Keyfile not found')
        exit()

    if not os.path.exists(args.certfile):
        print('Certfile not found')
        exit()

    if args.server:
        server(args.host, args.port, args.keyfile, args.certfile)
    else:
        client(args.host, args.port, args.keyfile, args.certfile)
