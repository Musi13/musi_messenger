import socket
import ssl
import sys
import os
import argparse
from threading import Thread
import key_utils
import requests
import select
import json
import base64
import time

KNS = 'http://127.0.0.1:1234/{pk_hash}'
keyfile = None
certfile = None

sessions = {} # Dict of public hash to socket

rev_sessions = {}

def connect_to_host_port(host, port):
    '''
    Given a host and port, return an SSLSocket
    '''
    # Created unencrypted socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    # Wrap the socket to encrypt
    wrap = ssl.wrap_socket(sock, keyfile=keyfile, certfile=certfile, ssl_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_NONE)
    wrap.connect((host, port))

    return wrap


def connect_to_peer(pk_hash):
    '''
    Given a pk_hash, add an SSLSocket to the peer to the sessions dict if possible.
    Returns True if added, False otherwise
    '''
    r = requests.get(KNS.format(pk_hash=pk_hash))
    if r.status_code != 200:
        print('Could not get peer address')
        return False
    else:
        #print('Connecting to {0}'.format(pk_hash))
        d = json.loads(r.text)  # JSON with {host: , port: }
        sock = connect_to_host_port(d['host'], int(d['port']))

        # At this point, we have an encrypted connection to the
        # peer, but we don't really have authentication.
        # So now we'll confirm each other's identities

        # First, send each other our public keys (client first)
        with open(keyfile, 'rb') as f:
            client_key = key_utils.get_key(f)

        transfer = key_utils.get_transfer_from_dual_key(client_key)
        #print('Client Key: {0}'.format(transfer))
        sock.send(transfer.encode('utf-8'))
        rec = sock.recv(1024)
        server_key = key_utils.get_pub_key_from_transfer(rec)
        #print('Server Key Hash: {0}'.format(key_utils.get_public_key_hash(server_key)))
        if key_utils.get_public_key_hash(server_key) != pk_hash:
            # Oh no! This person isn't the person we were trying to connect to!
            # Note that passing this is authenticated, only that they presented the
            # key that we're looking for. Still have to prove they have the private key
            sock.close()
            return False

        # Sign the public key we just got, and send that to the server
        # this proves that we have the private key
        sock.send(key_utils.get_signed_transfer(client_key, server_key))

        # Then check that what they sent was our public key signed
        # with the the private key of the guy we're looking for
        # i.e. if this passes we know they have the public and private
        # keys of the person we're looking for
        rec = sock.recv(1024)
        if not key_utils.verify_signed_transfer(rec, server_key, client_key.public_key()):
            print('Server failed verification')
            sock.close()
            return False

        sessions[pk_hash] = sock
        rev_sessions[sock] = pk_hash
        print('Started conversation with {0}.'.format(pk_hash))
        return True


def server_handle_client(sock, address):
    '''
    Handles a client connecting, adds an SSLSocket to the sessions
    dict if the client access who we are
    '''
    with open(keyfile, 'rb') as f:
        server_key = key_utils.get_key(f)

    transfer = key_utils.get_transfer_from_dual_key(server_key)
    #print('Server Key: {0}'.format(transfer))
    rec = sock.recv(1024)
    sock.send(transfer.encode('utf-8'))

    # This is slightly different, here the client
    # claims to be this hash, then has to prove it.
    # The client presumably already knows who we are
    client_key = key_utils.get_pub_key_from_transfer(rec)
    client_hash = key_utils.get_public_key_hash(client_key)

    #print('Client Key Hash: {0}'.format(client_hash))

    # No conditional because we didn't initiate the connection

    rec = sock.recv(1024)
    sock.send(key_utils.get_signed_transfer(server_key, client_key))

    if not key_utils.verify_signed_transfer(rec, client_key, server_key.public_key()):
        print('Client failed verification')
        sock.close()

    sessions[client_hash] = sock
    rev_sessions[sock] = client_hash
    print('{0} started a conversation with you.'.format(client_hash))


def register(pk_hash, host, port):
    r = requests.post(KNS.format(pk_hash=pk_hash), data={'method': 'set', 'host': host, 'port': port})
    #print(r.text)
    #r = requests.get(KNS.format(pk_hash=pk_hash))
    #print(r.text)


def listen_for_connections(host, port):
    """
    Listens for connections and adds them to the sessions dict.
    Run this from a daemon thread
    """

    # Created unencrypted socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(None)

    # Wrap the socket to encrypt
    wrap = ssl.wrap_socket(sock, keyfile=keyfile, certfile=certfile, ssl_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_NONE, server_side=True)

    wrap.bind((host, port))

    wrap.listen(5)

    while True:
        (clientsock, address) = wrap.accept()
        handle_thread = Thread(target=server_handle_client, args=(clientsock, address))
        handle_thread.start()

def read_messages():
    '''
    Loops through sessions and prints any new messages
    Run this in a new thread
    '''
    while True:
        if len(sessions.values()) > 0:
            readable, writable, errored = select.select(sessions.values(), [], [], 10)
            for sock in readable:
                msg = str(sock.recv(1024), encoding='utf-8')
                if len(msg) != 0:
                    print('{0}: {1}'.format(rev_sessions[sock], msg))
                else:
                    sock.close()
                    del sessions[rev_sessions[sock]]
                    del rev_sessions[sock]
        else:
            time.sleep(10)


def print_sessions():
    print(sessions)


def send_message(pk_hash, *msg_split):
    if pk_hash in sessions and len(msg_split) > 0:
        sessions[pk_hash].send(' '.join(msg_split).encode('utf-8'))
        print('Message Sent')


def close_session(pk_hash):
    if pk_hash in sessions:
        sessions[pk_hash].close()
        del rev_sessions[sessions[pk_hash]]
        del sessions[pk_hash]


def shutdown():
    for sock in sessions.values():
        sock.close()
    exit()


command_list = {
    '/connect': connect_to_peer,
    '/sessions': print_sessions,
    '/exit': shutdown,
    '/m': send_message,
    '/c': close_session
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('keyfile', help='RSA private key to use for connections')
    parser.add_argument('certfile', help='certificate to use for connections')
    parser.add_argument('--host', help='address to connect to or listen on', default='127.0.0.1')
    parser.add_argument('--port', help='port to connect to or listen on', type=int, default=8525)
    parser.add_argument('--server', help='run in server mode', action='store_true')

    args = parser.parse_args()

    if not os.path.exists(args.keyfile):
        print('Keyfile not found')
        exit()

    if not os.path.exists(args.certfile):
        print('Certfile not found')
        exit()

    keyfile = args.keyfile
    certfile = args.certfile

    with open(keyfile, 'rb') as f:
        pk_hash = key_utils.encode_key(f)

    listen_thread = Thread(target=listen_for_connections, args=(args.host, args.port), daemon=True)
    listen_thread.start()

    read_thread = Thread(target=read_messages, daemon=True)
    read_thread.start()

    register(pk_hash, args.host, args.port)

    while True:
        line = input('> ')
        if line.startswith('/'):
            sep = line.split()
            if sep[0] in command_list:
                command_list[sep[0]](*sep[1:])
        else:
            pass # TODO: Make this reply to most recent

    '''
    if args.server:
        server(args.host, args.port, args.keyfile, args.certfile)
    else:
        client(args.host, args.port, args.keyfile, args.certfile)
    '''
