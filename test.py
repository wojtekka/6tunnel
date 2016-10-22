#!/usr/bin/env python

import os
import socket
import time
import select

(SUCCESS, COMMAND_FAILED, CONNECT_FAILED, DISCONNECT, ACCEPT_FAILED, DATA_FAILED) = range(6)

def test(expect, client_af, server_af, from_ip, to_ip, args=""):
    # Open and close a socket to get random port available
    client_sock = socket.socket(client_af, socket.SOCK_STREAM, 0)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    client_sock.bind(('', 0))
    client_port = client_sock.getsockname()[1]
    client_sock.close()

    # Open a socket for mock server
    server_sock = socket.socket(server_af, socket.SOCK_STREAM, 0)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_sock.bind(('', 0))
    server_sock.listen(0)
    server_port = server_sock.getsockname()[1]

    if os.system("./6tunnel -1 %s %d %s %d" % (args, client_port, to_ip, server_port)) != 0:
        if expect != COMMAND_FAILED:
            raise Exception("expected % yet command failed" % expect)
        else:
            return

    client_sock = socket.socket(client_af, socket.SOCK_STREAM, 0)

    # Give 6tunnel instance some time to initialize
    connected = False
    for i in range(10):
        try:
            client_sock.connect((from_ip, client_port))
        except socket.error:
            time.sleep(0.1)
        connected = True
        break

    rlist, wlist, xlist = select.select([client_sock], [], [client_sock], 1)

    if rlist:
        try:
            res = client_sock.recv(1)
            if not res:
                raise socket.error
        except socket.error:
            if expect != DISCONNECT:
                raise Exception("expected %d yet disconnected" % expect)
            else:
                return

        raise Exception("unexpected data sent to client")

    if not connected:
        if expect != CONNECT_FAILED:
            raise Exception("expected %d yet connect failed" % expect)
        else:
            return

    rlist, wlist, xlist = select.select([server_sock], [], [], 1)

    if not rlist:
        if expect != ACCEPT_FAILED:
            raise Exception("expected %d yet accept failed" % expect)
        else:
            return

    accept_sock = server_sock.accept()[0]
    accept_sock.send("ABC")

    if client_sock.recv(3) != "ABC":
        if expect != DATA_FAILED:
            raise Exception("expected %d yet data failed" % expect)
        else:
            return

    client_sock.send("DEF")

    if accept_sock.recv(3) != "DEF":
        if expect != DATA_FAILED:
            raise Exception("expected %d yet data failed" % expect)
        else:
            return

    accept_sock.close()
    server_sock.close()
    client_sock.close()

    if expect != SUCCESS:
        raise Exception("expected %d yet succeeded" % expect)

test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-l 127.0.0.1')
test(COMMAND_FAILED, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-l ::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-s ::1')
test(COMMAND_FAILED, socket.AF_INET, socket.AF_INET6, '127.0.0.1', '::1', '-s 127.0.0.1')

test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4')
test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -l 127.0.0.1')
test(COMMAND_FAILED, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -l ::1')
test(SUCCESS, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -s 127.0.0.1')
test(COMMAND_FAILED, socket.AF_INET, socket.AF_INET, '127.0.0.1', '127.0.0.1', '-4 -s ::1')

test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6')
test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -l ::1')
test(COMMAND_FAILED, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -l 127.0.0.1')
test(SUCCESS, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -s 127.0.0.1')
test(COMMAND_FAILED, socket.AF_INET6, socket.AF_INET, '::1', '127.0.0.1', '-4 -6 -s ::1')

test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6')
test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -l ::1')
test(COMMAND_FAILED, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -l 127.0.0.1')
test(SUCCESS, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -s ::1')
test(COMMAND_FAILED, socket.AF_INET6, socket.AF_INET6, '::1', '::1', '-6 -s 127.0.0.1')

