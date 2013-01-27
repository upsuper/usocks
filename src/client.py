#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function, unicode_literals

import sys
import yaml
import errno
import socket
import signal
import select
import getopt
import logging

from os import path
from itertools import chain

import record
import tunnel

from util import ObjectSet
from util import import_backend
from util import get_select_list
from record import RecordConnection
from tunnel import StatusControl, TunnelConnection

class Connection(object):

    def __init__(self, conn, conn_id):
        self.conn = conn
        self.conn_id = conn_id
        self.conn.setblocking(0)
        self.send_buf = b""

    def send(self, data=None):
        if data:
            self.send_buf += data
        if not self.send_buf:
            return
        try:
            sent = self.conn.send(self.send_buf)
        except socket.error as e:
            if e.errno == errno.EWOULDBLOCK:
                sent = 0
            else:
                raise
        if sent:
            self.send_buf = self.send_buf[sent:]

    def close(self):
        self.conn.setblocking(1)
        self.conn.close()

    def reset(self):
        self.conn.setsockopt(socket.SOL_SOCKET,
                socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.close()

    def get_rlist(self):
        return [self.fileno()]

    def get_wlist(self):
        if self.send_buf:
            return [self.fileno()]

    def __getattr__(self, name):
        return getattr(self.conn, name)

class TunnelClient(object):

    def __init__(self, config):
        self.local_conn = Connection(socket.socket(), -1)
        # initialize local port
        self.local_conn.bind(("", config['port']))
        self.local_conn.listen(10)
        # initialize backend & record layer
        Backend = import_backend(config).ClientBackend
        self.backend = Backend(**config['backend'])
        self.record_conn = RecordConnection(config['key'], self.backend)
        self.tunnel = TunnelConnection(self.record_conn)
        # initialize connection dict
        self.conns = {}

    def run(self):
        self.running = True
        while self.running:
            self._process()
        # close connections
        self.local_conn.close()
        for conn in self.conns.itervalues():
            conn.close()
        self.record_conn.close()
        self.backend.close()

    def _process(self):
        rlist, rdict = get_select_list('get_rlist', 
                self.tunnel, self.local_conn,
                self.conns.itervalues() if self.tunnel.available else [])
        wlist, wdict = get_select_list('get_wlist',
                self.tunnel, self.conns.itervalues())
        try:
            rlist, wlist, _ = select.select(rlist, wlist, [])
        except select.error as e:
            if e[0] == errno.EINTR:
                return
            raise

        for fileno in rlist:
            conn = rdict[fileno]
            if conn is self.tunnel:
                self._process_tunnel()
            elif conn is self.local_conn:
                self._process_listening()
            else:
                self._process_connection(conn)
        for fileno in wlist:
            self._process_sending(wdict[fileno])

    def _process_tunnel(self):
        try:
            for conn_id, control, data in self.tunnel.receive_packets():
                conn = self.conns[conn_id]
                if control & StatusControl.rst:
                    self._close_connection(conn_id, True)
                if control & StatusControl.dat:
                    conn.send(data)
                if control & StatusControl.fin:
                    self._close_connection(conn_id)
        except record.ConnectionClosedException:
            self.running = False

    def _process_listening(self):
        conn, address = self.local_conn.accept()
        conn_id = self.tunnel.new_connection()
        conn = Connection(conn, conn_id)
        self.conns[conn_id] = conn

    def _process_connection(self, conn):
        conn_id = conn.conn_id
        try:
            data = conn.recv(4096)
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                self.tunnel.reset_connection(conn_id)
                self._close_connection(conn_id)
                return
            raise
        if not data:
            self.tunnel.close_connection(conn_id)
            self._close_connection(conn_id)
        else:
            self.tunnel.send_packet(conn_id, data)

    def _close_connection(self, conn_id, reset=False):
        if reset:
            self.conns[conn_id].reset()
        else:
            self.conns[conn_id].close()
        del self.conns[conn_id]

def usage():
    pass

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:v",
                ["help", "config=", "verbose"])
    except getopt.GetoptError as e:
        print(str(err), file=sys.stderr)
        usage()
        sys.exit(2)

    # parse opts
    config_file = None
    verbose = False
    for o, a in opts:
        if o in ("-v", "--verbose"):
            verbose = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-c", "--config"):
            config_file = a
        else:
            assert False, "unhandled option"

    # load config file
    if config_file is None:
        possible_files = [
                path.abspath("./config.yaml"),
                path.expanduser("~/.usocks.yaml"),
                ]
        for f in possible_files:
            if path.exists(f):
                config_file = f
                break
        else:
            print("cannot find config file", file=sys.stderr)
            sys.exit(2)
    config = yaml.load(open(config_file, "r"))
    if 'client' not in config:
        print("cannot find client config", file=sys.stderr)
        sys.exit(1)

    # initialize client
    client = TunnelClient(config['client'])
    # set signal handler
    def handler(signum, frame):
        client.running = False
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    # start client
    client.run()

if __name__ == '__main__':
    main()
