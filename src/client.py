#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function, unicode_literals

import sys
import yaml
import errno
import socket
import signal
import tunnel
import select
import getopt
import logging

from os import path
from itertools import chain

from util import ObjectSet, get_select_list
from record import RecordConnection
from tunnel import StatusControl

class Connection(object):

    def __init__(self, conn, conn_id):
        self.conn = conn
        self.conn_id = conn_id
        self.connected = False
        self.closed = False
        self.resetted = False
        # initialize non-blocking sending
        self.conn.setblocking(0)
        self.send_buf = b""

    def send(self, data=None):
        if self.closed or self.resetted:
            return True
        if data:
            self.send_buf += data
        if not self.send_buf:
            return True
        try:
            sent = self.conn.send(self.send_buf)
        except socket.error as e:
            if e.errno == errno.EWOULDBLOCK:
                sent = 0
            else:
                raise
        if sent:
            self.send_buf = self.send_buf[sent:]
        return not self.send_buf

    def get_flist(self):
        if self.closed or self.resetted:
            return []
        return [self.conn.fileno()]

    get_rlist = get_flist
    get_wlist = get_flist

    def __getattr__(self, name):
        return getattr(self.conn, name)

class TunnelClient(object):

    def __init__(self, config):

        # initialize local port
        self.local = socket.socket()
        self.local.bind(("", config['port']))
        self.local.listen(10)
        # initialize backend & record layer
        Backend = tunnel.import_backend(config).ClientBackend
        self.backend = Backend(**config['backend'])
        self.record_layer = RecordConnection(config['key'], self.backend)
        # initialize connection dict
        self.connections = {
                tunnel.max_conn_id + 1: self.record_layer,
                tunnel.max_conn_id + 2: self.local
                }
        # TODO a more memory-efficient allocater
        self.available_conn_id = range(tunnel.max_conn_id, 0, -1)
        # initialize connections waiting for sending
        self.unfinished = ObjectSet()

    def run(self):
        self.running = True
        while self.running:
            self._process()
        for conn in self.connections.values():
            conn.close()
        self.backend.close()

    def _process(self):
        rlist, rdict = get_select_list('get_rlist',
                self.connections.itervalues())
        wlist, wdict = get_select_list('get_wlist', self.unfinished)
        try:
            r, w, _ = select.select(rlist, wlist, [])
        except select.error as e:
            return
        for fileno in r:
            conn = rdict[fileno]
            if conn is self.record_layer:
                self._process_record_layer()
            elif conn is self.local:
                self._process_listening()
            else:
                self._process_connection(conn)
        for fileno in w:
            self._process_sending(wdict[fileno])

    def _process_record_layer(self):
        packets = self.record_layer.receive_packets()
        if packets is None:
            logging.info("remote host has closed connection.")
            self.running = False
        else:
            for packet in packets:
                self._process_packet(packet)

    def _process_packet(self, packet):
        control, conn_id, packet = tunnel.unpack_packet(packet)
        conn = self.connections[conn_id]
        if control & StatusControl.rst:
            self._close_connection(conn_id, True)
            if not conn.resetted:
                self._send_packet(conn_id, StatusControl.rst)
            return
        # server never sends syn flag at present
        # ack flag is set
        if control & StatusControl.dat:
            if not conn.send(packet):
                self.unfinished.add(conn)
        # rst or fin flag is set
        if control & StatusControl.fin:
            self._close_connection(conn_id)
            if not conn.closed:
                self._send_packet(conn_id, StatusControl.fin)

    def _close_connection(self, conn_id, reset=False):
        conn = self.connections[conn_id]
        if reset:
            conn.setsockopt(socket.SOL_SOCKET,
                    socket.SO_LINGER, b"\1\0\0\0\0\0\0\0")
        conn.close()
        self.unfinished.discard(conn)
        del self.connections[conn_id]
        self.available_conn_id.append(conn_id)

    def _process_listening(self):
        conn, address = self.local.accept()
        # alloc connection id
        conn_id = self.available_conn_id.pop()
        # put connection
        conn = Connection(conn, conn_id)
        self.connections[conn_id] = conn

    def _process_connection(self, conn):
        conn_id = conn.conn_id
        control = 0
        try:
            data = conn.recv(4096)
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                if conn.connected:
                    control = StatusControl.rst
                    conn.resetted = True
                else:
                    self._close_connection(conn_id)
                data = b""
            else:
                raise
        if data:
            control = StatusControl.dat
            if not conn.connected:
                conn.connected = True
                control |= StatusControl.syn
        else:
            if conn.connected and not control:
                control = StatusControl.fin
                conn.closed = True
            else:
                self._close_connection(conn_id)
        # send packet
        if control:
            self._send_packet(conn_id, control, data)

    def _send_packet(self, conn_id, control, data=b""):
        header = tunnel.pack_header(control, conn_id)
        conn = self.record_layer
        if not conn.send_packet(header + data):
            self.unfinished.add(conn)

    def _process_sending(self, conn):
        if conn is self.record_layer:
            is_finished = conn.continue_sending()
        else:
            is_finished = conn.send()
        if is_finished:
            self.unfinished.remote(conn)

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
