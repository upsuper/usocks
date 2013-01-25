#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function, unicode_literals

import sys
import yaml
import signal
import socket
import tunnel
import select
import getopt
import logging

from os import path
from itertools import chain

from util import ObjectSet, ObjectDict
from record import RecordLayer
from tunnel import StatusControl

def import_frontend(config):
    fromlist = ['FrontendServer']
    package = 'frontend.' + config['frontend']['type']
    package = __import__(package, fromlist=fromlist)
    FrontendServer = package.FrontendServer
    return lambda: FrontendServer(**config['frontend'])

class TunnelServer(object):

    def __init__(self, config):
        Backend = tunnel.import_backend(config).ServerBackend
        self.backend = Backend(**config['backend'])
        self.new_frontend = import_frontend(config)
        self.key = config['key']
        # initialize connections waiting for sending
        self.unfinished = ObjectSet()
        # record layers dictionary, in which values are dictionaries
        # of the connections belong to it.
        self.record_layers = ObjectDict()
        # dictionary of frontend connections, in which keys are
        # the frontend connections and values are tuples of
        # their corresponding connection ids and record layer one
        # belongs to.
        self.frontends = ObjectDict()

    def run(self):
        self.running = True
        while self.running:
            self._process()
        record_layers = self.record_layers.keys()
        for conn in record_layers:
            self._close_record_layer(conn)
        self.backend.close()

    def _process(self):
        rlist = list(chain(
            (self.backend, ),
            self.record_layers.iterkeys(),
            self.frontends.iterkeys()))
        wlist = list(self.unfinished)
        try:
            r, w, _ = select.select(rlist, wlist, [])
        except select.error as e:
            return
        for conn in r:
            if conn is self.backend:
                self._process_backend()
            elif isinstance(conn, RecordLayer):
                self._process_record_layer(conn)
            else:
                self._process_frontend(conn)
        for conn in w:
            self._process_sending(conn)

    def _process_backend(self):
        inst = self.backend.accept()
        record_layer = RecordLayer(self.key, inst)
        self.record_layers[record_layer] = {}

    def _process_record_layer(self, conn):
        packets = conn.receive_packets()
        if packets is None:
            self._close_record_layer(conn)
        else:
            for packet in packets:
                self._process_packet(conn, packet)

    def _close_record_layer(self, conn):
        for frontend in self.record_layers[conn].values():
            self._close_frontend(frontend)
        del self.record_layers[conn]
        conn.close()

    def _close_frontend(self, frontend):
        frontend.close()
        conn_id, conn = self.frontends[frontend]
        del self.frontends[frontend]
        del self.record_layers[conn][conn_id]

    def _process_packet(self, conn, packet):
        control, conn_id, packet = tunnel.unpack_packet(packet)
        conns = self.record_layers[conn]
        # syn flag is set
        if control & StatusControl.syn:
            if conn_id in conns:
                self._close_frontend(conns[conn_id])
            frontend = self.new_frontend()
            conns[conn_id] = frontend
            self.frontends[frontend] = conn_id, conn
        # ack flag is set
        if control & StatusControl.dat:
            if not conns[conn_id].send(packet):
                self.unfinished.add(conns[conn_id])
        # rst or fin flag is set
        if control & StatusControl.fin:
            self._close_frontend(conns[conn_id])

    def _process_frontend(self, frontend):
        data = frontend.recv()
        control = 0
        if data:
            control = StatusControl.dat
        elif data is None:
            data = b""
            control = StatusControl.fin
        if control:
            conn_id, conn = self.frontends[frontend]
            header = tunnel.pack_header(control, conn_id)
            if not conn.send_packet(header + data):
                self.unfinished.add(conn)
            if control & StatusControl.fin:
                self._close_frontend(frontend)

    def _process_sending(self, conn):
        if isinstance(conn, RecordLayer):
            is_finished = conn.continue_sending()
        else:
            is_finished = conn.send()
        if is_finished:
            self.unfinished.remove(conn)

def usage():
    pass

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hc:vl:",
                ["help", "config=", "verbose", "logfile"])
    except getopt.GetoptError as e:
        print(str(err), file=sys.stderr)
        usage()
        sys.exit(2)

    # parse opts
    config_file = None
    log_file = None
    verbose = False
    for o, a in opts:
        if o in ("-v", "--verbose"):
            verbose = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-c", "--config"):
            config_file = a
        elif o in ("-l", "--logfile"):
            log_file = a
        else:
            assert False, "unhandled option"

    # load config file
    if config_file is None:
        possible_files = [
                path.abspath("./config.yaml"),
                path.expanduser("~/.usocks.yaml"),
                "/etc/usocks.yaml",
                ]
        for f in possible_files:
            if path.exists(f):
                config_file = f
                break
        else:
            print("cannot find config file", file=sys.stderr)
            sys.exit(2)
    config = yaml.load(open(config_file, "r"))
    if 'server' not in config:
        print("cannot find client config", file=sys.stderr)
        sys.exit(1)

    # initialize server
    server = TunnelServer(config['server'])
    # set signal handler
    def handler(signum, frame):
        server.running = False
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    # start server
    server.run()
    
if __name__ == '__main__':
    main()
