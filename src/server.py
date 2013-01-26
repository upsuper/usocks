#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function, unicode_literals

import sys
import yaml
import errno
import signal
import socket
import tunnel
import select
import getopt
import logging
import traceback

from os import path
from itertools import chain
from functools import partial

import record
import frontend

from util import ObjectSet, ObjectDict, get_select_list
from tunnel import StatusControl

def import_frontend(config):
    fromlist = ['FrontendServer']
    package = 'frontend.' + config['frontend']['type']
    package = __import__(package, fromlist=fromlist)
    FrontendServer = package.FrontendServer
    return lambda: FrontendServer(**config['frontend'])

def log(level, msg, layer, client):
    if client is None:
        client = "-"
    return logging.log(level, msg, extra={'layer': layer, 'client': client})
debug    = partial(log, logging.DEBUG)
info     = partial(log, logging.INFO)
warning  = partial(log, logging.WARNING)
error    = partial(log, logging.ERROR)
critical = partial(log, logging.CRITICAL)

class FakeFrontend(object):
    def close(): pass
    def reset(): pass

class TunnelServer(object):

    def __init__(self, config):
        Backend = tunnel.import_backend(config).ServerBackend
        self.backend = Backend(**config['backend'])
        self.new_frontend = import_frontend(config)
        self.key = config['key']
        # initialize objectsets
        # connections waiting for sending
        self.unfinished = ObjectSet()
        # frontends has been resetted or closed, and waiting to be released
        self.resetted_frontend = ObjectSet()
        self.closed_frontend = ObjectSet()
        # record layers dictionary, in which values are dictionaries
        # of the connections belong to it.
        self.record_conns = ObjectDict()
        # dictionary of frontend connections, in which keys are
        # the frontend connections and values are tuples of
        # their corresponding connection ids and record layer one
        # belongs to.
        self.frontends = ObjectDict()

    def run(self):
        self.running = True
        while self.running:
            try:
                self._process()
            except Exception as e:
                exc_type, _, exc_tb = sys.exc_info()
                exc_type = exc_type.__name__
                exc_tb = traceback.extract_tb(exc_tb)
                msg = "unknown exception occurred: {0}, {1}; {2}"\
                        .format(exc_type, str(e), repr(exc_tb))
                error(msg, 'tunnel', None)
        record_conns = self.record_conns.keys()
        for conn in record_conns:
            self._clean_record_conn(conn)
            conn.close()
            conn.backend.close()
        self.backend.close()

    def _process(self):
        rlist, rdict = get_select_list('get_rlist',
            (self.backend, ),
            self.record_conns.iterkeys(),
            (f for f in self.frontends.iterkeys()
                if f not in self.closed_frontend and
                   f not in self.resetted_frontend))
        wlist, wdict = get_select_list('get_wlist', self.unfinished)
        try:
            r, w, _ = select.select(rlist, wlist, [])
        except select.error as e:
            if e[0] == errno.EINTR:
                return
            else:
                raise
        for fileno in r:
            conn = rdict[fileno]
            if conn is self.backend:
                self._process_backend()
            elif isinstance(conn, record.RecordConnection):
                self._process_record_conn(conn)
            else:
                self._process_frontend(conn)
        for fileno in w:
            self._process_sending(wdict[fileno])

    def _process_backend(self):
        inst = self.backend.accept()
        if not inst:
            return
        record_conn = record.RecordConnection(self.key, inst)
        self.record_conns[record_conn] = {}
        # log connection
        info("connected", 'record', inst.address)

    def _process_record_conn(self, conn):
        try:
            packets = conn.receive_packets()
        except record.CriticalException as e:
            self._clean_record_conn(conn)
            conn.backend.close()

            # logging message
            if isinstance(e, record.HashfailError):
                msg = "detect a wrong hash"
            elif isinstance(e, record.InvalidHeaderError):
                msg = "detect an invalid header"
            elif isinstance(e, record.RemoteResetException):
                msg = "remote host reset the connection"
            elif isinstance(e, record.InsecureClosingError):
                msg = "detect an insecure closing"
            else:
                msg = "detect a critical exception"
            # log the exception
            warning(msg, 'record', conn.backend.address)
            return

        if packets is None:
            self._clean_record_conn(conn)
            conn.close()
            conn.backend.close()
            info("disconnected", 'record', conn.backend.address)
        else:
            for packet in packets:
                self._process_packet(conn, packet)

    def _clean_record_conn(self, conn):
        for front in self.record_conns[conn].values():
            self._close_frontend(front)
        self.unfinished.discard(conn)
        del self.record_conns[conn]

    def _close_frontend(self, front, reset=False):
        if reset:
            front.reset()
        else:
            front.close()
        conn_id, conn = self.frontends[front]
        del self.frontends[front]
        del self.record_conns[conn][conn_id]

    def _process_packet(self, conn, packet):
        control, conn_id, packet = tunnel.unpack_packet(packet)
        conns = self.record_conns[conn]
        # rst flag is set
        if control & StatusControl.rst:
            front = conns[conn_id]
            self._close_frontend(front, True)
            if front in self.resetted_frontend:
                self.resetted_frontend.remove(front)
            else:
                self._send_packet(conn, conn_id, StatusControl.rst)
            return
        # syn flag is set
        if control & StatusControl.syn:
            if conn_id in conns:
                self._close_frontend(conns[conn_id])
            try:
                front = self.new_frontend()
            except frontend.FrontendUnavailableError as e:
                error(e.message, 'frontend', conn.backend.address)
                front = FakeFrontend()
                self.resetted_frontend.add(front)
                self._send_packet(conn, conn_id, StatusControl.rst)
                return
            conns[conn_id] = front
            self.frontends[front] = conn_id, conn
        # ack flag is set
        if control & StatusControl.dat:
            if not conns[conn_id].send(packet):
                self.unfinished.add(conns[conn_id])
        # rst or fin flag is set
        if control & StatusControl.fin:
            front = conns[conn_id]
            self._close_frontend(front)
            if front in self.closed_frontend:
                self.closed_frontend.remove(front)
            else:
                self._send_packet(conn, conn_id, StatusControl.fin)

    def _send_packet(self, conn, conn_id, control, data=b""):
        header = tunnel.pack_header(control, conn_id)
        if not conn.send_packet(header + data):
            self.unfinished.add(conn)

    def _process_frontend(self, front):
        control = 0
        try:
            data = front.recv()
        except Exception as e:
            _, conn = self.frontends[front]
            msg = "unknown error: " + str(e)
            error(msg, 'frontend', conn.backend.address)
            data = b""
            control = StatusControl.rst
        if data:
            control = StatusControl.dat
        elif data is None:
            data = b""
            control = StatusControl.fin
        if control:
            conn_id, conn = self.frontends[front]
            self._send_packet(conn, conn_id, control, data)
            if control & StatusControl.rst:
                self.resetted_frontend.add(front)
            elif control & StatusControl.fin:
                self.closed_frontend.add(front)

    def _process_sending(self, conn):
        if isinstance(conn, record.RecordConnection):
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
                ["help", "config=", "verbose", "logfile="])
    except getopt.GetoptError as e:
        print(str(e), file=sys.stderr)
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

    # initilize logging
    if log_file and log_file != '-':
        log_stream = open(log_file, "a")
    else:
        log_stream = sys.stdout
    logging.basicConfig(
            format="%(asctime)s [%(layer)s] " +
                   "%(levelname)s: %(client)s %(message)s",
            level=logging.INFO if not verbose else logging.DEBUG,
            datefmt="%Y-%m-%d %H:%M:%S",
            stream=log_stream)

    # initialize server
    server = TunnelServer(config['server'])
    # set signal handler
    def stop_handler(signum, frame):
        server.running = False
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)
    # start server
    server.run()
    
if __name__ == '__main__':
    main()
