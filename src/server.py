#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function, unicode_literals

import sys
import yaml
import errno
import signal
import socket
import select
import getopt
import logging
import traceback

from os import path
from itertools import chain
from functools import partial

import record
import tunnel

from util import get_select_list
from util import ObjectSet, ObjectDict
from util import import_backend, import_frontend
from record import RecordConnection
from tunnel import TunnelConnection, StatusControl
from frontend import FrontendUnavailableError

def log(level, msg, layer, client):
    if client is None:
        client = "-"
    return logging.log(level, msg, extra={'layer': layer, 'client': client})
debug    = partial(log, logging.DEBUG)
info     = partial(log, logging.INFO)
warning  = partial(log, logging.WARNING)
error    = partial(log, logging.ERROR)
critical = partial(log, logging.CRITICAL)

class TunnelServer(object):

    def __init__(self, config):
        Backend = import_backend(config).ServerBackend
        self.backend = Backend(**config['backend'])
        self.new_frontend = import_frontend(config)
        self.key = config['key']
        # tunnels dictionary, in which values are dictionaries of the
        # connections belong to it. Those dictionaries' key is the
        # Connection ID and value is the frontend instance.
        self.tunnels = ObjectDict()
        # dictionary of frontend instances, in which keys are the
        # frontend instances and values are tuples of their
        # corresponding Connection IDs and tunnel one belongs to.
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
        # close connections
        self.backend.close()
        for tunnel in self.tunnels.keys():
            self._close_tunnel(tunnel)
        while True:
            wlist, wdict = get_select_list(
                    'get_wlist', self.tunnels.iterkeys())
            if not wlist:
                break
            _, wlist, _ = select.select([], wlist, [])
            for fileno in wlist:
                conn = wdict[fileno]
                if conn in self.tunnels:
                    self._process_tunnel_sending(conn)

    def _process(self):
        rlist, rdict = get_select_list('get_rlist',
                self.backend, self.tunnels.iterkeys(),
                (frontend for frontend, (conn_id, tunnel)
                    in self.frontends.iteritems()
                    if tunnel.available))
        wlist, wdict = get_select_list('get_wlist',
                self.tunnels.iterkeys(), self.frontends.iterkeys())
        try:
            rlist, wlist, _ = select.select(rlist, wlist, [])
        except select.error as e:
            if e[0] == errno.EINTR:
                return
            raise

        for fileno in rlist:
            conn = rdict[fileno]
            if conn is self.backend:
                self._process_backend()
            elif conn in self.tunnels:
                self._process_tunnel(conn)
            elif conn in self.frontends:
                self._process_frontend(conn)
        written_conns = ObjectSet()
        for fileno in wlist:
            conn = wdict[fileno]
            if conn in written_conns:
                continue
            written_conns.add(conn)
            if conn in self.tunnels:
                self._process_tunnel_sending(conn)
            else:
                conn.send()

    def _process_backend(self):
        inst = self.backend.accept()
        if not inst:
            return
        record_conn = RecordConnection(self.key, inst)
        tunnel = TunnelConnection(record_conn)
        tunnel.address = inst.address
        self.tunnels[tunnel] = {}
        info("connected", 'backend', inst.address)

    def _process_tunnel(self, tunnel):
        try:
            for packet in tunnel.receive_packets():
                self._process_tunnel_packet(tunnel, *packet)
        except record.ConnectionClosedException:
            self._close_tunnel(tunnel)
            info("disconnected", 'record', tunnel.address)
        except record.CriticalException as e:
            self._close_tunnel(tunnel)

            # logging message
            if isinstance(e, record.HashfailError):
                msg = "detect a wrong hash"
            elif isinstance(e, record.InvalidHeaderError):
                msg = "detect an invalid header"
            elif isinstance(e, record.RemoteResetException):
                msg = "remote host reset the connection"
            elif isinstance(e, record.InsecureClosingError):
                msg = "detect an insecure closing"
            elif isinstance(e, record.FirstPacketIncorrectError):
                msg = "first packet is incorrect, protocol incompatible"
            else:
                msg = "detect a critical exception"
            # log the exception
            warning(msg, 'record', tunnel.address)

    def _process_tunnel_packet(self, tunnel, conn_id, control, data):
        frontends = self.tunnels[tunnel]
        # RST flag is set
        if control & StatusControl.rst:
            self._close_frontend(frontends[conn_id], True)
        # SYN flag is set
        if control & StatusControl.syn:
            if conn_id in frontends:
                self._close_frontend(frontends[conn_id], True)
            try:
                frontend = self.new_frontend()
            except FrontendUnavailableError:
                error(e.message, 'frontend', tunnel.address)
                tunnel.reset_connection(conn_id)
                return
            frontends[conn_id] = frontend
            self.frontends[frontend] = conn_id, tunnel
        # DAT flag is set
        if control & StatusControl.dat:
            frontends[conn_id].send(data)
        # FIN flag is set
        if control & StatusControl.fin:
            self._close_frontend(frontends[conn_id])

    def _process_frontend(self, frontend):
        conn_id, tunnel = self.frontends[frontend]
        try:
            data = frontend.recv()
        except Exception as e:
            msg = "unknown error: " + str(e)
            error(msg, 'frontend', tunnel.address)
            tunnel.reset_connection(conn_id)
            self._close_frontend(frontend)
            return
        if data:
            tunnel.send_packet(conn_id, data)
        elif data is None:
            tunnel.close_connection(conn_id)
            self._close_frontend(frontend)

    def _process_tunnel_sending(self, tunnel):
        tunnel.continue_sending()
        if tunnel.record_conn.closed:
            if not tunnel.get_wlist():
                tunnel.record_conn.backend.close()
                del self.tunnels[tunnel]

    def _close_tunnel(self, tunnel):
        for frontend in self.tunnels[tunnel].values():
            self._close_frontend(frontend)
        tunnel.record_conn.close()

    def _close_frontend(self, frontend, reset=False):
        if reset:
            frontend.reset()
        else:
            frontend.close()
        conn_id, tunnel = self.frontends[frontend]
        del self.frontends[frontend]
        del self.tunnels[tunnel][conn_id]

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
