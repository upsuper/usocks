# coding: UTF-8

import errno
import socket

from . import FrontendUnavailableError

class FrontendServer(object):

    server = "localhost"
    port = 80

    def __init__(self, **opts):
        if 'server' in opts:
            self.server = opts['server']
        if 'port' in opts:
            self.port = opts['port']
        
        # initialize socket
        self.conn = socket.socket()
        try:
            self.conn.connect((self.server, self.port))
        except socket.error as e:
            if e.errno == errno.ECONNREFUSED:
                msg = "connection to {0}:{1} is refused" \
                        .format(self.server, self.port)
                raise FrontendUnavailableError(msg)
            raise
        self.conn.setblocking(0)
        self.send_buf = b""

    def send(self, data=None):
        if data:
            self.send_buf += data
        self._continue()

    def _continue(self):
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

    def recv(self):
        data = self.conn.recv(4096)
        if data == b"":
            data = None
        return data

    def close(self):
        self.conn.close()

    def reset(self):
        self.conn.setsockopt(socket.SOL_SOCKET,
                socket.SO_LINGER, b"\1\0\0\0\0\0\0\0")
        self.conn.close()

    def get_rlist(self):
        return [self.conn.fileno()]

    def get_wlist(self):
        if self.send_buf:
            return [self.conn.fileno()]
