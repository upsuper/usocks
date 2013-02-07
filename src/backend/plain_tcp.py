# coding: UTF-8

import socket
import errno

DEFAULT_PORT = 4194
BUFFER_SIZE = 16384

class PlainTCPBackend(object):
    
    def __init__(self):
        self.send_buf = b""
        self.is_urgent = True

    def send(self, data=None, urgent=True):
        if not data:
            return self._continue()
        if urgent and data:
            self.is_urgent = True
        elif not urgent and not self.send_buf:
            self.is_urgent = False
        self.send_buf += data

    def _continue(self):
        if self.send_buf:
            try:
                sent = self.conn.send(self.send_buf)
            except socket.error as e:
                if e.errno == errno.EWOULDBLOCK:
                    sent = 0
                else:
                    raise
            if sent:
                self.send_buf = self.send_buf[sent:]
        return len(self.send_buf) < BUFFER_SIZE

    def recv(self):
        data = self.conn.recv(4096)
        if data == b"":
            data = None
        return data

    def close(self):
        self.conn.setblocking(1)
        # TODO make close non-blocking
        self.conn.close()

    def get_rlist(self):
        return [self.conn.fileno()]

    def get_wlist(self):
        if self.send_buf and self.is_urgent:
            return [self.conn.fileno()]

class ClientBackend(PlainTCPBackend):

    server = "127.0.0.1"
    port = DEFAULT_PORT

    def __init__(self, **opts):
        super(ClientBackend, self).__init__()
        if 'server' in opts:
            self.server = opts['server']
        if 'port' in opts:
            self.port = opts['port']
        # initialize socket
        self.conn = socket.socket()
        # TODO make connect non-blocking
        self.conn.connect((self.server, self.port))
        self.conn.setblocking(0)

class ServerInstance(PlainTCPBackend):

    def __init__(self, conn, address):
        super(ServerInstance, self).__init__()
        self.conn = conn
        self.address = address
        self.conn.setblocking(0)

class ServerBackend(object):

    address = ""
    port = DEFAULT_PORT

    def __init__(self, **opts):
        if 'address' in opts:
            self.address = opts['address']
        if 'port' in opts:
            self.port = opts['port']

        # initialize socket
        self.conn = socket.socket()
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((self.address, self.port))
        self.conn.listen(10)

    def accept(self):
        conn, address = self.conn.accept()
        return ServerInstance(conn, address[0])

    def close(self):
        self.conn.close()

    def get_rlist(self):
        return [self.conn.fileno()]
