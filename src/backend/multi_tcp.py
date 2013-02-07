# coding: UTF-8

import errno
import socket

from collections import defaultdict

DEFAULT_PORT = 4194
DEFAULT_BLOCKSIZE = 8192
DEFAULT_NUMBER = 5
BUFFER_SIZE = 4096

class MultiTCPBackend(object):
    
    blocksize = DEFAULT_BLOCKSIZE
    number = DEFAULT_NUMBER

    def __init__(self, **opts):
        if 'blocksize' in opts:
            self.blocksize = opts['blocksize']
        if 'number' in opts:
            self.number = opts['number']

        self.send_bufs = [b"" for i in range(self.number)]
        self.cur_filling = 0
        self.filled_bytes = 0
        self.cur_recving = 0
        self.remaining_bytes = self.blocksize
        self.is_urgent = True

    def send(self, data=None, urgent=True):
        if not data:
            return self._continue()
        if urgent and data:
            self.is_urgent = True
        elif not urgent:
            buf_len = sum(len(buf) for buf in self.send_bufs)
            if buf_len == 0:
                self.is_urgent = False
        while data:
            left_bytes = self.blocksize - self.filled_bytes
            if len(data) >= left_bytes:
                self.send_bufs[self.cur_filling] += data[:left_bytes]
                self.cur_filling = (self.cur_filling + 1) % self.number
                self.filled_bytes = 0
                data = data[left_bytes:]
            else:
                self.send_bufs[self.cur_filling] += data
                self.filled_bytes += len(data)
                break

    def _continue(self):
        available = True
        for i, conn in zip(range(self.number), self.conns):
            if not self.send_bufs[i]:
                continue
            try:
                sent = conn.send(self.send_bufs[i])
            except socket.error as e:
                if e.errno == errno.EWOULDBLOCK:
                    sent = 0
                else:
                    raise
            if sent:
                self.send_bufs[i] = self.send_bufs[i][sent:]
            if len(self.send_bufs[i]) >= BUFFER_SIZE:
                available = False
        return available

    def recv(self):
        data = b""
        while True:
            conn = self.conns[self.cur_recving]
            try:
                packet = conn.recv(self.remaining_bytes)
            except socket.error as e:
                if e.errno == errno.EAGAIN:
                    break
                raise
            if packet == b"":
                break
            self.remaining_bytes -= len(packet)
            data += packet
            if self.remaining_bytes == 0:
                self.cur_recving = (self.cur_recving + 1) % self.number
                self.remaining_bytes = self.blocksize
            else:
                break
        if data == b"":
            data = None
        return data

    def close(self):
        for conn in self.conns:
            conn.setblocking(1)
            # TODO make close non-blocking
            conn.close()

    def get_rlist(self):
        return [self.conns[self.cur_recving].fileno()]

    def get_wlist(self):
        if not self.is_urgent:
            return []
        return [self.conns[i].fileno()
                for i in range(self.number) if self.send_bufs[i]]

class ClientBackend(MultiTCPBackend):

    server = "127.0.0.1"
    port = DEFAULT_PORT

    def __init__(self, **opts):
        super(ClientBackend, self).__init__(**opts)

        if 'server' in opts:
            self.server = opts['server']
        if 'port' in opts:
            self.port = opts['port']

        # initialize socket
        self.conns = [socket.socket() for i in range(self.number)]
        for conn in self.conns:
            # TODO make connect non-blocking
            conn.connect((self.server, self.port))
            conn.setblocking(0)

class ServerInstance(MultiTCPBackend):

    def __init__(self, conns, address, **opts):
        super(ServerInstance, self).__init__(**opts)

        self.conns = conns
        self.address = address
        for conn in conns:
            conn.setblocking(0)

class ServerBackend(object):

    address = ""
    port = DEFAULT_PORT
    blocksize = DEFAULT_BLOCKSIZE
    number = DEFAULT_NUMBER

    def __init__(self, **opts):
        self.opts = opts
        if 'address' in opts:
            self.address = opts['address']
        if 'port' in opts:
            self.port = opts['port']
        if 'blocksize' in opts:
            self.blocksize = opts['blocksize']
        if 'number' in opts:
            self.number = opts['number']

        # initialize waiting list
        self.connections = defaultdict(list)
        # initialize socket
        self.conn = socket.socket()
        self.conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.conn.bind((self.address, self.port))
        self.conn.listen(10)

    def accept(self):
        conn, address = self.conn.accept()
        address = address[0]
        # collect connections
        # TODO should expire after a while
        self.connections[address].append(conn)
        if len(self.connections[address]) < self.number:
            return None
        # create new instance
        conns = self.connections[address]
        del self.connections[address]
        return ServerInstance(conns, address, **self.opts)

    def close(self):
        self.conn.close()

    def get_rlist(self):
        return [self.conn.fileno()]
