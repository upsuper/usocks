# coding: UTF-8

import errno
import socket

from collections import defaultdict

DEFAULT_PORT = 4194
DEFAULT_BLOCKSIZE = 8192
DEFAULT_NUMBER = 5

class MultiTCPBackend(object):
    
    def __init__(self, number, blocksize):
        self.number = number
        self.blocksize = blocksize
        self.send_bufs = [b"" for i in range(number)]
        self.cur_filling = 0
        self.filled_bytes = 0
        self.cur_recving = 0
        self.remaining_bytes = blocksize

    def send(self, data=None, urgent=True):
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
        if not urgent:
            return True
        return self._continue()

    def _continue(self):
        complete = True
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
            if self.send_bufs[i]:
                complete = False
        return complete

    def recv(self):
        conn = self.conns[self.cur_recving]
        data = conn.recv(self.remaining_bytes)
        if data == b"":
            return None
        self.remaining_bytes -= len(data)
        if self.remaining_bytes == 0:
            self.cur_recving = (self.cur_recving + 1) % self.number
            self.remaining_bytes = self.blocksize
        return data

    def close(self):
        for conn in self.conns:
            conn.setblocking(1)
            # TODO make close non-blocking
            conn.close()

    def get_rlist(self):
        return [self.conns[self.cur_recving].fileno()]

    def get_wlist(self):
        return [self.conns[i].fileno()
                for i in range(self.number) if self.send_bufs[i]]

class ClientBackend(MultiTCPBackend):

    server = "127.0.0.1"
    port = DEFAULT_PORT
    blocksize = DEFAULT_BLOCKSIZE
    number = DEFAULT_NUMBER

    def __init__(self, **opts):
        if 'server' in opts:
            self.server = opts['server']
        if 'port' in opts:
            self.port = opts['port']
        if 'blocksize' in opts:
            self.blocksize = opts['blocksize']
        if 'number' in opts:
            self.number = opts['number']

        super(ClientBackend, self).__init__(self.number, self.blocksize)

        # initialize socket
        self.conns = [socket.socket() for i in range(self.number)]
        for conn in self.conns:
            # TODO make connect non-blocking
            conn.connect((self.server, self.port))
            conn.setblocking(0)

class ServerInstance(MultiTCPBackend):

    def __init__(self, conns, address, blocksize):
        super(ServerInstance, self).__init__(len(conns), blocksize)

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
        return ServerInstance(conns, address, self.blocksize)

    def close(self):
        self.conn.close()

    def get_rlist(self):
        return [self.conn.fileno()]
