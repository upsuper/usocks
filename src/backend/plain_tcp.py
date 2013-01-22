# coding: UTF-8

import socket
import errno

DEFAULT_PORT = 4194

class PlainTCPBackend(object):
    
    def __init__(self):
        self.send_buf = b""

    def send(self, data, urgent=True):
        """send(data[, urgent]) --> Bool

        Send data. If urgent is set to False, data may not be sent
        immediately. It depends on backend when a non-urgent data
        will be sent. But anyway, all data will be sent sequentially.
        The return value has the same meaning with continue_send.
        """
        if not urgent:
            self.send_buf += data
            return
        self.send_buf += data
        return self.continue_send()

    def continue_send(self):
        """continue_send() --> Bool

        Continue sending. Return True if all data in sending buffer
        has been sent, False otherwise. Caller should call this method
        until it returns True.
        """
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
        return not self.send_buf

    def recv(self):
        data = self.conn.recv(4096)
        if data == b"":
            data = None
        return data

    def close(self):
        self.conn.close()

    def fileno(self):
        return self.conn.fileno()


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
        self.conn.bind((self.address, self.port))
        self.conn.listen(10)

    def accept(self):
        conn, address = self.conn.accept()
        return ServerInstance(conn, address)

    def close(self):
        self.conn.close()

    def fileno(self):
        return self.conn.fileno()
