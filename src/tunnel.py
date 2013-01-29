# coding: UTF-8

"""Layer for packing data into one tunnel.

Packet Structure:

    Packet in this layer can be divided into two part, one is header,
    the other is body. Body of a packet is plain data which is
    received from or being sent to the counterpart of an outside
    connection. The following figure illustrate the format of header:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               |S|D|F|R|       |                               |
    |    Version    |Y|A|I|S|       |         Connection ID         |
    |               |N|T|N|T|       |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Version         8-bit version number = 1.

    Control bits    4-bit flags. See Connection Procedure.

    Reserved        4 bits reserved for future use. Must be zero.

    Connection ID   16-bit Connection ID which is used for identifying
                    connections. This id must be unique for each
                    connection in its lifetime, but may be reused
                    after one has been closed.

Connection Procedure:

    When a new connection is established, the client half allocates a
    unused Connection ID to this connection. Then it can send a packet
    with SYN set either immediately or with the first data packet. All
    following packet of this connection must have SYN flag cleared.

    After receiving a packet with SYN flag, server half create a new
    frontend to process this connection, and bind the Connection ID
    with this frontend. If there has been a frontend using the same
    Connection ID (which should be prevented by client half), server
    half should close the old frontend first.

    When either side closes the connection, the corresponding half
    sends a packet with FIN set. The half who did not sent a FIN
    packet must reply it with FIN set as well, and then closes its
    connection. The initial sender can recycle the resources of
    connection only when it receives the reply. In a word, resources
    are released as soon as a packet with FIN is received.

    All packets with data have DAT flag set. Since a packet should
    make sense, no packet should be sent without any of the flag set.

    The three flags mentioned above are not exclusive, one packet may
    have any combination of the three flags set (except none of them).
    If more than one flag is set, SYN flag is the first one to be
    processed, followed by DAT, and FIN is the last.

    If there is a critical error occurs in frontend, or the outside
    connection is resetted, a packet with RST flag alone should be
    sent. Receiving this packet, client should reset the connection,
    or server should reset the frontend, respectively. This flag
    also indicates that the connection is able to be released, and
    the Connection ID is available for allocating again. But like
    FIN flag, receiver must reply a RST packet, and all connection
    resources are released only after a packet with RST is received.

"""

VERSION_CODE = 1

import struct

class UnsupportVersionError(Exception): pass
class NoIDAvailableError(Exception): pass

header_format = "!BBH"
header_size = struct.calcsize(header_format)
max_conn_id = 65535

class StatusControl(object):
    syn = 1 # first packet, means connection is started
    dat = 2 # data transmission
    fin = 4 # connection is closed
    rst = 8 # connection is resetted

class ConnectionStatus(object):
    new         = 0 # connection is created, but SYN has not been sent
    connected   = 1 # connection has established
    closing     = 2 # FIN has been sent, waiting for reply
    resetting   = 3 # RST has been sent, waiting for reply
    closed      = 4 # connection has been closed

class IDAllocator(object):

    def __init__(self, min_id, max_id):
        self.next_id = min_id
        self.max_id = max_id
        self.recycled = set()

    def allocate(self):
        if self.recycled:
            return self.recycled.pop()
        if self.next_id >= self.max_id:
            raise NoIDAvailableError()
        next_id = self.next_id
        self.next_id += 1
        return next_id

    def recycle(self, conn_id):
        self.recycled.add(conn_id)
        while (self.next_id - 1) in self.recycled:
            self.next_id -= 1
            self.recycled.remove(self.next_id)

class TunnelConnection(object):

    def __init__(self, record_conn):
        self.record_conn = record_conn
        self.id_allocator = IDAllocator(1, max_conn_id)
        self.conn_states = {}
        # is tunnel available for writing?
        self.available = True

    def new_connection(self):
        conn_id = self.id_allocator.allocate()
        self.conn_states[conn_id] = ConnectionStatus.new
        return conn_id

    def reset_connection(self, conn_id):
        if self.conn_states[conn_id] == ConnectionStatus.connected:
            self._send_packet(conn_id, StatusControl.rst)
        self.conn_states[conn_id] = ConnectionStatus.resetting

    def close_connection(self, conn_id):
        if self.conn_states[conn_id] == ConnectionStatus.connected:
            self._send_packet(conn_id, StatusControl.fin)
        self.conn_states[conn_id] = ConnectionStatus.closing

    def send_packet(self, conn_id, data):
        if not data:
            return
        control = StatusControl.dat
        if self.conn_states[conn_id] == ConnectionStatus.new:
            control |= StatusControl.syn
            self.conn_states[conn_id] = ConnectionStatus.connected
        self._send_packet(conn_id, control, data)

    def receive_packets(self):
        for packet in self.record_conn.receive_packets():
            packet = self._process_packet(packet)
            if packet:
                yield packet

    def _process_packet(self, packet):
        ver, control, conn_id = \
                struct.unpack(header_format, packet[:header_size])
        if ver != VERSION_CODE:
            raise UnsupportVersionError()
        data = packet[header_size:]

        # RST flag is set
        if control & StatusControl.rst:
            old_state = self.conn_states[conn_id]
            self.reset_connection(conn_id)
            self.conn_states[conn_id] = ConnectionStatus.closed
            self.id_allocator.recycle(conn_id)
            if old_state != ConnectionStatus.connected:
                return None
            return conn_id, StatusControl.rst, b""
        # SYN flag is set
        if control & StatusControl.syn:
            self.conn_states[conn_id] = ConnectionStatus.connected
        # clear DAT flag if status is not connected
        if self.conn_states[conn_id] != ConnectionStatus.connected:
            control &= ~StatusControl.dat
        # if DAT flag is not set, no data should be returned
        if not (control & StatusControl.dat):
            data = b""
        # FIN flag is set
        if control & StatusControl.fin:
            old_state = self.conn_states[conn_id]
            self.close_connection(conn_id)
            self.conn_states[conn_id] = ConnectionStatus.closed
            self.id_allocator.recycle(conn_id)
            if old_state != ConnectionStatus.connected:
                return None
        if not control:
            return None
        return conn_id, control, data

    def _send_packet(self, conn_id, control, data=b""):
        header = struct.pack(header_format, VERSION_CODE, control, conn_id)
        self.record_conn.send_packet(header + data)

    def continue_sending(self):
        self.available = self.record_conn.continue_sending()

    def get_rlist(self):
        return self.record_conn.get_rlist()

    def get_wlist(self):
        return self.record_conn.get_wlist()
