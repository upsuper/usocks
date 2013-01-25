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

class UnsupportVersionError(Exception):
    pass

header_format = "!BBH"
header_size = struct.calcsize(header_format)
max_conn_id = 65535

def pack_header(control, conn_id):
    return struct.pack(header_format, VERSION_CODE, control, conn_id)

def unpack_packet(packet):
    ver, control, conn_id = struct.unpack(header_format, packet[:header_size])
    if ver != VERSION_CODE:
        raise UnsupportVersionError()
    return control, conn_id, packet[header_size:]

def import_backend(config):
    fromlist = ['ServerBackend', 'ClientBackend']
    package = 'backend.' + config['backend']['type']
    return __import__(package, fromlist=fromlist)

class StatusControl(object):
    syn = 1 # first packet, means connection is started
    dat = 2 # data transmission
    fin = 4 # connection is closed
    rst = 8 # connection is resetted
