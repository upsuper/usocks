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
    |               |S|D|F|         |                               |
    |    Version    |Y|A|I|         |         Connection ID         |
    |               |N|T|N|         |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Version         8-bit version number = 1.

    Control bits    3-bit flags. See Connection Procedure.

    Reserved        5 bits reserved for future use. Must be zero.

    Connection ID   16-bit connection id which is used for identifying
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
    sends a packet with FIN set. Who receives "FIN" packet can close
    its connection without replying anything.

    All packets with data have DAT flag set. Since a packet should
    make sense, no packet should be sent without any of the flag set.

    The three flags are not exclusive, one packet may have any
    combination of the three flags set. If more than one flag is set,
    SYN flag is the first one to be processed, followed by DAT, and
    FIN is the last.

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
