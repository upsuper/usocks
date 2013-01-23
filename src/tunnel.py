# coding: UTF-8

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
    ack = 2 # data transmission
    rst = 4 # connection is resetted
    fin = 8 # connection is closed
