# coding: UTF-8

"""Layer for integrity and confidentiality of the tunnel.

Record layer provides reliable, ordered delivery of datagrams for
upper layers, and it requires a lower layer (called backend here)
which can guarantee reliablity and ordering.

Security:
    
    At present, record layer uses MD5 to verify the integrity of
    packets, and encrypts data by AES with 128-bit key in CBC mode.

    Since the whole packet, including hash value, is secured by AES,
    it is not necessary to use stronger HMAC algorithms.

Packet Structure:

    There are three parts of packets, which are header, data, and
    padding. The following figure is the packet format:

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                        Message Digest                         +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Data Length          |Padding Length |  Packet Type  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                             Data                              .
    .                                                               .
    |                                                               |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    .                                                               .
    .                            Padding                            .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Message Digest  128-bit MD5 digest of the whole packet excluding
                    the digest itself. 

    Data Length     16-bit unsigned integer in network byte order
                    represents the length of Data field in octets.

    Padding Length  8-bit unsigned integer. Length of Padding in
                    octets. The sum of Data Length and Padding Length
                    must be an integer multiple of the block size of
                    the encryption algorithm, which is 16 octets.
                    There is no other requirement for length and
                    content of Padding.

    Packet Type     8-bit packet type field. See Packet Types.

Packet Types:

    There is five different types of packet, two of them contain data
    while others is only used for notifying or control the connection
    status. The types are:

          1 - data, packet contains the last part of a higher-level
              packet, which can be then provided to the upper.

          2 - part, packet contains data of a higher-level packet,
              but there is more data of the same packet follows. A
              higher-level packet smaller than 65536 octets may only
              be sent in one "data" packet without any "part" packet
              before. Packets other than "data"s and "part"s may be
              inserted into a sequence of "part" and "data" packets.

          3 - nodata, packet has no essential meaning. The only effect
              of this kind of packets is the status of decryptor. The
              packets can be sent to hide the traffic feature and
              confuse the traffic analyser. Data Length must be zero
              for packets of "nodata" type.

        254 - reset, packet is sent when one detects that there is a
              critical error occurred which might be caused by attack.
              Who receives this packet must immediately close the
              backend directly. This packet must not contain any data,
              but it should have padding longer than necessary.

        255 - close, packet is sent when one decides to close the
              connection. If there is no "close" packet received
              before the remote closes the connection, this closing
              action might be insecure.

Handshake Procedure:

    When establishing a record layer connection, each side initializes
    the encryptor and decryptor with the same preshared key and a
    random initial vector. Then they both send a non-urgent encrypted
    random block to synchronize the status of the cipher stream.

Exceptions:

    HashfailError:
        A digest of a packet is wrong. One should send "reset" to its
        counterpart when it detects this error.

    InvalidHeaderError:
        The header is invalid, which means one of the following errors
        is detected:
        * sum of Data Length and Padding Length is not an integer
          multiple of block size,
        * Data Length is not equal to zero for a packet which should
          not have data,
        * Packet Type is not a value listed above.
        One should send "reset" to its counterpart for these errors.

    RemoteResetException:
        A "reset" packet has been received.

    InsecureClosingError:
        The backend connection is closed before any "close" packet is
        received. Implementations should report this error to user.

"""

import struct
import random

from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES

digest_size = MD5.digest_size
block_size = AES.block_size
header_size = digest_size + struct.calcsize("!HBB")

def _hash(data):
    return MD5.new(data).digest()

class PacketType(object):
    data    = 1
    part    = 2
    nodata  = 3
    reset   = 254
    close   = 255

# Exceptions
class CriticalException(Exception): pass
class HashfailError(CriticalException): pass
class InvalidHeaderError(CriticalException): pass
class RemoteResetException(CriticalException): pass
class InsecureClosingError(CriticalException): pass

class RecordConnection(object):

    def __init__(self, key, backend):
        self.backend = backend
        key = MD5.new(key).digest()
        self.random = Random.new()
        # We want to use self-synchronizing feature of CBC, so the IV
        # is trivial in fact, but for security consideration, we
        # should give it a random value.
        iv = self.random.read(block_size)
        self.send_cipher = AES.new(key, AES.MODE_CBC, iv)
        self.recv_cipher = AES.new(key, AES.MODE_CBC, iv)
        # initialize record layer buffers
        self.cipher_buf = b""
        self.plain_buf = b""
        self.recv_synchornized = False
        self.header_arrived = False
        self.secure_closed = False
        # part packet buffer
        self.part_packet = b""
        # The first block must not contain any useful data or it will
        # never be recognized, so we send one block here. However,
        # it is only required to be received before the first data
        # block, so it is not necessary to be sent instantaneously.
        data = self.random.read(block_size)
        data = self.send_cipher.encrypt(data)
        backend.send(data, False)

    def _send_packet(self, data, padding, packet_type):
        data_len = len(data)
        padding_len = len(padding)

        out_data = struct.pack("!HBB", data_len, padding_len, packet_type)
        out_data += data + padding
        out_data = _hash(out_data) + out_data
        # encrypt & send data packet
        out_data = self.send_cipher.encrypt(out_data)
        return self.backend.send(out_data, True)

    def _send_reset(self):
        padding_len = (block_size - header_size) % block_size
        padding = self.random.read(padding_len)
        return self._send_packet(b"", padding, PacketType.reset)

    def _send_close(self):
        padding_len = (block_size - header_size) % block_size
        padding = self.random.read(padding_len)
        return self._send_packet(b"", padding, PacketType.close)

    def send_packet(self, data):
        data_len = len(data)
        while data_len > 65535:    # the max size a packet can contain
            new_len = 65532 # (65532 + header_size) % block_size == 0
            self._send_packet(data[:new_len], b"", PacketType.part)
            data = data[new_len:]
            data_len -= new_len
        padding_len = data_len + header_size
        padding_len = (block_size - padding_len) % block_size
        padding = chr(padding_len) * padding_len
        return self._send_packet(data, padding, PacketType.data)

    def _update_buffer(self):
        length = len(self.cipher_buf)
        if length < block_size:
            return False

        # decrypt received data
        length -= length % block_size
        if length > 0:
            data = self.cipher_buf[:length]
            self.cipher_buf = self.cipher_buf[length:]
            self.plain_buf += self.recv_cipher.decrypt(data)

            # drop first block which is useless
            if not self.recv_synchornized:
                self.plain_buf = self.plain_buf[block_size:]
                self.recv_synchornized = True

        return True

    def _extract_packets(self):
        packets = []

        while True:
            length = len(self.plain_buf)
            if length < header_size:
                break

            # unpack header
            if not self.header_arrived:
                header = self.plain_buf[digest_size:header_size]
                self.data_len, padding_len, self.packet_type = \
                        struct.unpack("!HBB", header)
                self.expected_length = header_size + \
                        self.data_len + padding_len
                self.header_arrived = True
                # check if header is valid
                if self.expected_length % block_size != 0:
                    raise InvalidHeaderError()
                # check packet type
                if self.packet_type == PacketType.data:
                    pass
                elif self.packet_type == PacketType.part:
                    pass
                elif self.data_len != 0:
                    # packet whose type is neither data nor part
                    # must not contain any data
                    raise InvalidHeaderError()
                elif self.packet_type == PacketType.nodata:
                    pass
                elif self.packet_type == PacketType.reset:
                    pass
                elif self.packet_type == PacketType.close:
                    pass
                else:
                    raise InvalidHeaderError()

            # check if the full packet is available
            if length < self.expected_length:
                break

            self.header_arrived = False
            digest = self.plain_buf[:digest_size]
            packet = self.plain_buf[digest_size:self.expected_length]
            data = self.plain_buf[header_size:header_size + self.data_len]
            self.plain_buf = self.plain_buf[self.expected_length:]
            # check hash
            if _hash(packet) != digest:
                raise HashfailError()
            # return packet
            if self.packet_type == PacketType.nodata:
                pass
            elif self.packet_type == PacketType.reset:
                raise RemoteResetException()
            elif self.packet_type == PacketType.close:
                self.secure_closed = True
            elif self.packet_type == PacketType.part:
                self.part_packet += data
            elif self.packet_type == PacketType.data:
                if self.part_packet:
                    data = self.part_packet + data
                    self.part_packet = b""
                packets.append(data)

        return packets

    def receive_packets(self):
        """receive_packets() --> list of packets or None

        It will return any packets available. If backend has been
        closed, this method will return None to notify the upper.
        If the connection seems to be attacked, it will raise 
        different kinds of exceptions.
        """
        data = self.backend.recv()
        if data is None:
            if not self.secure_closed:
                raise InsecureClosingError()
            return None
        self.cipher_buf += data
        if self._update_buffer():
            try:
                packet = self._extract_packets()
            except RemoteResetException:
                raise
            except CriticalException:
                self._send_reset()
                raise
            return packet
        else:
            return []

    def close(self):
        """close() --> None

        This method only sends secure close command to the other peer,
        but will not close the backend. The caller is responsible for
        closing the backend.
        """
        self._send_close()

    def continue_sending(self):
        return self.backend.send()

    def get_rlist(self):
        return self.backend.get_rlist()

    def get_wlist(self):
        return self.backend.get_wlist()
