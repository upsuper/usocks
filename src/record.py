# coding: UTF-8

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
    nodata  = 2
    reset   = 3
    close   = 4
    MAX     = 5

# Exceptions
class CriticalException(Exception): pass
class HashfailError(CriticalException): pass
class InvalidHeaderError(CriticalException): pass
class RemoteResetException(CriticalException): pass
class InsecureClosingError(CriticalException): pass

class RecordLayer(object):

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
            self._send_packet(data[:new_len], b"", PacketType.data)
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
                if self.packet_type != PacketType.data:
                    if self.data_len != 0:
                        raise InvalidHeaderError()
                elif self.packet_type >= PacketType.MAX:
                    raise InvalidHeaderError()
                elif self.packet_type == 0:
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
            else:
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

    def fileno(self):
        return self.backend.fileno()
