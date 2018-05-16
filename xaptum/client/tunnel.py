# Copyright 2018 Xaptum, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

from __future__ import absolute_import, print_function

import socket
import struct
import tempfile
import wolfssl
import xtt

__all__ = ['tunnel']

default_protocol = wolfssl.PROTOCOL_TLSv1_2

class Tunnel(object):

    def __init__(self, sock, blocking=True):
        """
        The :wolfssl.SSLSocket: class does not work like a Python :socket:
        or :ssl.socket:.  The :Tunnel: class tries to provide the more
        standard interface.

        The underlying socket is available via the :Tunnel.socket: property.
        """
        self._sock     = sock
        self._blocking = blocking

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if not self._sock._closed:
            self.close()

    @property
    def socket(self):
        """
        Return the underlying :wolfssl.SSLSocket:
        """
        return self._sock

    def close(self):
        """
        Close the underlying socket.
        """
        self._sock.close()

    def recv(self, bufsize):
        """
        """
        try:
            return self._sock.read(bufsize)
        except wolfssl.SSLWantReadError:
            if self._blocking:
                raise socket.timeout("The read operation timed out")
            else:
                raise

    def send(self, string):
        try:
            return self._sock.write(string)
        except wolfssl.SSLWantWriteError:
            if self._blocking:
                raise socket.timeout("The write operation timed out")
            else:
                raise

    def setblocking(self, flag):
        """
        Set blocking or non-blocking mode of the socket: if :flag: is
        false, the socket is set to non-blocking, else to blocking
        mode.

        """
        self._blocking = flag
        self._sock.setblocking(flag)

    def settimeout(self, value):
        """
        Set a timeout on blocking socket operations.  The :value: argument
        can be a nonnegative floating point number expressing seconds,
        or :None:.
        """
        if value == None:
            self.setblocking(True)
        elif value == 0.0:
            self.setblocking(False)
        else:
            self.setblocking(True)
            timeval_sec  = int(value * 1000000) / 1000000
            timeval_usec = int(value * 1000000) % 1000000
            timeval = struct.pack('ll', int(timeval_sec), int(timeval_usec))
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeval)

def tunnel(sock, client_cert, client_key, ca_cert, protocol=default_protocol):
    """
    Establishes a TLS connection using the provided client credentials.
    The ca cert is used to verify the server identity.

    :sock: a connected socket
    :client_cert: path to the PEM-encoded client certificate file
    :client_key: path to the PEM-encoded client key file
    :ca_cert: path to the PEM-encoded CA certificate file
    """
    context = wolfssl.SSLContext(protocol)

    # Load client credentials
    context.load_cert_chain(client_cert, client_key)

    # Enable server verification
    context.verify_mode = wolfssl.CERT_REQUIRED
    context.load_verify_locations(ca_cert)

    # Establish tunnel
    tls_sock = context.wrap_socket(sock)
    tls_sock.do_handshake()

    return Tunnel(tls_sock)
