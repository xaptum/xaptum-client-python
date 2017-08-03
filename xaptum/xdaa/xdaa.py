# Copyright 2017 Xaptum, Inc.
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

import os
import struct

from collections import namedtuple
from xaptum.xdaa import secp256r1
from xaptum.xdaa import x25519
from xaptum.xdaa import util

class XDAAError(Exception):
    pass

class XDAASocketClosedError(XDAAError):
    pass

def negotiate_secret(sock, group):
    """Performs the XDAA handshake on the given socket and returns the negotiated
    shared secret.

    """
    # Initialize parameters
    group = daa_group.from_encoded(group)
    client = client_params.initialize(group)
    server = server_params.initialize(group)

    # ClientHello
    msg = client_hello.build_from_params(client)
    sock.sendall(msg.buffer)

    # ServerKeyExchange
    buf = util.recvexactly(sock, server_key_exchange.header_len)
    if buf == "":
        raise XDAASocketClosedError("Socket closed while reading ServerKeyExchange")
    msg = server_key_exchange.parse_header(buf)

    buf = util.recvexactly(sock, msg.body_len)
    if buf == "":
        raise XDAASocketClosedError("Socket closed while reading ServerKeyExchange")
    msg = msg.parse_body(buf)

    assert(msg.group_id == server.group.id)
    assert(msg.verify_signature(client, server))
    server = msg.add_params_to(server)

    # ClientKeyExchange
    msg = client_key_exchange.build_from_params(client, server)
    sock.sendall(msg.buffer)

    # Compute shared secret
    shared_secret = client.ephemeral.compute_shared(server.ephemeral_public)[::-1]
    
    # Done
    return shared_secret

class daa_group(object):

    @staticmethod
    def from_encoded(encoded):
        (id, public, private) = encoded.split(",")
        public    = secp256r1.public_key_from_encoded_point_hex(public)
        private   = secp256r1.private_key_from_int_hex(private)
        return daa_group(id, public, private)
        
    def __init__(self, id, public, private = None):
        self.id = id
        self.public = public
        self.private = private

class client_params(namedtuple('client_params', ['version',
                                                 'group',
                                                 'nonce',
                                                 'ephemeral'])):
    __slots__ = ()

    @staticmethod
    def initialize(group):
        nonce_len = 32
        return client_params(0,
                             group,
                             os.urandom(nonce_len),
                             x25519.key_pair())


class server_params(namedtuple('server_params', ['version',
                                                 'group',
                                                 'nonce',
                                                 'ephemeral_public'])):
    __slots__ = ()

    @staticmethod
    def initialize(group):
        return server_params(None,
                             group,
                             None,
                             None)


class client_hello(namedtuple('client_hello', ['version',
                                               'group_id_len',
                                               'nonce_len',
                                               'group_id',
                                               'nonce'])):
    __slots__ = ()

    @staticmethod
    def build_from_params(client):
        return client_hello(client.version,
                            len(client.group.id),
                            len(client.nonce),
                            client.group.id,
                            client.nonce)

    @property
    def buffer(self):
        format = '!BHH%ds%ds'%(self.group_id_len,
                               self.nonce_len)
        return struct.pack(format,
                           self.version,
                           self.group_id_len,
                           self.nonce_len,
                           self.group_id.encode('ascii'),
                           self.nonce)

class server_key_exchange(namedtuple('server_key_exchange', ['version',
                                                             'group_id_len',
                                                             'nonce_len',
                                                             'ecdhe_public_key_len',
                                                             'signature_len',
                                                             'group_id',
                                                             'nonce',
                                                             'ecdhe_public_key',
                                                             'signature'])):
    __slots__ = ()

    header_len = 1 + 2 + 2 + 2 + 2

    @property
    def body_len(self):
        return sum([self.group_id_len, self.nonce_len,
                    self.ecdhe_public_key_len, self.signature_len])
    
    @staticmethod
    def parse_header(header):
        format = '!BHHHH'
        (version,
         group_id_len,
         nonce_len,
         ecdhe_public_key_len,
         signature_len) = struct.unpack(format, header)
        return server_key_exchange(version,
                                   group_id_len,
                                   nonce_len,
                                   ecdhe_public_key_len,
                                   signature_len,
                                   None,
                                   None,
                                   None,
                                   None)

    def parse_body(self, body):
        format = '!%ds%ds%ds%ds'%(self.group_id_len,
                                  self.nonce_len,
                                  self.ecdhe_public_key_len,
                                  self.signature_len)
        (group_id,
         nonce,
         ecdhe_public_key,
         signature) = struct.unpack(format, body)
        return self._replace(group_id         = group_id.decode('ascii'),
                             nonce            = nonce,
                             ecdhe_public_key = ecdhe_public_key,
                             signature        = signature)

    def verify_signature(self, client, server):
        key = self.ecdhe_public_key
        sig_format = '!%ds%ds'%(len(key),
                                len(client.nonce))
        sig_buffer = struct.pack(sig_format,
                                 key,
                                 client.nonce)
        return server.group.public.verify_sha256(self.signature, sig_buffer)
    
    def add_params_to(self, server):
        ephemeral = x25519.public_key_from_bytes_be(self.ecdhe_public_key)
        return server._replace(version          = self.version,
                               nonce            = self.nonce,
                               ephemeral_public = ephemeral)
    
    @property
    def buffer(self):
        format = '!BHHHH%ds%ds%ds%ds'%(self.group_id_len,
                                       self.nonce_len,
                                       self.ecdhe_public_key_len,
                                       self.signature_len)
        return struct.pack(format,
                           self.group_id_len,
                           self.nonce_len,
                           self.ecdhe_public_key_len,
                           self.signature_len,
                           self.group_id.encode('ascii'),
                           self.nonce,
                           self.ecdhe_public_key,
                           self.signature)

class client_key_exchange(namedtuple('client_key_exchange', ['version',
                                                             'ecdhe_public_key_len',
                                                             'signature_len',
                                                             'ecdhe_public_key',
                                                             'signature'])):
    __slots__ = ()

    @staticmethod
    def build_from_params(client, server):
        key = client.ephemeral.public.to_bytes_be()
        sig_format = '!%ds%ds'%(len(key),
                                len(server.nonce))
        sig_buffer = struct.pack(sig_format,
                                 key,
                                 server.nonce)
        sig = client.group.private.sign_sha256(sig_buffer)

        return client_key_exchange(client.version,
                                   len(key),
                                   len(sig),
                                   key,
                                   sig)

    @property
    def buffer(self):
        format = '!BHH%ds%ds'%(self.ecdhe_public_key_len,
                               self.signature_len)
        return struct.pack(format,
                           self.version,
                           self.ecdhe_public_key_len,
                           self.signature_len,
                           self.ecdhe_public_key,
                           self.signature)
