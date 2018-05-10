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

import wolfssl

import tempfile
import xtt

__all__ = ['tunnel']

default_protocol = wolfssl.PROTOCOL_TLSv1_2

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

    return tls_sock
