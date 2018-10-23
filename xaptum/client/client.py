# Copyright 2017-2018 Xaptum, Inc.
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
import ssl

from xaptum.client import provision, ProvisioningContext

def connect(host, xtt_port, group_params, root_cert, server_id,
            tls_port, tls_ca_cert):
    """Establishes a connection to the Xaptum ENF.

    Raises *socket.error* on underlying socket errors, *ssl.SSLError* on
    underlying SSL socket errors, and *xtt.XTTError* on errors during
    XTT identity provisioning negotiation.

    """
    # Provision Identity
    context = ProvisioningContext()
    context.group_params     = group_params
    context.root_certificate = root_cert
    context.server_id        = server_id

    sock = socket.create_connection((host, xtt_port))
    try:
        identity = provision(sock, context)
    finally:
        sock.close()

    # Establish Tunnel
    sock = socket.create_connection((host, tls_port))
    try:
        tls_sock = ssl.wrap_socket(sock,
                                   keyfile=context.private_key_file,
                                   certfile=context.certificate_file,
                                   ca_certs=tls_ca_cert,
                                   cert_reqs=ssl.CERT_REQUIRED)
        tls_sock.do_handshake()
        return (identity, tls_sock)
    except Exception as e:
        sock.close()
        raise e
