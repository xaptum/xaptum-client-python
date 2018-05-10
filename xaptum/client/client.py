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

from xaptum.client import provision, ProvisioningContext
from xaptum.client import tunnel

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
        tls_sock = tunnel(sock, context.certificate_file,
                          context.private_key_file, tls_ca_cert)
        return (identity, tls_sock)
    except Exception as e:
        sock.close()
        raise e
