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

import tempfile
import xtt

from xaptum.client.pem import pem_encode

__all__ = [
    'provision', 'ProvisioningContext',
    'RootCertificate', 'ServerIdentity', 'GroupParams',
]

default_version    = xtt.Version.ONE
default_suite_spec = xtt.SuiteSpec.XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512

class RootCertificate(object):

    @classmethod
    def load(cls, id_file, public_key_file):
        cert = cls()
        cert.load_id(id_file)
        cert.load_public_key(public_key_file)
        return cert

    def __init__(self):
        super(RootCertificate, self).__init__()

        self.id         = None
        self.public_key = None

    def load_id(self, filename):
        self.id = xtt.CertificateRootId.from_file(filename)

    def load_public_key(self, filename):
        self.public_key = xtt.ED25519PublicKey.from_file(filename)

class ServerIdentity(object):

    @classmethod
    def load(cls, id_file):
        id = cls()
        id.load_id(id_file)
        return id

    def __init__(self):
        super(ServerIdentity, self).__init__()

        self.id = None

    def load_id(self, filename):
        self.id = xtt.Identity.from_file(filename)

class GroupParams(object):

    @classmethod
    def load(cls, gid_file, basename_file, credential_file, secret_key_file):
        params = cls()
        params.load_gid(gid_file)
        params.load_basename(basename_file)
        params.load_credential(credential_file)
        params.load_secret_key(secret_key_file)
        return params

    def __init__(self):
        super(GroupParams, self).__init__()

        self.gid        = None
        self.basename   = None
        self.credential = None
        self.secret_key = None

    def load_gid(self, filename):
        self.gid = xtt.GroupId.from_file(filename)

    def load_basename(self, filename):
        with open(filename, 'rb') as f:
            self.basename = f.read()

    def load_credential(self, filename):
        self.credential = xtt.LRSWCredential.from_file(filename)

    def load_secret_key(self, filename):
        self.secret_key = xtt.LRSWPrivateKey.from_file(filename)

    def to_xtt_group_context(self):
        return xtt.ClientLRSWGroupContext(self.gid, self.secret_key,
                                          self.credential, self.basename)

class ProvisioningContext(object):

    def __init__(self, version=default_version, suite_spec=default_suite_spec):
        super(ProvisioningContext, self).__init__()
        self.version   = version
        self.suite_spec = suite_spec

        self.server_id        = None
        self.group_params     = None
        self.root_certificate = None

        self._cert_file    = None
        self._privkey_file = None

    @property
    def certificate_file(self):
        """
        File in which the client certificate created during the
        provisioning process will be stored.  This certificate is used
        to authenticate the client when establishing the TLS tunnel to
        the ENF.
        """
        if self._cert_file == None:
            self._cert_file = tempfile.NamedTemporaryFile(delete=False).name
        return self._cert_file

    @certificate_file.setter
    def certificate_file(self, file):
        self._cert_file = file

    @property
    def private_key_file(self):
        """
        File in which the client private key created during the
        provisioning process will be stored.  This certificate is used
        to authenticate the client when establishing the TLS tunnel to
        the ENF.
        """
        if self._privkey_file == None:
            self._privkey_file = tempfile.NamedTemporaryFile(delete=False).name
        return self._privkey_file

    @private_key_file.setter
    def private_key_file(self, file):
        self._privkey_file = file

def provision(sock, context):
    """
    Runs an XTT provisioning handshake and returns the provisioned
    identity.

    The client certificate and private key generated during provisioning
    are stored in the files specified in the context.

    :sock: a socket connected to the ENF
    :context ProvisioningContext: the configuration required for provisioning
    """
    xtt_sock = xtt.XTTClientSocket(sock,
                                   context.version, context.suite_spec,
                                   context.group_params.to_xtt_group_context(),
                                   context.server_id.id,
                                   context.root_certificate.id,
                                   context.root_certificate.public_key)

    # Run the hanshake
    xtt_sock.start()
    identity = xtt_sock.identity
    pubkey   = xtt_sock.longterm_public_key
    privkey  = xtt_sock.longterm_private_key

    # Save the certificate and private key
    def write(file, contents):
        with open(file, 'wb') as f:
            f.write(contents)

    cert_der = xtt.x509_from_ed25519_key_pair(pubkey, privkey, identity)
    cert_pem  = pem_encode(cert_der, b"CERTIFICATE")
    write(context.certificate_file, cert_pem)

    # Save the private key
    key_der  = xtt.asn1_from_ed25519_private_key(privkey)
    key_pem  = pem_encode(key_der, b"EDDSA PRIVATE KEY")
    write(context.private_key_file, key_pem)

    return identity
