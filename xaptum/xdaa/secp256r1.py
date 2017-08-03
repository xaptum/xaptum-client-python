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

import codecs

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def public_key_from_encoded_point(point):
    raw = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256R1(), point).public_key(backends.default_backend())
    return public_key(raw)

def public_key_from_encoded_point_hex(point):
    return public_key_from_encoded_point(codecs.decode(point, 'hex'))

def private_key_from_int(value):
    raw = ec.derive_private_key(value, ec.SECP256R1(), backends.default_backend())
    return private_key(raw)

def private_key_from_int_hex(value):
    return private_key_from_int(int(value, 16))

class public_key(object):

    def __init__(self, public):
        self._public = public

    def _verify(self, signature, message, hash):
        try:
            self._public.verify(signature, message, hash)
            return True
        except InvalidSignature:
            return False

    def verify_sha256(self, signature, message):
        hash = ec.ECDSA(hashes.SHA256())
        return self._verify(signature, message, hash)

class private_key(object):

    def __init__(self, private):
        self._private = private

    def _sign(self, message, hash):
        return self._private.sign(message, hash)

    def sign_sha256(self, message):
        hash = ec.ECDSA(hashes.SHA256())
        return self._sign(message, hash)
