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

import donna25519

def public_key_from_bytes_le(bytes_le):
    raw = donna25519.keys.PublicKey(bytes_le)
    return public_key(raw)
    
def public_key_from_bytes_be(bytes_be):
    bytes_le = bytes_be[::-1]
    return public_key_from_bytes_le(bytes_le)

class public_key(object):
 
    def __init__(self, public):
        self._public = public

    def to_bytes_le(self):
        return self._public.public

    def to_bytes_be(self):
        return self.to_bytes_le()[::-1]
        
class key_pair(object):

    def __init__(self):
        self._private = donna25519.keys.PrivateKey()
        self._public = self._private.get_public()

    @property
    def public(self):
        return public_key(self._public)

    def compute_shared(self, peer_public):
        return self._private.do_exchange(peer_public._public)
