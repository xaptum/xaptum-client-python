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

from __future__ import absolute_import

import socket

def recvexactly(sock, size, flags=0):
    """Receive exactly size bytes from the socket.

    The return value is a bytes object representing the data received. See the
    Unix manual page recv(2) for the meaning of the optional argument *flags*;
    it defaults to zero.

    """

    buffer = bytearray(size)
    view = memoryview(buffer)
    pos = 0
    while pos < size:
        read = sock.recv_into(view[pos:], size - pos, flags)
        if read == 0:
            return bytes(b'')
        pos += read
    return bytes(buffer)
