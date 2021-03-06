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

import base64
import six

def _to_bytes(s, encoding="ascii"):
    if isinstance(s, six.binary_type):
        return s
    else:
        return six.text_type(s).encode(encoding)

def _markers(pem_marker):
    pem_marker = _to_bytes(pem_marker)
    return (b'-----BEGIN ' + pem_marker + b'-----',
            b'-----END '   + pem_marker + b'-----')

def _chunk_string(string, line_length):
    index = 0
    while index < len(string):
        next_index = min(index+line_length, len(string))
        yield string[index:next_index]
        index = next_index

def pem_encode(contents, pem_marker):
        (pem_start, pem_end) = _markers(pem_marker)

        pem_lines = [pem_start]
        encoded_line = base64.standard_b64encode(contents)
        pem_line_length = 64
        encoded_chunks = _chunk_string(encoded_line, pem_line_length)
        pem_lines += list(encoded_chunks)
        pem_lines.append(pem_end)
        pem_lines.append(b'')

        return b'\n'.join(pem_lines)
