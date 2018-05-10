# xaptum-client-python

Python 2.7 and 3.3+ client libraries for connecting to the [Xaptum Edge
Network Fabric](https://www.xaptum.com).

## Installation

```
python setup.py install
```

##  Usage

```python
import xaptum.client
from xaptum.client import (
    GroupParams, RootCertificate, ServerIdentity
)

HOST = '23.147.127.112'
TLS_PORT = 443
XTT_PORT = 4444

SERVER_ID    = ServerIdentity.load("server_id.bin")
ROOT_CERT    = RootCertificate.load("root_cert_id.bin", "root_cert_pubkey.bin")
GROUP_PARAMS = GroupParams.load("group_id.bin", "group_basename.bin",
                                "group_credential.bin", "group_seckey.bin")

TLS_CA_CERT = "/etc/ssl/cacert.pem"

def example():
    (identity, conn) = xaptum.client.connect(HOST, XTT_PORT, GROUP_PARAMS, ROOT_CERT, SERVER_ID,
                                             TLS_PORT, TLS_CA_CERT)
    conn.send("my data")
    conn.close()

if __name__ == "__main__":
    example()
)
```

## TODOs

Currently `xaptum.client.connect(...)` does not perform DDS registration and
the returned socket does not expose methods to read or write payloads in the
DDS format.

## Changelog

+ 0.2.0 (May 9, 2018)
  + switch to XTT for provisioning
+ 0.1.0 (August 2, 2017)
  + initial release

## License
Copyright 2017 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
