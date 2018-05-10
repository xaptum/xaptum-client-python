import xaptum.client
from xaptum.client import (
    GroupParams, RootCertificate, ServerIdentity
)

import os
os.chdir("example")

HOST = '192.168.40.11'
TLS_PORT = 443
XTT_PORT = 4444

SERVER_ID    = ServerIdentity.load("server_id.bin")
ROOT_CERT    = RootCertificate.load("root_cert_id.bin", "root_cert_pubkey.bin")
GROUP_PARAMS = GroupParams.load("group_id.bin", "group_basename.bin",
                                "group_credential.bin", "group_seckey.bin")
TLS_CA_CERT  = "tls_ca_cert.pem"

def example():
    (identity, conn) = xaptum.client.connect(HOST, XTT_PORT, GROUP_PARAMS,
                                             ROOT_CERT, SERVER_ID,
                                             TLS_PORT, TLS_CA_CERT)
    print("Identity:", identity)
    conn.close()

if __name__ == "__main__":
    example()
