import xaptum.client
from xaptum.client import (
    GroupParams, RootCertificate, ServerIdentity
)

HOST = 'localhost'
PORT = 4444

SERVER_ID    = ServerIdentity.load("server_id.bin")
ROOT_CERT    = RootCertificate.load("root_cert_id.bin", "root_cert_pubkey.bin")
GROUP_PARAMS = GroupParams.load("group_id.bin", "group_basename.bin",
                                "group_credential.bin", "group_seckey.bin")

def example():
    xaptum.client.connect(HOST, PORT, GROUP_PARAMS, ROOT_CERT, SERVER_ID)

if __name__ == "__main__":
    example()
