#!/usr/bin/env python
# Copyright 2018 Canonical, Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""The Python implementation of the gRPC kms-plugin-vault server."""

import argparse
import os
import time
from base64 import b64encode, b64decode
from concurrent import futures
from pathlib import Path

import grpc
import hvac
import yaml

from kms_plugin_vault_pb2 import KeyManagementServicesServicer as BaseServicer
from kms_plugin_vault_pb2 import add_KeyManagementServiceServicer_to_server

from kms_plugin_vault_pb2_grpc import (
    VersionResponse,
    DecryptResponse,
    EncryptResponse,
)


_ONE_DAY_IN_SECONDS = 60 * 60 * 24
CONF_PATH = Path(os.environ.get('SNAP_COMMON', '/etc/kms-plugin-vault'))
DATA_PATH = Path(os.environ.get('SNAP_DATA', '/var/run/kms-plugin-vault'))


class KeyManagementServicesServicer(BaseServicer):
    """Provides methods that implement functionality of kms server."""

    def __init__(self, vault_url, ca_cert, app_role, key_ring):
        self.vault_url = vault_url
        self.ca_cert = ca_cert
        self.app_role = app_role
        self.key_ring = key_ring
        self.client = self._connect_client()

    def _connect_client(self):
        client = hvac.Client(self.vault_url, verify=self.ca_cert)
        client.auth_approle(self.app_role)

    def Version(self, request, context):
        response = VersionResponse()
        return response

    def Decrypt(self, request, context):
        # TODO: handle key versioning and rotation
        ciphertext = 'vault:v1:' + b64encode(request.cipher)
        result = self.client.write('transit/decrypt/' + self.keyring,
                                   ciphertext=ciphertext)
        plain = b64decode(result['plaintext'])
        response = DecryptResponse(plain=plain)
        return response

    def Encrypt(self, request, context):
        plaintext = b64encode(request.plain)
        result = self.client.write('transit/encrypt/' + self.keyring,
                                   plaintext=plaintext)
        # TODO: handle key versioning and rotation
        cipher = b64decode(result['ciphertext'][len('vault:v1:'):])
        response = EncryptResponse(cipher=cipher)
        return response


def serve(opts):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    servicer = KeyManagementServicesServicer(opts.vault_url,
                                             opts.ca_cert,
                                             opts.app_role,
                                             opts.key_ring)
    add_KeyManagementServiceServicer_to_server(servicer, server)
    server.add_insecure_port('unix:' + opts.socket_path)
    server.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == '__main__':
    config_path = CONF_PATH / 'config.yaml'
    ca_cert_path = CONF_PATH / 'ca.crt',
    socket_path = DATA_PATH / 'kms-plugin-vault.socket',
    parser = argparse.ArgumentParser(
        description="gRPC Server for KMS backed by Vault")
    parser.add_argument('--config',
                        type=Path,
                        help='Path to YAML-formatted config file. '
                             'Default: {}'.format(config_path))
    parser.add_argument('--ca-cert',
                        type=Path,
                        help='Path to CA certificate bundle used to verify '
                             'the connection to Vault. Default: {}'.format(
                                 ca_cert_path,
                             ))
    parser.add_argument('--socket-path',
                        type=Path,
                        help='Path to unix-domain socket file to listen on. '
                             'Default: {}'.format(socket_path))
    parser.add_argument('--vault-url',
                        help='URL for Vault.')
    parser.add_argument('--app-role',
                        help='Vault app role ID for authentication. The app '
                             'role\'s policy must allow access to '
                             'transit/{encrypt,decrypt}/{key-ring}')
    parser.add_argument('--key-ring',
                        help='Name of key ring to use for encrypting and '
                             'decrypting.')
    opts = parser.parse_args()

    if opts.config.exists():
        config = yaml.safe_load(opts.config.read_text())
        for key, value in config.items():
            attr = key.replace('-', '_')
            if getattr(opts, attr, None) is None:
                setattr(opts, attr, value)
    missing = set()
    if not opts.vault_url:
        missing.add('vault-url')
    if not opts.app_role:
        missing.add('app-role')
    if not opts.key_ring:
        missing.add('key-ring')
    if missing:
        parser.error('Missing required config: {}'.format(', '.join(missing)))

    serve(opts)
