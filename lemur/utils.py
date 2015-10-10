"""
.. module: lemur.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from cryptography.fernet import Fernet, MultiFernet

import sqlalchemy.types as types


def get_keys():
    """
    Gets the encryption keys.

    This supports multiple keys to facilitate key rotation. The first
    key in the list is used to encrypt. Decryption is attempted with
    each key in succession.

    :return:
    """

    # TODO should we make this config key plural?
    try:
        key_config = current_app.config.get('LEMUR_ENCRYPTION_KEY')
    except:
        print "no encryption keys"
        return []

    key_config = key_config.strip()

    # this function is expected to return a list of keys, but we want
    # to let people just specify a single key
    if not isinstance(key_config, list):
        key_config = [key_config]

    return key_config


class Vault(types.TypeDecorator):
    """
    A custom SQLAlchemy column type that transparently handles encryption.

    This uses the MultiFernet from the cryptography package to faciliate
    key rotation. That class handles encryption and signing.

    Fernet uses AES in CBC mode with 128-bit keys and PKCS7 padding. It
    uses HMAC-SHA256 for ciphertext authentication. Initialization
    vectors are generated using os.urandom().
    """

    # required by SQLAlchemy. defines the underlying column type
    impl = types.Binary

    def __init__(self):
        """
        Initialize the class with some keys.
        """

        # we assume that the user's keys are already Fernet keys (32 byte
        # keys that have been base64 encoded).
        self.keys = [Fernet(key) for key in get_keys()]

    def process_bind_param(self, value, dialect):
        """
        Encrypt values on the way into the database.

        MultiFernet.encrypt uses the first key in the list.
        """

        # value must be of type bytes or this raises a TypeError
        return MultiFernet(self.keys).encrypt(value)

    def process_result_value(self, value, dialect):
        """
        Decrypt values on the way out of the database.

        MultiFernet tries each key until one works.
        """

        # TODO this may raise an InvalidToken exception in certain
        # cases. Should we handle that?
        # https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet.decrypt
        return MultiFernet(self.keys).decrypt(value)
