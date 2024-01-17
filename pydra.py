# Requirements:
# pip install pycryptodome
# pip install cryptography

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES

def b64(msg):
    """
    Helper function to encode in Base64
    """
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf(str, length):
    """
    Use HKDF on an input string to derive a key
    """
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=length,
                salt=b'',
                info=b'',
                backend=default_backend())
    return hkdf.derive(str)

class Bob(object):
    def __init__(self):
        """
        Generating Bob's keys for exchange:
        - IK: long-term identity key
        - SPK: signed pre-key
        - OPK: one-time pre-key
        - EK: ephemeral key
        """
        self.IKb = X25519PrivateKey.generate()
        self.SPKb = X25519PrivateKey.generate()
        self.OPKb = X25519PrivateKey.generate()
    
    def x3dh(self, alice):
        """
        Performing the Extended Triple Diffie-Hellman here
        """
        dh1 = self.SPKb.exchange(alice.IKa.public_key())
        dh2 = self.IKb.exchange(alice.EKa.public_key())
        dh3 = self.SPKb.exchange(alice.EKa.public_key())
        dh4 = self.OPKb.exchange(alice.EKa.public_key())

        # shared key: KDF(dh1 || dh2 || dh3 || dh4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key: ', b64(self.sk))

class Alice(object):
    def __init__(self):
        """
        Generating Alice's keys for exchange:
        - IK: long-term identity key
        - EK: ephemeral key
        """
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()
    
    def x3dh(self, bob):
        """
        Performing the Extended Triple Diffie-Hellman here
        """
        dh1 = self.IKa.exchange(bob.SPKb.public_key())
        dh2 = self.EKa.exchange(bob.IKb.public_key())
        dh3 = self.EKa.exchange(bob.SPKb.public_key())
        dh4 = self.EKa.exchange(bob.OPKb.public_key())

        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key: ', b64(self.sk))

alice = Alice()
bob = Bob()

alice.x3dh(bob)
bob.x3dh(alice)