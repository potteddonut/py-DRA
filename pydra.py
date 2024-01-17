# Requirements:
# pip install pycryptodome
# pip install cryptography

# pylint: disable=W0611, W0621, W0622, R0903, C0115, C0103, W0201

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES

# HELPER METHODS
def b64(msg):
    """
    Helper function to encode in Base64
    """
    return base64.encodebytes(msg).decode('utf-8').strip()
def hkdf(input_str, length):
    """
    Use HKDF on an input string to derive a key
    """
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=length,
                salt=b'',
                info=b'',
                backend=default_backend())
    return hkdf.derive(input_str)
def pad(msg):
    """PKCS7 padding to align to a 16-byte boundary"""
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)
def unpad(msg):
    """Remove PKCS7 padding"""
    return msg[:-msg[-1]]

class SymmetricRatchet(object):
    def __init__(self, key):
        self.state = key
    
    def next(self, input=b'') -> tuple[bytes, bytes]:
        """
        turning the ratchet by one -> change state, yield new key and IV
        """
        output = hkdf(self.state + input, 80)
        self.state = output[:32]
        out_key, iv = output[32:64], output[64:]
        return out_key, iv

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

        # initialise Bob's DH ratchet
        self.DHratchet = X25519PrivateKey.generate()
    
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
    
    def init_ratchets(self):
        """
        Initialise Bob's root chain with the shared key obtained below,
        then initialise Send and Receive chains
        """
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
    
    def dh_ratchet(self, alice_publicKey):
        """
        Perform one DH ratchet turn with Alice's public key
        """
        dh_recv = self.DHratchet.exchange(alice_publicKey)
        shared_recv = self.root_ratchet.next(dh_recv)[0]

        # use Alice's public key and our private key to generate new receiving ratchet
        self.recv_ratchet = SymmetricRatchet(shared_recv)
        print('[Bob]\tReceiving ratchet seed: ', b64(shared_recv))

        # generate new keypair and send ratchet with our new public key + message to Alice
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_publicKey)
        shared_send = self.root_ratchet.next(dh_send)[0] # the DH input yields us a new key

        self.send_ratchet = SymmetricRatchet(shared_send)
        print('[Alice]\tSend ratchet seed: ', b64(shared_send))

    def send(self, alice, msg):
        """
        Bob cannot decrypt Alice's message without turning his own DH ratchet once
        (with Alice's public key, send with the msg)
        """
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice: ', b64(cipher))

        # send CT + current DH public key
        alice.recv(cipher, self.DHratchet.public_key())
    
    def recv(self, cipher, alice_publicKey):
        """
        On receive, we turn the DH ratchet once more, decrypt and unpad.
        """
        # receive Alice's new public key
        self.dh_ratchet(alice_publicKey)
        key, iv = self.recv_ratchet.next()

        # decrypt -> unpad to obtain msg
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message: ', msg)

class Alice(object):
    def __init__(self):
        """
        Generating Alice's keys for exchange:
        - IK: long-term identity key
        - EK: ephemeral key
        """
        self.IKa = X25519PrivateKey.generate()
        self.EKa = X25519PrivateKey.generate()

        # Alice's DH ratchet starts off empty
        self.DHratchet = None
    
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
    
    def init_ratchets(self):
        """
        Initialise Alice's root chain with the shared key obtained below,
        then initialise Send and Receive chains
        """
        self.root_ratchet = SymmetricRatchet(self.sk)
        self.send_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmetricRatchet(self.root_ratchet.next()[0])
    
    def dh_ratchet(self, bob_publicKey):
        """
        rotate our DH ratchet once using Bob's public key
        """
        if self.DHratchet is not None:
            # indicate that this is not the first turn: we have a ratchet
            dh_recv = self.DHratchet.exchange(bob_publicKey)
            shared_recv = self.root_ratchet.next(dh_recv)[0]

            # obtain new receiving ratchet w/ Bob's public key and our private key
            self.recv_ratchet = SymmetricRatchet(shared_recv)
            print('[Alice]\tReceiving ratchet seed: ', b64(shared_recv))
        else:
            # generate new keypair + sending ratchet
            # new public key is sent with the message to Bob
            self.DHratchet = X25519PrivateKey.generate()
            dh_send = self.DHratchet.exchange(bob_publicKey)
            shared_send = self.root_ratchet.next(dh_send)[0]

            self.send_ratchet = SymmetricRatchet(shared_send)
            print('[Alice]\tSend ratchet seed: ', b64(shared_send))

    def send(self, bob, msg):
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob: ', b64(cipher))

        # send ciphertext + current DH public key
        bob.recv(cipher, self.DHratchet.public_key())
    
    def recv(self, cipher, bob_publicKey):
        self.dh_ratchet(bob_publicKey)
        key, iv = self.recv_ratchet.next()

        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Alice]\tDecrypted message: ', msg)

alice = Alice()
bob = Bob()

# both Alice and Bob have arrived a common shared secret key generated over X3DH
# these keys are now used to establish session keys with DRA
alice.x3dh(bob)
bob.x3dh(alice)
# initialise their symmatric ratchets
alice.init_ratchets()
bob.init_ratchets()

# 1 send or receive = 1 turn of the ratchets
# print their matching send/recv pairs
# at this point, the session has been established and messages are sent with forward secrecy
print() # line break
print('[Alice]\tSend ratchet: ', list(map(b64, alice.send_ratchet.next())))
print('[Bob]\tReceive ratchet: ', list(map(b64, bob.recv_ratchet.next())))
print('[Alice]\tReceive ratchet: ', list(map(b64, alice.recv_ratchet.next())))
print('[Bob]\tSend ratchet: ', list(map(b64, bob.send_ratchet.next())))

# initialise Alice's sending ratchet with Bob's public key
print() # line break
alice.dh_ratchet(bob.DHratchet.public_key())

# test send/receive encrypt and decrypt
alice.send(bob, b'Hello world!')
bob.send(alice, b'Goodbye world!')
