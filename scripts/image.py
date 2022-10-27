from cProfile import run
import sys
from os.path import exists, sep
import logging
import click


from Crypto.PublicKey import RSA
from Crypto.Signature import pss, pkcs1_15
from Crypto.Hash import SHA256
from Crypto import Random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

IMAGE_MAGIC = "28FEB8C6"
IMAGE_HEADER_SIZE = 40
HASH_SIZE = 32
SIGN_SIZE = 256
E_VALUE = pow(2,16)+1
RSA_SIZE = 2048
KEY_PAIR_NAME = "newKeypair.pem"
SIGN_BIN_FILE = "test_signed"
KEYS_HEADER_NAME = "keys.h"

class Image():
    def __init__(self, pubKey_size = 270, sign_size = SIGN_SIZE,
                header_size=IMAGE_HEADER_SIZE, version=None, endian = 'little',
                erased_val=None, hazmat=True, pss=False):
        self.version = version if version is not None else "0"
        self.header_size = header_size
        self.erased_val = 0xff if erased_val is None else int(erased_val, 0)
        self.pubKey_size = pubKey_size #  certificate is also good
        self.sign_size = sign_size
        self.endian = endian
        self.public_key = None
        self.private_key = None
        self.signature = None
        self.img_payload = []
        self.hazmat = hazmat
        self.pss = pss

    def load(self, path):
        """ Load the signed sample binary file from a given path """
        try:
            with open(path, 'rb') as f:
                self.img_payload = f.read()
        except FileNotFoundError:
            raise click.UsageError("Input file not found")

    def _createKeypair(self, path, passwd=None):
        """Create private method for RSA Key using two external libraries
            pycryptodome or hazmat."""
        if self.hazmat:
            key = rsa.generate_private_key(
                public_exponent=E_VALUE,
                key_size=RSA_SIZE,
                backend=default_backend()
            )
            if passwd is None:
                enc = serialization.NoEncryption()
            else:
                enc = serialization.BestAvailableEncryption(passwd)
            pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=enc)
        else:
            key = RSA.generate(RSA_SIZE)
            pem = key.exportKey()

        with open(path, 'w') as f:
            f.write(pem.decode())

    def getPublicKey(self, path, password=None):
        """ Generate the public key and keypair if it does not exists using two external libraries
            pycryptodome or hazmat."""
        try:
            if not exists(path):
                self._createKeypair(path)

            with open(path, 'rb') as f:
                raw_pem = f.read()
                if self.hazmat:
                    self.private_key = serialization.load_pem_private_key(
                        raw_pem,
                        password=password,
                        backend=default_backend())
                else:
                    self.private_key = RSA.import_key(raw_pem)
        except FileNotFoundError:
            raise click.UsageError("Keypair file not found")

        if self.hazmat:
            self.public_key = self.private_key.public_key()
            logging.debug("public key hazmat = {}". format(self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()))
            logging.debug("public key hazmat digest= {}".format(SHA256.new(self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()))
            logging.debug("public key hazmat PEM = {}".format(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)))
        else:
            self.public_key = self.private_key.publickey().exportKey(format='DER')
            logging.debug("public key = {}".format(self.public_key.hex()))
            logging.debug("public key digest= {}".format(SHA256.new(self.public_key).hexdigest()))
            logging.debug("public key PEM = {}".format(self.private_key.publickey().exportKey()))

    def buildSignedImg(self, kp_path, out_path):
        """ Compute the signature RSA based on PSS or PKCS1v15 """
        try:
            with open(kp_path, 'r') as f:
                keypair = f.read()
        except FileNotFoundError:
            raise click.UsageError("Keypair file not found")
        if self.hazmat:
            key = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            key = self.public_key

        # Refer to include/secureboot.h for the header structure
        self.img_payload = bytes.fromhex(IMAGE_MAGIC) + \
                  int(self.version).to_bytes(4, byteorder = self.endian) + \
                  (IMAGE_HEADER_SIZE - 2).to_bytes(4, byteorder = self.endian) + \
                  (len(self.img_payload)).to_bytes(4, byteorder = self.endian) + \
                  (IMAGE_HEADER_SIZE - 2 + len(self.img_payload)).to_bytes(4, byteorder = self.endian) + \
                  (len(key)).to_bytes(4, byteorder = self.endian) + \
                  (IMAGE_HEADER_SIZE - 2 + len(self.img_payload) + len(key) ).to_bytes(4, byteorder = self.endian) + \
                  (32).to_bytes(4, byteorder = self.endian) + \
                  (IMAGE_HEADER_SIZE - 2 + len(self.img_payload) + 32 + len(key)).to_bytes(4, byteorder = self.endian) + \
                  (SIGN_SIZE).to_bytes(4, byteorder = self.endian) + \
                  self.img_payload

        digest = SHA256.new(self.img_payload + key )
        logging.debug("header + image digest= {}".format(digest.hexdigest()))

        try:
            if self.hazmat:
                if self.pss:
                    self.signature = self.private_key.sign(
                        digest.digest(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=HASH_SIZE
                        ),
                        hashes.SHA256())
                else:
                    self.signature = self.private_key.sign(
                        digest.digest(),
                        padding.PKCS1v15(),
                        hashes.SHA256())
            else:
                if self.pss:
                    signer = pss.new(RSA.importKey(keypair))
                else:
                    signer = pkcs1_15.new(RSA.importKey(keypair))
                self.signature = signer.sign(digest)
            logging.debug("signature = {}".format(self.signature.hex()))
        except TypeError:
            raise click.UsageError("signature process fails")

        with open(out_path, 'wb') as f:
            f.write(self.img_payload + key + digest.digest() + self.signature)

    def verifySignature(self):
        """ Verify the signature RSA based on PSS or PKCS1v15 """
        if self.hazmat:
            key = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            key = self.public_key
        digest = SHA256.new(self.img_payload + key)
        try:
            if self.hazmat:
                if self.pss:
                    self.public_key.verify(
                        self.signature,
                        digest.digest(),
                        padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=HASH_SIZE
                            ),
                        hashes.SHA256()
                    )
                else:
                    self.public_key.verify(
                        self.signature,
                        digest.digest(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
            else:
                if self.pss:
                    verifier = pss.new(RSA.import_key(self.public_key))
                else:
                    verifier = pkcs1_15.new(RSA.import_key(self.public_key))
                verifier.verify(digest, self.signature)
        except (ValueError, TypeError):
            raise click.UsageError("Signature error")

    def exportPublicKey_in_C(self, path, indent="    "):
        """ Generate the C-header with the public key, length and hash used by
            C-code to verify the public key. """
        with open(path, 'w') as f:
            f.write("/* Autogenerated by image.py, do not edit. */\n\n")
            f.write("const unsigned char rsa2048_pub_key[] = {")
            if self.hazmat:
                key = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                key = self.public_key
            for count, b in enumerate(key):
                if count % 8 == 0:
                    f.write("\n" + indent)
                else:
                    f.write(" ")
                coma = "," if count != (len(key) - 1) else "\n"
                f.write("0x{:02x}{}".format(b,coma))
            f.write("}; \n\n")
            f.write("const unsigned int rsa2048_pub_key_len = {};\n\n".format(len(key)))
            f.write("/**\n* @Note: this value needs to be stored in OTP\n**/\n")
            f.write("const unsigned char rsa2048_pub_key_hash[] = {")
            for count, b in enumerate(bytes.fromhex(SHA256.new(key).hexdigest())):
                if count % 8 == 0:
                    f.write("\n" + indent)
                else:
                    f.write(" ")
                coma = "," if count != (HASH_SIZE - 1) else "\n"
                f.write("0x{:02x}{}".format(b, coma))
            f.write("}; \n")

def main():
    logging.basicConfig(level=logging.DEBUG)

    try:
        n = len(sys.argv)
        if n != 4:
            raise ValueError("Expected at 3 arguments")
        else:
            run_path=sys.argv[1] # path to private key
            samples_path=sys.argv[2] # path to sample test image
            version=int(sys.argv[3]) # image version
        #TODO investigate the PSS mode in hazmat and PSS/PKCS1_v15 in pycryptodome
        img = Image(version=version)
        img.load(samples_path)
        pp = sep.join([run_path, KEY_PAIR_NAME])
        img.getPublicKey(sep.join([run_path, KEY_PAIR_NAME]))
        img.exportPublicKey_in_C(sep.join([run_path, KEYS_HEADER_NAME]))
        img.buildSignedImg(sep.join([run_path, KEY_PAIR_NAME]),
                        sep.join([run_path,SIGN_BIN_FILE ]))
        img.verifySignature()
        logging.info("Image Verified Correctly")
    except ValueError:
        logging.error("something went wrong" + ValueError)

if __name__ == "__main__":
    main()
