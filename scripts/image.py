from cProfile import run
import sys
from os.path import exists, sep
import logging
import click


from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto import Random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

IMAGE_MAGIC = "28FEB8C6"
IMAGE_HEADER_SIZE = 56
HASH_SIZE = 32
RSA_SIGN_SIZE = 256
ECDSA_SIGN_SIZE = 72    # It is the maximum length of the signature with secp256 curve
E_VALUE = pow(2,16)+1
RSA_SIZE = 2048
RSA_KEY_PAIR_NAME = "newRSAKeypair.pem"
ECDSA_KEY_PAIR_NAME = "newECDSAKeypair.pem"
SIGN_BIN_FILE = "test_signed"
KEYS_HEADER_NAME = "keys.h"

class Image():
    def __init__(self, pubKey_size = 270, sign_size = RSA_SIGN_SIZE,
                header_size=IMAGE_HEADER_SIZE, version=None, endian = 'little',
                erased_val=None, hazmat=True, pss=False):
        self.version = version if version is not None else "0"
        self.header_size = header_size
        self.erased_val = 0xff if erased_val is None else int(erased_val, 0)
        self.pubKey_size = pubKey_size #  certificate is also good
        self.sign_size = sign_size
        self.endian = endian
        self.rsa_public_key = None
        self.rsa_private_key = None
        self.rsa_signature = None
        self.ecdsa_public_key = None
        self.ecdsa_private_key = None
        self.ecdsa_signature = None
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

    def _createRSAKeypair(self, path, passwd=None):
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

            with open(path, 'w') as f:
                f.write(pem.decode())
        else:
            key = RSA.generate(RSA_SIZE)
            pem = key.export_key(format='PEM', pkcs=8)

            with open(path, 'wb') as f:
                f.write(pem)

    def _createECDSAKeypair(self, path, passwd=None):
        """Create private method for ECDSA Key using two external libraries
            pycryptodome or hazmat."""
        if self.hazmat:
            key = ec.generate_private_key(ec.SECP256R1())
            if passwd is None:
                enc = serialization.NoEncryption()
            else:
                enc = serialization.BestAvailableEncryption(passwd)
            pem = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=enc)

            with open(path, 'w') as f:
                f.write(pem.decode())
        else:
            key = ECC.generate(curve='P-256')
            pem = key.export_key(format='PEM')

            with open(path, 'w') as f:
                f.write(pem)

    def getRSAPublicKey(self, path, password=None):
        """ Generate the RSA public key and keypair if it does not exists using two external libraries
            pycryptodome or hazmat."""
        try:
            if not exists(path):
                self._createRSAKeypair(path)

            with open(path, 'rb') as f:
                raw_pem = f.read()
                if self.hazmat:
                    self.rsa_private_key = serialization.load_pem_private_key(
                        raw_pem,
                        password=password,
                        backend=default_backend())
                else:
                    self.rsa_private_key = RSA.import_key(raw_pem)
        except FileNotFoundError:
            raise click.UsageError("Keypair file not found")

        if self.hazmat:
            self.rsa_public_key = self.rsa_private_key.public_key()
            logging.debug("public RSA key hazmat = {}". format(self.rsa_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()))
            logging.debug("public RSA key hazmat digest= {}".format(SHA256.new(self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()))
            logging.debug("public RSA key hazmat PEM = {}".format(self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)))
        else:
            self.rsa_public_key = self.rsa_private_key.publickey().export_key(format='DER', pkcs=8)
            logging.debug("public RSA key = {}".format(self.rsa_public_key.hex()))
            logging.debug("public RSA key digest= {}".format(SHA256.new(self.rsa_public_key).hexdigest()))
            logging.debug("public RSA key PEM = {}".format(self.rsa_private_key.publickey().export_key(pkcs=8)))

    def getECDSAPublicKey(self, path, password=None):
        """ Generate the ECDSA public key and keypair if it does not exists using two external libraries
            pycryptodome or hazmat."""
        try:
            if not exists(path):
                self._createECDSAKeypair(path)

            with open(path, 'rb') as f:
                raw_pem = f.read()
                if self.hazmat:
                    self.ecdsa_private_key = serialization.load_pem_private_key(
                        raw_pem,
                        password=password,
                        backend=default_backend())
                else:
                    self.ecdsa_private_key = ECC.import_key(raw_pem)
        except FileNotFoundError:
            raise click.UsageError("Keypair file not found")

        if self.hazmat:
            self.ecdsa_public_key = self.ecdsa_private_key.public_key()
            logging.debug("public ECDSA key hazmat = {}". format(self.ecdsa_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()))
            logging.debug("public ECDSA key hazmat digest= {}".format(SHA256.new(self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()))
            logging.debug("public ECDSA key hazmat PEM = {}".format(self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)))

        else:
            self.ecdsa_public_key = self.ecdsa_private_key.public_key().export_key(format='DER')
            logging.debug("public ECDSA key = {}".format(self.ecdsa_public_key.hex()))
            logging.debug("public ECDSA key digest= {}".format(SHA256.new(self.ecdsa_public_key).hexdigest()))
            logging.debug("public ECDSA key PEM = {}".format(self.ecdsa_private_key.public_key().export_key(format='PEM')))

    def buildSignedImg(self, rsa_kp_path, ecdsa_kp_path, out_path):
        """ Compute the signature RSA based on PSS or PKCS1v15 and ECDSA """
        if self.hazmat:
            rsa_key = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            ecdsa_key = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            rsa_key = self.rsa_public_key
            ecdsa_key = self.ecdsa_public_key

        # Refer to include/secureboot.h for the header structure
        self.img_payload = bytes.fromhex(IMAGE_MAGIC) + \
                  \
                  int(self.version).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1).to_bytes(4, byteorder = self.endian) + \
                  \
                  (len(self.img_payload)).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload)).to_bytes(4, byteorder = self.endian) + \
                  \
                  (len(rsa_key)).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload) + \
                    len(rsa_key) ).to_bytes(4, byteorder = self.endian) + \
                  \
                  (len(ecdsa_key)).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload) + \
                    len(rsa_key) + len(ecdsa_key) ).to_bytes(4, byteorder = self.endian) + \
                  \
                  (32).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload) + 32 + \
                    len(rsa_key) + len(ecdsa_key) ).to_bytes(4, byteorder = self.endian) + \
                  \
                  (RSA_SIGN_SIZE).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload) + 32 + \
                    len(rsa_key) + len(ecdsa_key) + RSA_SIGN_SIZE ).to_bytes(4, byteorder = self.endian) + \
                  \
                  (IMAGE_HEADER_SIZE - 1 + len(self.img_payload) + 32 + \
                    len(rsa_key) + len(ecdsa_key) + RSA_SIGN_SIZE + 4 ).to_bytes(4, byteorder = self.endian) + \
                  \
                  self.img_payload

        digest = SHA256.new(self.img_payload + rsa_key + ecdsa_key )
        logging.debug("header + image digest= {}".format(digest.hexdigest()))

        try:
            if self.hazmat:
                # Sign RSA signature
                if self.pss:
                    self.rsa_signature = self.rsa_private_key.sign(
                        digest.digest(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=HASH_SIZE
                        ),
                        hashes.SHA256())
                else:
                    self.rsa_signature = self.rsa_private_key.sign(
                        digest.digest(),
                        padding.PKCS1v15(),
                        hashes.SHA256())

                # Sign ECDSA signature
                self.ecdsa_signature = self.ecdsa_private_key.sign(
                    digest.digest(),
                    ec.ECDSA(hashes.SHA256()))
            else:
                # Load RSA key file
                try:
                    with open(rsa_kp_path, 'r') as f:
                        rsa_keypair = f.read()
                except FileNotFoundError:
                    raise click.UsageError("RSA Keypair file not found")
                # Load ECDSA key file
                try:
                    with open(ecdsa_kp_path, 'r') as f:
                        ecdsa_keypair = f.read()
                except FileNotFoundError:
                    raise click.UsageError("ECDSA Keypair file not found")

                # Sign RSA signature
                if self.pss:
                    signer = pss.new(RSA.import_key(rsa_keypair))
                else:
                    signer = pkcs1_15.new(RSA.import_key(rsa_keypair))
                self.rsa_signature = signer.sign(digest)

                # Sign ECDSA signature
                signer = DSS.new(ECC.import_key(ecdsa_keypair), 'fips-186-3')
                self.ecdsa_signature = signer.sign(digest)
            logging.debug("RSA signature = {}".format(self.rsa_signature.hex()))
            logging.debug("ECDSA signature = {}".format(self.ecdsa_signature.hex()))
        except TypeError:
            raise click.UsageError("signature process fails")

        with open(out_path, 'wb') as f:
            f.write(self.img_payload + rsa_key + ecdsa_key + digest.digest() + \
                    self.rsa_signature + \
                    (len(self.ecdsa_signature)).to_bytes(4, byteorder = self.endian) + \
                    self.ecdsa_signature)

    def verifySignature(self):
        """ Verify the signature RSA based on PSS or PKCS1v15 and ECDSA"""
        if self.hazmat:
            rsa_key = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            ecdsa_key = self.ecdsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            rsa_key = self.rsa_public_key
            ecdsa_key = self.ecdsa_public_key
        digest = SHA256.new(self.img_payload + rsa_key + ecdsa_key)
        try:
            if self.hazmat:
                # Verify RSA signature
                if self.pss:
                    self.rsa_public_key.verify(
                        self.rsa_signature,
                        digest.digest(),
                        padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=HASH_SIZE
                            ),
                        hashes.SHA256()
                    )
                else:
                    self.rsa_public_key.verify(
                        self.rsa_signature,
                        digest.digest(),
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )

                # Verify ECDSA signature
                self.ecdsa_public_key.verify(
                    self.ecdsa_signature,
                    digest.digest(),
                    ec.ECDSA(hashes.SHA256())),
            else:
                # Verify RSA signature
                if self.pss:
                    verifier = pss.new(RSA.import_key(self.rsa_public_key))
                else:
                    verifier = pkcs1_15.new(RSA.import_key(self.rsa_public_key))
                verifier.verify(digest, self.rsa_signature)

                # Verify ECDSA signature
                verifier = DSS.new(ECC.import_key(self.ecdsa_public_key), 'fips-186-3')
                verifier.verify(digest, self.ecdsa_signature)
        except (ValueError, TypeError):
            raise click.UsageError("Signature error")

    def exportPublicKeys_in_C(self, path, indent="    "):
        """ Generate the C-header with the public key, length and hash used by
            C-code to verify the public key. """
        with open(path, 'w') as f:
            f.write("/* Autogenerated by image.py, do not edit. */\n\n")

            # Export RSA Keys
            f.write("const unsigned char rsa2048_pub_key[] = {")
            if self.hazmat:
                key = self.rsa_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                key = self.rsa_public_key
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
            f.write("}; \n\n")

            # Export ECDSA Keys
            f.write("const unsigned char ecdsa256_pub_key[] = {")
            if self.hazmat:
                key = self.ecdsa_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                key = self.ecdsa_public_key
            for count, b in enumerate(key):
                if count % 8 == 0:
                    f.write("\n" + indent)
                else:
                    f.write(" ")
                coma = "," if count != (len(key) - 1) else "\n"
                f.write("0x{:02x}{}".format(b,coma))
            f.write("}; \n\n")
            f.write("const unsigned int ecdsa256_pub_key_len = {};\n\n".format(len(key)))
            f.write("/**\n* @Note: this value needs to be stored in OTP\n**/\n")
            f.write("const unsigned char ecdsa256_pub_key_hash[] = {")
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
        pp = sep.join([run_path, RSA_KEY_PAIR_NAME])
        img.getRSAPublicKey(sep.join([run_path, RSA_KEY_PAIR_NAME]))
        img.getECDSAPublicKey(sep.join([run_path, ECDSA_KEY_PAIR_NAME]))
        img.exportPublicKeys_in_C(sep.join([run_path, KEYS_HEADER_NAME]))
        img.buildSignedImg(sep.join([run_path, RSA_KEY_PAIR_NAME]),
                        sep.join([run_path, ECDSA_KEY_PAIR_NAME]),
                        sep.join([run_path,SIGN_BIN_FILE ]))
        img.verifySignature()
        logging.info("Image Verified Correctly")
    except ValueError:
        logging.error("something went wrong" + ValueError)

if __name__ == "__main__":
    main()
