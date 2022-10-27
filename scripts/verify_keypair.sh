#!/bin/sh
RSA_KEY_PAIR_NAME=newRSAKeypair.pem
RSA_KEY_PUB_NAME=newRSAPubkey.pem
ECDSA_KEY_PAIR_NAME=newECDSAKeypair.pem
ECDSA_KEY_PUB_NAME=newECDSAPubkey.pem
SAMPLE_NAME=32_bytes_bin
if [[ $# -ne 1 ]]
then
    echo "Number of paramters are incorrect" >&2
    exit 1
fi
if ! [ -x "$(command -v openssl)" ]; then
    echo "Openssl is not in the path" >&2
    exit 1
fi
IN_FOLDER=$1
BIN_FILE=$IN_FOLDER/$SAMPLE_NAME
RSA_KEYPAIR_FILE=$IN_FOLDER/$RSA_KEY_PAIR_NAME
RSA_PUB_PEM=$IN_FOLDER/$RSA_KEY_PUB_NAME
ECDSA_KEYPAIR_FILE=$IN_FOLDER/$ECDSA_KEY_PAIR_NAME
ECDSA_PUB_PEM=$IN_FOLDER/$ECDSA_KEY_PUB_NAME

echo "Verify RSA signature..."
RESULT=$(openssl rsa -in $RSA_KEYPAIR_FILE -inform pem -pubout -out $RSA_PUB_PEM)
$(head -c32 < /dev/urandom > $BIN_FILE )
$(openssl dgst -sha256 -sigopt rsa_padding_mode:pkcs1 -sign $RSA_KEYPAIR_FILE -out $BIN_FILE.sig $BIN_FILE)
RESULT=$(openssl dgst -sha256 -sigopt rsa_padding_mode:pkcs1 -verify $RSA_PUB_PEM -signature $BIN_FILE.sig $BIN_FILE)
if [[ "$RESULT" != "Verified OK" ]]
then
    echo "Signature verification error" >&2
    exit 1
fi

echo "Verify ECDSA signature..."
RESULT=$(openssl ec -in $ECDSA_KEYPAIR_FILE -inform pem -pubout -out $ECDSA_PUB_PEM)
$(head -c32 < /dev/urandom > $BIN_FILE )
$(openssl dgst -sha256 -sign $ECDSA_KEYPAIR_FILE -out $BIN_FILE.sig $BIN_FILE)
RESULT=$(openssl dgst -sha256 -verify $ECDSA_PUB_PEM -signature $BIN_FILE.sig $BIN_FILE)
if [[ "$RESULT" != "Verified OK" ]]
then
    echo "Signature verification error" >&2
    exit 1
fi
