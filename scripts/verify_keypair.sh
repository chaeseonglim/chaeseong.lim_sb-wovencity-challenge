#!/bin/sh
KEY_PAIR_NAME=newKeypair.pem
KEY_PUB_NAME=newPubkey.pem
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
KEYPAIR_FILE=$IN_FOLDER/$KEY_PAIR_NAME
BIN_FILE=$IN_FOLDER/$SAMPLE_NAME
PUB_PEM=$IN_FOLDER/$KEY_PUB_NAME
RESULT=$(openssl rsa -in $KEYPAIR_FILE -inform pem -pubout -out $PUB_PEM)
$(head -c32 < /dev/urandom > $BIN_FILE )
$(openssl dgst -sha256 -sigopt rsa_padding_mode:pkcs1 -sign $KEYPAIR_FILE -out $BIN_FILE.sig $BIN_FILE)
RESULT=$(openssl dgst -sha256 -sigopt rsa_padding_mode:pkcs1 -verify $PUB_PEM -signature $BIN_FILE.sig $BIN_FILE)
if [[ "$RESULT" != "Verified OK" ]]
then 
    echo "Signature verification error" >&2
    exit 1
fi