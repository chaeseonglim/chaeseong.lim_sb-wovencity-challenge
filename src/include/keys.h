#ifdef __cplusplus
extern "C" {
#endif

struct opt_key {
    const uint8_t *hash_pk;
    const uint8_t *pk;
    const unsigned int *pk_len;
};

/* import the keys auto-generated by python */
#include "../../unit_test/keys.h"

const struct opt_key opt_keys[] = {
    {
        .hash_pk = rsa2048_pub_key_hash,
        .pk_len = &rsa2048_pub_key_len,
        .pk = rsa2048_pub_key
    },
    {
        .hash_pk = ecdsa256_pub_key_hash,
        .pk_len = &ecdsa256_pub_key_len,
        .pk = ecdsa256_pub_key
    }
};

#ifdef __cplusplus
}
#endif
