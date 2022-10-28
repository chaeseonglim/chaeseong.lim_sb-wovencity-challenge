#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// static inline is the best way (vincent's suggestion)
// good comment in 0; removed due to compilation dependency -> check the objdump for assembly
// for code structure -> change way to define functions avoid using a boolean parameter to determine behaviour
// this is more static inline function
#ifdef DEBUG
#define LOG_DEBUG(msg, val, sz, val_is_str) {   \
    if ((val_is_str == false) ){                \
        printf("[+] Debug %s: %s \n", msg, val);\
    }else{                                      \
        printf("[+] Debug %s: ", msg);          \
        for(int i = 0 ; i < sz; i++)            \
            printf("%02x", val[i]);             \
        printf("\n");                           \
    }                                           \
}
#else
#define LOG_DEBUG(msg, a,n,b)
#endif

// TODO improve naming because it is better for readibility.
#define OFF_VERSION         4                           /* Image version */
#define OFF_IMG             (OFF_VERSION) + 4           /* Image offset to image body offset*/
#define OFF_IMG_LEN         (OFF_IMG) + 4               /* Image body length */
#define OFF_RSA_PK          (OFF_IMG_LEN) + 4           /* Image offset to RSA Public key offset */
#define OFF_RSA_PK_LEN      (OFF_RSA_PK) + 4            /* RSA Public Key length  */
#define OFF_ECDSA_PK        (OFF_RSA_PK_LEN) + 4        /* Image offset to ECDSA Public key offset */
#define OFF_ECDSA_PK_LEN    (OFF_ECDSA_PK) + 4          /* ECDSA Public Key length  */
#define OFF_HASH            (OFF_ECDSA_PK_LEN) + 4      /* Image offset to Hash offset */
#define OFF_HASH_LEN        (OFF_HASH) + 4              /* Hash length  */
#define OFF_RSA_SIGN        (OFF_HASH_LEN) + 4          /* Image offset to RSA signature offset */
#define OFF_RSA_SIGN_LEN    (OFF_RSA_SIGN) + 4          /* RSA Signature length  */
#define OFF_ECDSA_SIGN_LEN  (OFF_RSA_SIGN_LEN) + 4      /* Image offset to ECDSA signature length */
#define OFF_ECDSA_SIGN      (OFF_ECDSA_SIGN_LEN) + 4    /* Image offset to ECDSA Signature offset  */

// The "offset" of offset field in the header (in bytes)
#define OFF_OFF_HDR     (1)

// Error Codes
#define VERIFY_SUCCESS          0X80000000
#define VERIFY_GENERIC_ERROR    0x7FFFFFFF
#define PUBKEY_LOADING_ERROR    0x7FFFFFFE
#define SSL_CTX_INIT_ERROR      0x7FFFFFFD
#define EVP_PKEY_INIT_ERROR     0x7FFFFFFC
#define VERIFY_INIT_ERROR       0x7FFFFFFB
#define VERIFY_UPDATE_ERROR     0x7FFFFFFA
#define VERIFY_FINAL_ERROR      0x7FFFFFF9
#define IMAGE_FORMAT_ERROR      0x7FFFFFF1
#define MEMORY_ALLOC_ERROR      0x7FFFFFF2
#define VERIFY_VERSION_ERROR    0x7FFFFFF3

// Signature buffer size
#define RSA_SIG_BUF_SZ          256
#define ECDSA_SIG_BUF_SZ        72

// Hash size
#define HASH_SZ    32

// temporary buffer size
#define TMPBUF_SZ   1000

// Certificate Header and Footer len
// -----BEGIN PUBLIC KEY-----
// -----END PUBLIC KEY-----
// + '\0'
#define CERT_STR_HAF_SZ    52

// Number of hash of Public key in the OTP (One is for RSA, another for ECDSA)
#define NUM_PK_OTP    2

// Version supposed to be embedded in NVM memory such as OTP, flash etc
// Assumes the version of current installed image is 5 for test purpose
#define EMBEDDED_VERSION    5

// Used in the old implementation based on TLV
struct img_hdr {
    uint32_t ih_magic;
    uint32_t version;               /* version of the image */
    uint32_t image_off;             /* offset to the image  */
    uint32_t image_len;             /* Size of image (in bytes). */
    uint32_t rsa_pk_off;            /* offset to the RSA public key  */
    uint32_t rsa_pk_len;            /* Size of RSA public key (in bytes). */
    uint32_t ecdsa_pk_off;          /* offset to the ECDSA public key  */
    uint32_t ecdsa_pk_len;          /* Size of ECDSA public key (in bytes). */
    uint32_t hash_off;              /* offset to the hash  */
    uint32_t hash_len;              /* Size of hash. */
    uint32_t rsa_sign_off;          /* offset to the RSA signature  */
    uint32_t rsa_sign_len;          /* Size of RSA signature (in bytes). */
    uint32_t ecdsa_sign_len_off;    /* offset to size of ECDSA signature (in bytes). */
    uint32_t ecdsa_sign_off;        /* offset to the ECDSA signature  */
};

#define IMAGE_MAGIC     0x28FEB8C6
#define IMAGE_HDR_SZ    sizeof(struct img_hdr)

int secureboot_validate_image( uint8_t *payload, uint8_t *tmp_buf,
                               uint32_t tmp_buf_sz);

// Unit tests
int secureboot_unittest_memcmp(void);
int secureboot_unittest_rollback(void);
int secureboot_unittest_ec(void);

#ifdef __cplusplus
}
#endif
