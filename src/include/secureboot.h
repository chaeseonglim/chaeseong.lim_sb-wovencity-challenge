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
#define OFF_IMG         4                   /* Image offset to image body offset*/
#define OFF_IMG_LEN     (OFF_IMG) + 4       /* Image body length */
#define OFF_PK          (OFF_IMG_LEN) + 4   /* Image offset to Public key offset */
#define OFF_PK_LEN      (OFF_PK) + 4        /* Public Key length  */
#define OFF_HASH        (OFF_PK_LEN) + 4    /* Image offset to Public key offset */
#define OFF_HASH_LEN    (OFF_HASH) + 4      /* Public Key length  */
#define OFF_SIGN        (OFF_HASH_LEN) + 4  /* Image offset to signature offset */
#define OFF_SIGN_LEN    (OFF_SIGN) + 4      /* signature length  */

// Error Codes
#define VERIFY_SUCCESS          0
#define VERIFY_GENERIC_ERROR    0x7FFFFFFF
#define PUBKEY_LOADING_ERROR    0x7FFFFFFE
#define SSL_CTX_INIT_ERROR      0x7FFFFFFD
#define EVP_PKEY_INIT_ERROR     0x7FFFFFFC
#define VEFIFY_INIT_ERROR       0x7FFFFFFB
#define VEFIFY_UPDATE_ERROR     0x7FFFFFFA
#define VEFIFY_FINAL_ERROR      0x7FFFFFF9
#define IMAGE_FORMAT_ERROR      0x7FFFFFF1

// Signature buffer size
#define SIG_BUF_SZ    256 

// Hash size
#define HASH_SZ    32

// temporary buffer size
#define TMPBUF_SZ   1000

// Certificate Header and Footer len
// -----BEGIN PUBLIC KEY----- 
// -----END PUBLIC KEY-----
// + '\0'
#define CERT_STR_HAF_SZ    52

// Number of hash of Public key in the OTP
#define NUM_PK_OTP    1

// Not used in current PoC
struct img_hdr {
    uint32_t ih_magic;
    uint32_t image_off; /* offset to the image  */
    uint32_t image_len; /* Size of image (in bytes). */
    uint32_t pk_off;    /* offset to the public key  */
    uint32_t pk_len;    /* Size of public key (in bytes). */
    uint32_t hash_off; /* offset to the image  */
    uint32_t hash_len; /* Size of image (in bytes). */
    uint32_t sign_off;  /* offset to the signature  */
    uint32_t sign_len;  /* Size of signature (in bytes). */
    //uint32_t pad;
    //uint32_t versioning;
};

// i will generate a macro because it will change depending of endianness - > add macro
// and size of the header direct in code.
#define IMAGE_MAGIC     0x28FEB8C6
#define IMAGE_HDR_SZ    sizeof(struct img_hdr)

int secureboot_validate_image( uint8_t *payload, uint8_t *tmp_buf, 
                      uint32_t tmp_buf_sz);

#ifdef __cplusplus
}
#endif
