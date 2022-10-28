#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "include/secureboot.h"

// Keys
#include "include/keys.h"

// Support for the openssl for sha and  RSA-PSS verification
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

// Future Support for the TLV structure in the trailer instead of info in header
#include "include/tlv.h"


/* Macros for redundant conditionals */
/* Inspired by https://research.nccgroup.com/2021/07/08/software-based-fault-injection-countermeasures-part-2-3/ */
#define IF_AND(cond)  if((cond) && (cond) && (cond))
#define IF_OR(cond)   if((cond) || (cond) || (cond))


/* Forward declarations */
static int secureboot_rollback(const uint8_t *payload, uint8_t cur_version);
static int secureboot_memcmp(const void *s1, const void *s2, size_t n);
static int secureboot_sig_verify_ec(const uint8_t *hash, uint32_t hlen, const uint8_t *payload,
        uint8_t *tmp_buf, uint32_t tmp_buf_sz, const struct opt_key *opt_key);

/**
 * @brief It handles the fatal error.
 *        It will trigger a NULL dereference immediately to prevent fault injection.
 */
static inline void fatal(void)
{
    *(volatile uint32_t*) 0;
}

/**
 * @brief Helper function to check endianess.
 * @return The function returns 1 if little endian architecture or 0 if big
 *         endian.
 */
static inline int check_endian(void){
    uint32_t x = 1;
    uint8_t *test = (uint8_t*)&x;
    volatile int rc = (int)*test;
    IF_AND(rc == (int)(*(uint8_t*)&x)) {
        return rc;
    }
    else {
        fatal();
        return rc;
    }
}

/**
 * @brief Inline function to extract the field from the header.
 *        This function will be called redunduntly to make it hard to injecting a fault
 *
 * TODO: improve readibility internal code style ternary 1 line fits in 80 lines.
 */
static inline int _getFieldFromHeader(const uint8_t *payload, int off)
{
   return (check_endian())?(payload[off + 3] << 24) + \
        (payload[off + 2] << 16) + \
        (payload[off + 1] << 8) + \
        payload[off]:
        (payload[off] << 24) + \
        (payload[off + 1] << 16) + \
        (payload[off + 2] << 8) + \
        payload[off + 3];
}

/**
 * @brief Helper function to extract the field from the header.
 */
static inline int getFieldFromHeader(const uint8_t *payload, int off)
{
    volatile int data = _getFieldFromHeader(payload, off);

    // Read memory redundantly to make it difficult to inject a faulty
    IF_OR( data != _getFieldFromHeader(payload,off ) ) {
        fatal();
    }

    return data;
}

static inline unsigned int base64_len(size_t len)
{
    return ((len + 2) / 3 * 4) + 1;
}

/**
 * @brief Helper function to convert char array to Base64 string.
 *        inspired in https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c
 * @return base64 String
 */
static int hex_to_base64(char *encoded, const unsigned char *string, size_t len)
{
    static const char base64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    volatile int i;
    char *p;
    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
        *p++ = base64[(string[i] >> 2) & 0x3F];
        *p++ = base64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = base64[((string[i + 1] & 0xF) << 2) |
                        ((int) (string[i + 2] & 0xC0) >> 6)];
        *p++ = base64[string[i + 2] & 0x3F];
    }
    IF_AND( i < len ) {
        *p++ = base64[(string[i] >> 2) & 0x3F];
        IF_AND (i == (len - 1)) {
            *p++ = base64[((string[i] & 0x3) << 4)];
            *p++ = '=';
         }
         else {
            *p++ = base64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
            *p++ = base64[((string[i + 1] & 0xF) << 2)];
        }
        *p++ = '=';
    }
    *p++ = '\0';
    return p - encoded;
}

/**
 * @brief Validate the SHA256 of the public key part of the trailer and comparing
 *        with the reference value in the OTP
 *        Added 'offset' parameter to check multiple public keys in header
 */
static int
secureboot_hash_pubkey(const uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                uint8_t *hash_result, int *key_id, uint32_t offset)
{
    SHA256_CTX sha256_ctx;
    volatile uint32_t blk_sz = 0;
    uint32_t size;
    uint32_t off;
    uint32_t offset_len = offset + 4;
    volatile int rc = VERIFY_GENERIC_ERROR;

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    SHA256_Init(&sha256_ctx);
    // Hash is computed over public key.
    size = getFieldFromHeader(payload,offset_len);

    // for images bigger than 1000 to avoid overflowing tmp buffer
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        IF_OR( blk_sz > tmp_buf_sz ) {
            blk_sz = tmp_buf_sz;
        }
        memcpy(tmp_buf, payload + getFieldFromHeader(payload, offset) + OFF_OFF_HDR + off, blk_sz);
        SHA256_Update(&sha256_ctx, tmp_buf, blk_sz);
    }
    SHA256_Final(hash_result, &sha256_ctx);
    for ( int cnt = 0; cnt < NUM_PK_OTP; cnt++){
        IF_AND( ! secureboot_memcmp(hash_result, opt_keys[cnt].hash_pk, HASH_SZ) ) {
            LOG_DEBUG("public key digest is correct", hash_result, HASH_SZ, true);
            (void)sha256_ctx;
            *key_id = cnt;
            rc = VERIFY_SUCCESS;
        }
    }
    (void)sha256_ctx;
    return rc;
}

/**
 * @brief Validate the SHA256 of the image including header and body
 */
static int
secureboot_hash_image_hdr_body(const uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                uint8_t *hash_result)
{
    volatile int rc = VERIFY_GENERIC_ERROR;
    volatile uint32_t blk_sz = 0;
    SHA256_CTX sha256_ctx;
    uint32_t size;
    uint32_t off;

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    SHA256_Init(&sha256_ctx);
    // Hash is computed over image header and image itself.
    size = IMAGE_HDR_SZ;
    size += getFieldFromHeader(payload, OFF_IMG_LEN);
    size += getFieldFromHeader(payload, OFF_RSA_PK_LEN);
    size += getFieldFromHeader(payload, OFF_ECDSA_PK_LEN);
    // for images bigger than 1000 to avoid overflowing tmp buffer
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        IF_OR (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }
        memcpy(tmp_buf, payload + off, blk_sz);
        SHA256_Update(&sha256_ctx, tmp_buf, blk_sz);
    }
    SHA256_Final(hash_result, &sha256_ctx);
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_HASH) + OFF_OFF_HDR, HASH_SZ );
    IF_AND( ! secureboot_memcmp(hash_result, tmp_buf , HASH_SZ) ) {
        LOG_DEBUG("hash of header + body + public key is correct", hash_result, HASH_SZ, true);
        rc = VERIFY_SUCCESS;
    }
    (void)sha256_ctx;
    return rc;
}


/**
 * @brief initialize random in openssl
 *
 */
static void init_openssl(void)
{
    if(SSL_library_init())
    {
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
    }
    else
        exit(EXIT_FAILURE);
}

/**
 * @brief Implement signature verification based on RSA PSS
 *
 */
static int secureboot_sig_verify_rsa(const uint8_t *hash, uint32_t hlen, const uint8_t *payload,
        uint8_t *tmp_buf, uint32_t tmp_buf_sz, const struct opt_key *opt_key)
{
    volatile int rc = VERIFY_GENERIC_ERROR;

    EVP_PKEY *pkey = NULL;
    uint32_t siglen;
    EVP_MD_CTX* rsa_verify_ctx = NULL;
    BIO *bufio;

    // Get signature length from header
    siglen = getFieldFromHeader(payload, OFF_RSA_SIGN_LEN);
    IF_OR( siglen != RSA_SIG_BUF_SZ ) {
        rc = IMAGE_FORMAT_ERROR;
        goto out;
    }

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_RSA_SIGN) + OFF_OFF_HDR , siglen);
    LOG_DEBUG("RSA signature", tmp_buf, siglen, true);
    rsa_verify_ctx = EVP_MD_CTX_create();

    IF_OR( rsa_verify_ctx == NULL ) {
        rc = SSL_CTX_INIT_ERROR;
        goto out;
    }

    // Get base64 length of public key (with redundant writing)
    volatile int pubkeyDER_len = base64_len(*opt_key->pk_len);
    IF_OR( pubkeyDER_len != base64_len(*opt_key->pk_len) ) {
        fatal();
    }

    // Prepare header and footer of public key string
    const char *hdrpubkeyDER = "-----BEGIN PUBLIC KEY-----\n",
          *fotpubkeyDER = "\n-----END PUBLIC KEY-----";
    const int hdrpubkeyDER_len = strlen(hdrpubkeyDER);
    const size_t biopubkeyDER_len = pubkeyDER_len + CERT_STR_HAF_SZ;

    // using only one buffer
    char *biopubkeyDER = malloc(biopubkeyDER_len);
    IF_OR( biopubkeyDER == NULL ) {
        rc = MEMORY_ALLOC_ERROR;
        goto out;
    }

    // Copy header of pub key
    strncpy(biopubkeyDER, hdrpubkeyDER, biopubkeyDER_len);
    // Copy body of pub key
    hex_to_base64(biopubkeyDER + hdrpubkeyDER_len, opt_key->pk,
            *opt_key->pk_len);
    // Copy footer of pub key
    // offset -1 to remove \0 at the end of base64 body
    strncpy(biopubkeyDER + hdrpubkeyDER_len + pubkeyDER_len - 1, fotpubkeyDER,
            biopubkeyDER_len - hdrpubkeyDER_len - pubkeyDER_len);
    bufio = BIO_new(BIO_s_mem());
    LOG_DEBUG("Debug Bio RSA Pub Key", biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ, false);
    int len = BIO_write(bufio, biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ);
    pkey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    IF_OR ( pkey == NULL || len <= 0 ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }

    /* Initialize */
    rc = EVP_DigestVerifyInit(rsa_verify_ctx, NULL, EVP_sha256(), NULL, pkey);
    IF_OR( !rc ) {
        rc = VERIFY_INIT_ERROR;
        goto out_buf;
    }
    rc = VERIFY_GENERIC_ERROR; // reset-after-use

    /* Update with the hash */
    rc = EVP_DigestVerifyUpdate(rsa_verify_ctx, hash, hlen);
    IF_OR( !rc ) {
        rc = VERIFY_UPDATE_ERROR;
        goto out_buf;
    }
    rc = VERIFY_GENERIC_ERROR; // reset-after-use

    /* Verify with the signature */
    IF_AND( EVP_DigestVerifyFinal(rsa_verify_ctx, tmp_buf, siglen) ) {
        rc = VERIFY_SUCCESS;
        printf("Verification Success - \t");
    }
    else {
        rc = VERIFY_FINAL_ERROR;
        goto out_buf;
    }
out_buf:
    if (biopubkeyDER) {
        free(biopubkeyDER);
    }
out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (rsa_verify_ctx) {
        EVP_MD_CTX_free(rsa_verify_ctx);
    }
    printf("Return Code(%s) : %x \n", __FUNCTION__, rc);
    return rc;
}

/**
 * @brief Challenge: Implement a rollback and update the structures accordingly.
 *
 *        Check if the target image is newer than the current image using version field
 *        in the image header
 *
 * @return VERIFY_SUCCESS if success else VERIFY_VERSION_ERROR
 */
static int secureboot_rollback(const uint8_t *payload, uint8_t cur_version)
{
    // Extract version from the header
    volatile int version = getFieldFromHeader(payload, OFF_VERSION);

    // Assumes always use the latest version and rollback is never allowed.
    IF_AND( cur_version < version ) {
        return VERIFY_SUCCESS;
    }
    else {
        return VERIFY_VERSION_ERROR;
    }
}

/**
 * @brief Challenge: Replace by a secure implementation of memcmp and replace in the code.
 *
 *        It performs comparisions in constant time to prevent timing attacks.
 *        It checks only if they are same or not and doesn't provide which one is
 *        greater or less at the first mismatched chracters unlike memcmp().
 *        All parameters are identical to memcmp().
 *
 *        Inspired by https://security.stackexchange.com/questions/160808/why-should-memcmp-not-be-used-to-compare-security-critical-data
 *
 * @return nonzero if s1 and s2 is different else zero
 */
static int secureboot_memcmp(const void *s1, const void *s2, size_t n)
{
    int rc = 0;
    for( size_t i = 0; i < n; ++i ) {
        // Make it runs at the same number of cycles whether they match or not.
        rc |= (int) ( *( (const char*)s1 + i ) - *( (const char*)s2 + i ) );

        // Go till the end of buffers
    }
    return rc;
}

/**
 * @brief Challenge: Implement a signature verification supporting Eliptic Curve
 * using openssl primitives and provide a keys.h with example of keys
 */
static int secureboot_sig_verify_ec(const uint8_t *hash, uint32_t hlen, const uint8_t *payload,
        uint8_t *tmp_buf, uint32_t tmp_buf_sz, const struct opt_key *opt_key)
{
    volatile int rc = VERIFY_GENERIC_ERROR;

    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    uint32_t siglen;
    EVP_MD_CTX* ecdsa_verify_ctx = NULL;
    BIO *bufio;

    // Get the size of ECDSA signature in the trailer part (ECDSA signature has a variable size)
    // TODO: add sanity check to prevent overrun if value in OFF_ECDSA_SIGN_LEN is bigger than the payload size
    siglen = getFieldFromHeader(payload, getFieldFromHeader(payload, OFF_ECDSA_SIGN_LEN) +
            OFF_OFF_HDR);

    // Check if it exceeds the maximum size of ECSDA signature (72)
    IF_OR( siglen > ECDSA_SIG_BUF_SZ ) {
        rc = IMAGE_FORMAT_ERROR;
        goto out;
    }

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_ECDSA_SIGN) + OFF_OFF_HDR , siglen);
    LOG_DEBUG("ECDSA signature", tmp_buf, siglen, true);
    ecdsa_verify_ctx = EVP_MD_CTX_create();

    IF_OR( ecdsa_verify_ctx == NULL ) {
        rc = SSL_CTX_INIT_ERROR;
        goto out;
    }

    volatile int pubkeyDER_len = base64_len(*opt_key->pk_len);
    IF_OR( pubkeyDER_len != base64_len(*opt_key->pk_len) ) {
        fatal();
    }

    // Prepare header and footer of public key string
    const char *hdrpubkeyDER = "-----BEGIN PUBLIC KEY-----\n",
          *fotpubkeyDER = "\n-----END PUBLIC KEY-----";
    const int hdrpubkeyDER_len = strlen(hdrpubkeyDER);
    const size_t biopubkeyDER_len = pubkeyDER_len + CERT_STR_HAF_SZ;

    // using only one buffer
    char *biopubkeyDER = malloc(biopubkeyDER_len);
    IF_OR( biopubkeyDER == NULL ) {
        rc = MEMORY_ALLOC_ERROR;
        goto out;
    }
    // Copy header of pub key
    strncpy(biopubkeyDER, hdrpubkeyDER, biopubkeyDER_len);
    // Copy body of pub key
    hex_to_base64(biopubkeyDER + hdrpubkeyDER_len, opt_key->pk,
            *opt_key->pk_len);
    // Copy footer of pub key
    // offset -1 to remove \0 at the end of base64 body
    strncpy(biopubkeyDER + hdrpubkeyDER_len + pubkeyDER_len - 1, fotpubkeyDER,
            biopubkeyDER_len - hdrpubkeyDER_len - pubkeyDER_len);
    bufio = BIO_new(BIO_s_mem());
    LOG_DEBUG("Debug Bio ECDSA Pub Key", biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ, false);
    int len = BIO_write(bufio, biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ);
    // Get EC_KEY first
    eckey = PEM_read_bio_EC_PUBKEY(bufio, NULL, NULL, NULL);
    IF_OR( eckey == NULL || len <= 0 ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }
    // Convert EC_KEY to EVP_PKEY
    pkey = EVP_PKEY_new();
    rc = EVP_PKEY_set1_EC_KEY(pkey, eckey);
    IF_OR( !rc ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }
    rc = VERIFY_GENERIC_ERROR; // reset-after-use

    /* Initialize */
    rc = EVP_DigestVerifyInit(ecdsa_verify_ctx, NULL, EVP_sha256(), NULL, pkey);
    IF_OR( !rc ) {
        rc = VERIFY_INIT_ERROR;
        goto out_buf;
    }
    rc = VERIFY_GENERIC_ERROR; // reset-after-use
    /* Update with the hash */
    rc = EVP_DigestVerifyUpdate(ecdsa_verify_ctx, hash, hlen);
    IF_OR( !rc ) {
        rc = VERIFY_UPDATE_ERROR;
        goto out_buf;
    }
    rc = VERIFY_GENERIC_ERROR; // reset-after-use
    /* Verify with the signature */
    IF_AND( EVP_DigestVerifyFinal(ecdsa_verify_ctx, tmp_buf, siglen) ) {
        rc = VERIFY_SUCCESS;
        printf("Verification Success - \t");
    }
    else {
        rc = VERIFY_FINAL_ERROR;
        goto out_buf;
    }
out_buf:
    if (biopubkeyDER) {
        free(biopubkeyDER);
    }
out:
    if (eckey) {
        EC_KEY_free(eckey);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (ecdsa_verify_ctx) {
        EVP_MD_CTX_free(ecdsa_verify_ctx);
    }
    printf("Return Code(%s) : %x \n", __FUNCTION__, rc);
    return rc;
}

/**
 * @brief Validate the image.
 *
 */
int
secureboot_validate_image(uint8_t *payload, uint8_t *tmp_buf,
                      uint32_t tmp_buf_sz)
{
    volatile int rc = VERIFY_GENERIC_ERROR;
    uint8_t hash[HASH_SZ];

    // validate the hash of the public key with the one stored in the OTP
    const uint32_t pubkeys[] = { OFF_RSA_PK, OFF_ECDSA_PK };
    for( size_t i = 0; i < sizeof(pubkeys)/sizeof(uint32_t); ++i ) {
        int key_id = VERIFY_GENERIC_ERROR;
        IF_OR( ( rc = secureboot_hash_pubkey(payload, tmp_buf, tmp_buf_sz,
                        hash, &key_id, pubkeys[i]) ) != VERIFY_SUCCESS ||
                0 > key_id || key_id > NUM_PK_OTP ) {
            // error means that hash of PK not matching ones in the OTP
            printf("Public Key verification is failed at %zu\n", i );
            goto out;
        }
    }

    // validate the hash of the image header and body with the one computed
    IF_OR( ( rc = secureboot_hash_image_hdr_body(payload, tmp_buf,tmp_buf_sz, hash) )
            != VERIFY_SUCCESS ) {
        // error means that sha is not done
        printf("Hash verification is failed\n" );
        goto out;
    }

    // Init OpenSSL and random generator
    init_openssl();

    // verify the signature of the image with RSA public key
    IF_OR( ( rc = secureboot_sig_verify_rsa(hash, HASH_SZ, payload, tmp_buf,
            tmp_buf_sz, &opt_keys[0]) ) != VERIFY_SUCCESS ) {
        // error means that verification is incorrect
        printf("RSA Signature verification is failed\n" );
        goto out;
    }

    // verify the signature of the image with ECDSA public key
    IF_OR( ( rc = secureboot_sig_verify_ec(hash, HASH_SZ, payload, tmp_buf,
            tmp_buf_sz, &opt_keys[1]) ) != VERIFY_SUCCESS ) {
        // error means that verification is incorrect
        printf("ECDSA Signature verification is failed\n" );
        goto out;
    }

    // verify the image version is not an old one
    IF_OR( ( rc = secureboot_rollback(payload, EMBEDDED_VERSION) ) != VERIFY_SUCCESS ) {
        // error means that the version of payload is deprecated
        printf("Image rollback is detected\n" );
        goto out;
    }

out:
    if (rc != VERIFY_SUCCESS) {
       printf("Error validate the signature %x ", rc);
    }
    return rc;
}


/******************************************************************************
 * Unit tests for the challange
 *****************************************************************************/

/**
 * @brief Structure contains testvectors used in secureboot_unittest_memcmp()
 */
struct memcmp_testvectors
{
    const char* s1;
    const char* s2;
};

/**
 * @brief Measure the elapsed time of multiple memcmp calls
 *
 * @return VERIFY_SUCCESS always
 */
static inline int _test_memcmp( const struct memcmp_testvectors* tv, size_t tv_count, size_t iteration,
        int (*cmp)(const void* s1, const void* s2, size_t n) )
{
    clock_t start, end;
    double cpu_time_used;

    // do compare test vectors
    for( size_t i = 0; i < tv_count; ++i )
    {
        start = clock();

        for( size_t j = 0; j < iteration; ++j ) {
            // prevent being optimized out
            volatile int res = (*cmp)( tv[i].s1, tv[i].s2, strlen( tv[i].s2 ) );
            (void) res;
        }

        end = clock();
        cpu_time_used = ( (double) (end - start) ) / CLOCKS_PER_SEC;

        if( i > 0 ) {
            // Exclude the first run from the result to minimize impact of cache.
            // Maybe we can drop caches before every run but it might be platform dependent.
            printf( "%zu-th test: %f sec\n", i, cpu_time_used );
        }
    }

    // No fail for this test yet.
    // A pass/fail condition may be varied depends on the platform/HW.
    return VERIFY_SUCCESS;
}

/**
 * @brief Unit test for secureboot_memcmp()
 *
 * @return VERIFY_SUCCESS if success
 */
int secureboot_unittest_memcmp(void)
{
    // Prepare test vectors which have zero or single difference between the pair.
    const struct memcmp_testvectors tvs[] = {
        { "A123456789123456789123456789123456789123456789",
          "A123456789123456789123456789123456789123456789" }, // same
        { "A123456789123456789123456789123456789123456789",
          "A123456789123456789123456789123456789123456789" }, // same as intended
        { "B123456789123456789123456789123456789123456789",
          "B123456089123456789123456789123456789123456789" }, // 8-th ch
        { "C123456789123456789123456789123456789123456789",
          "C123456789123456089123456789123456789123456789" }, // 17-th ch
        { "D123456789123456789123456789123456789123456789",
          "D123456789123456789123456789123456789123456780" }, // the last ch
    };

    int rc = VERIFY_GENERIC_ERROR;

    const size_t iteration = 1000;

    // Test original memcmp()
    printf("- original memcmp() test\n");
    if( ( rc = _test_memcmp( tvs, sizeof(tvs) / sizeof(struct memcmp_testvectors), iteration,
            memcmp ) ) != VERIFY_SUCCESS ) {
        goto out;
    }

    // Test secureboot_memcmp()
    printf("- secureboot_memcmp() test\n");
    if( ( rc = _test_memcmp( tvs, sizeof(tvs) / sizeof(struct memcmp_testvectors), iteration,
            secureboot_memcmp ) ) != VERIFY_SUCCESS ) {
        goto out;
    }

out:
    return rc;
}

/**
 * @brief Unit test for secureboot_rollback()
 *
 * @return VERIFY_SUCCESS if success else VERIFY_VERSION_ERROR
 */
int secureboot_unittest_rollback(void)
{
    // Prepare test vectors which contain possible versions of the image.
    const uint32_t tvs[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    int rc = VERIFY_GENERIC_ERROR;

    for( size_t i = 0; i < sizeof(tvs)/sizeof(uint32_t); ++i ) {
        struct img_hdr hdr = { IMAGE_MAGIC, tvs[i] };

        rc = secureboot_rollback((uint8_t *)&hdr, EMBEDDED_VERSION);
        if( ( rc == VERIFY_SUCCESS && tvs[i] <= EMBEDDED_VERSION ) ||
                ( rc != VERIFY_SUCCESS && tvs[i] > EMBEDDED_VERSION ) ) {
            return VERIFY_VERSION_ERROR;
        }
        rc = VERIFY_GENERIC_ERROR;
    }

    return VERIFY_SUCCESS;
}

/**
 * @brief Unit test for secureboot_sig_verify_ec()
 *
 * @return VERIFY_SUCCESS if success else VERIFY_VERSION_ERROR
 */
int secureboot_unittest_ec(void)
{
    // Prepare test vectors
    const unsigned char ecdsa256_pub_key[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0x6f, 0x94, 0x57, 0xd5, 0xa0,
        0x80, 0xb2, 0x5a, 0xd1, 0x2d, 0x43, 0xb3, 0x53,
        0x80, 0x8b, 0x8d, 0x72, 0xe1, 0xdb, 0x57, 0x76,
        0x55, 0x54, 0x98, 0x41, 0x25, 0x45, 0xc0, 0x92,
        0xff, 0x2e, 0x2e, 0x54, 0xe5, 0x5e, 0x31, 0x52,
        0x70, 0xa8, 0x7e, 0x34, 0x72, 0x87, 0xaa, 0x68,
        0xa7, 0x4c, 0xe9, 0xa1, 0x76, 0xa3, 0x1f, 0x45,
        0x66, 0x9c, 0x80, 0x61, 0x52, 0x89, 0x22, 0x5f,
        0xbe, 0x73, 0x2a
    };
    const unsigned int ecdsa256_pub_key_len = 91;
    const unsigned char ecdsa256_pub_key_hash[] = {
        0x36, 0xea, 0xee, 0x6a, 0xea, 0x0d, 0x89, 0x1c,
        0x59, 0xb0, 0x38, 0x7b, 0xd3, 0x11, 0x00, 0x0d,
        0xd9, 0xa5, 0x6a, 0xe4, 0xa1, 0x79, 0x90, 0x23,
        0xf9, 0xdd, 0x86, 0x97, 0x7b, 0xb4, 0x76, 0x91
    };
    const struct opt_key opt_key = {
        .hash_pk = ecdsa256_pub_key_hash,
        .pk_len = &ecdsa256_pub_key_len,
        .pk = ecdsa256_pub_key,
    };
    const unsigned char hash[] = {
        0x93, 0xda, 0x6f, 0xbd, 0x5c, 0x9d, 0x12, 0xed,
        0x11, 0xe0, 0xa9, 0x1a, 0xd7, 0x64, 0x2e, 0x25,
        0xb1, 0xd9, 0xf8, 0x31, 0x87, 0x84, 0x44, 0xc4,
        0x0e, 0xf8, 0x71, 0x7e, 0x8f, 0x52, 0xd9, 0x07
    };
    const uint32_t hlen = 32;
    const unsigned char sig[] = {
        0x30, 0x44, 0x02, 0x20, 0x24, 0xa7, 0x07, 0x5c,
        0xb8, 0xd0, 0xa1, 0x6c, 0xfe, 0x24, 0x54, 0x09,
        0x34, 0xc1, 0x3a, 0xe5, 0x03, 0x76, 0x9c, 0x31,
        0x44, 0x83, 0x07, 0x29, 0x03, 0x50, 0x67, 0xcf,
        0x9d, 0x74, 0xe9, 0x0f, 0x02, 0x20, 0x75, 0xd9,
        0xb4, 0xc0, 0xaf, 0x0d, 0x49, 0x0a, 0x57, 0x4a,
        0x6f, 0xf5, 0x2d, 0x5e, 0xfb, 0x28, 0x17, 0x38,
        0xc9, 0xe1, 0xf7, 0xd3, 0x95, 0xf6, 0xa9, 0xf7,
        0xad, 0xee, 0xf9, 0xd8, 0xc4, 0x38
    };
    const uint32_t siglen = 70;
    uint8_t payload[TMPBUF_SZ];
    uint8_t tmpbuf[TMPBUF_SZ];

    // Create dummy payload
    struct img_hdr *hdr = (struct img_hdr *)payload;
    hdr->hash_off = IMAGE_HDR_SZ - OFF_OFF_HDR;
    hdr->hash_len = hlen;
    hdr->ecdsa_sign_len_off = hdr->hash_off + hdr->hash_len;
    hdr->ecdsa_sign_off = hdr->ecdsa_sign_len_off + 4;

    memcpy( payload + hdr->hash_off + OFF_OFF_HDR, hash, hlen );
    memcpy( payload + hdr->ecdsa_sign_len_off + OFF_OFF_HDR, &siglen, 4 );
    memcpy( payload + hdr->ecdsa_sign_off + OFF_OFF_HDR, sig, siglen );

    // run secureboot_sig_verify_ec
    init_openssl();
    int rc = secureboot_sig_verify_ec(hash, hlen, payload, tmpbuf, TMPBUF_SZ, &opt_key );

    return rc;
}
