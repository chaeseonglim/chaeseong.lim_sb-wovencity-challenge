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

/* Forward declarations */
static int secureboot_rollback(uint8_t *payload, uint8_t cur_version);
static int secureboot_memcmp(const void *s1, const void *s2, size_t n);

/**
 * @brief Helper function to check endianess.
 * @return The function returns 1 if little endian architecture or 0 if big
 *         endian.
 */
static int check_endian(){
    uint32_t x = 1;
    uint8_t *test = (uint8_t*)&x;
    return (int)*test;
}

/**
 * @brief Helper function to extract the field from the header.
 *
 * TODO: improve readibility internal code style ternary 1 line fits in 80 lines.
 */
static int getFieldFromHeader(uint8_t *payload, int off)
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

static unsigned int base64_len(size_t len)
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

    int i;
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
    if (i < len) {
        *p++ = base64[(string[i] >> 2) & 0x3F];
        if (i == (len - 1)) {
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
 *
 *        Added 'offset' parameter to check multiple public keys in header
 */
static int
secureboot_hash_pubkey(uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                uint8_t *hash_result, int *key_id, uint32_t offset)
{
    SHA256_CTX sha256_ctx;
    uint32_t blk_sz = 0;
    uint32_t size;
    uint32_t off;
    uint32_t offset_len = offset + 4;
    int rc = VERIFY_GENERIC_ERROR;

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    SHA256_Init(&sha256_ctx);
    // Hash is computed over public key.
    size = getFieldFromHeader(payload,offset_len);

    // for images bigger than 1000 to avoid overflowing tmp buffer
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        if (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }
        memcpy(tmp_buf, payload + getFieldFromHeader(payload, offset) + OFF_OFF_HDR + off, blk_sz);
        SHA256_Update(&sha256_ctx, tmp_buf, blk_sz);
    }
    SHA256_Final(hash_result, &sha256_ctx);
    for ( int cnt = 0; cnt < NUM_PK_OTP; cnt++){
        if ( ! secureboot_memcmp(hash_result, opt_keys[cnt].hash_pk, HASH_SZ) ){
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
secureboot_hash_image_hdr_body(uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz,
                uint8_t *hash_result)
{
    SHA256_CTX sha256_ctx;
    uint32_t blk_sz = 0;
    uint32_t size;
    uint32_t off;
    int rc = VERIFY_GENERIC_ERROR;

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
        if (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }
        memcpy(tmp_buf, payload + off, blk_sz);
        SHA256_Update(&sha256_ctx, tmp_buf, blk_sz);
    }
    SHA256_Final(hash_result, &sha256_ctx);
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_HASH) + OFF_OFF_HDR, HASH_SZ );
    if ( ! secureboot_memcmp(hash_result, tmp_buf , HASH_SZ) ){
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
static int secureboot_sig_verify_rsa(uint8_t *hash, uint32_t hlen, uint8_t *payload, uint8_t *tmp_buf,
        uint32_t tmp_buf_sz, uint8_t key_id)
{
    int rc = VERIFY_GENERIC_ERROR;

    EVP_PKEY *pkey = NULL;
    uint32_t siglen;
    EVP_MD_CTX* rsa_verify_ctx = NULL;
    BIO *bufio;

    siglen = getFieldFromHeader(payload, OFF_RSA_SIGN_LEN);

    if (siglen != RSA_SIG_BUF_SZ ){
        rc = IMAGE_FORMAT_ERROR;
        goto out;
    }

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_RSA_SIGN) + OFF_OFF_HDR , siglen);
    LOG_DEBUG("RSA signature", tmp_buf, siglen, true);
    rsa_verify_ctx = EVP_MD_CTX_create();

    if ( rsa_verify_ctx == NULL ) {
        rc = SSL_CTX_INIT_ERROR;
        goto out;
    }

    int pubkeyDER_len = base64_len(*opt_keys[key_id].pk_len);

    // Prepare header and footer of public key string
    const char *hdrpubkeyDER = "-----BEGIN PUBLIC KEY-----\n",
          *fotpubkeyDER = "\n-----END PUBLIC KEY-----";
    const int hdrpubkeyDER_len = strlen(hdrpubkeyDER);
    const size_t biopubkeyDER_len = pubkeyDER_len + CERT_STR_HAF_SZ;

    // using only one buffer
    char *biopubkeyDER = malloc(biopubkeyDER_len);
    // Copy header of pub key
    strncpy(biopubkeyDER, hdrpubkeyDER, biopubkeyDER_len);
    // Copy body of pub key
    hex_to_base64(biopubkeyDER + hdrpubkeyDER_len, opt_keys[key_id].pk,
            *opt_keys[key_id].pk_len);
    // Copy footer of pub key
    // offset -1 to remove \0 at the end of base64 body
    strncpy(biopubkeyDER + hdrpubkeyDER_len + pubkeyDER_len - 1, fotpubkeyDER,
            biopubkeyDER_len - hdrpubkeyDER_len - pubkeyDER_len);
    bufio = BIO_new(BIO_s_mem());
    LOG_DEBUG("Debug Bio RSA Pub Key", biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ, false);
    int len = BIO_write(bufio, biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ);
    pkey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    if ( pkey == NULL || len <= 0 ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }

    /* Initialize */
    if( !EVP_DigestVerifyInit(rsa_verify_ctx, NULL, EVP_sha256(), NULL, pkey) ){
        rc = VEFIFY_INIT_ERROR;
        goto out_buf;
    }
    /* Update with the hash */
    if( !EVP_DigestVerifyUpdate(rsa_verify_ctx, hash, hlen) ){
        rc = VEFIFY_UPDATE_ERROR;
        goto out_buf;
    }
    /* Verify with the signature */
    if( !EVP_DigestVerifyFinal(rsa_verify_ctx, tmp_buf, siglen) )
    {
        rc = VEFIFY_FINAL_ERROR;
        goto out_buf;
    }
    else
    {
        rc = VERIFY_SUCCESS;
        printf("Verification Success - \t");
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
 * @return zero if success else nonzero
 */
static int secureboot_rollback(uint8_t *payload, uint8_t cur_version)
{
    // Extract version from the header
    int version = getFieldFromHeader(payload, OFF_VERSION);

    // Assumes always use the latest version and rollback is never allowed.
    return !(cur_version < version);
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
static int secureboot_sig_verify_ec(uint8_t *hash, uint32_t hlen, uint8_t *payload, uint8_t *tmp_buf,
        uint32_t tmp_buf_sz, uint8_t key_id)
{
    int rc = VERIFY_GENERIC_ERROR;

    EVP_PKEY *pkey = NULL;
    EC_KEY *eckey = NULL;
    uint32_t siglen;
    EVP_MD_CTX* ecdsa_verify_ctx = NULL;
    BIO *bufio;

    // Get the size of ECDSA signature (it's variable length)
    // TODO: add sanity check to prevent overrun if value in OFF_ECDSA_SIGN_LEN is bigger than the payload size
    siglen = getFieldFromHeader(payload,
            getFieldFromHeader(payload, OFF_ECDSA_SIGN_LEN) + OFF_OFF_HDR);

    // Check if it exceeds the maximum size of ECSDA signature (72)
    if (siglen > ECDSA_SIG_BUF_SZ ){
        rc = IMAGE_FORMAT_ERROR;
        goto out;
    }

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_ECDSA_SIGN) + OFF_OFF_HDR , siglen);
    LOG_DEBUG("ECDSA signature", tmp_buf, siglen, true);
    ecdsa_verify_ctx = EVP_MD_CTX_create();

    if ( ecdsa_verify_ctx == NULL ) {
        rc = SSL_CTX_INIT_ERROR;
        goto out;
    }

    int pubkeyDER_len = base64_len(*opt_keys[key_id].pk_len);

    // Prepare header and footer of public key string
    const char *hdrpubkeyDER = "-----BEGIN PUBLIC KEY-----\n",
          *fotpubkeyDER = "\n-----END PUBLIC KEY-----";
    const int hdrpubkeyDER_len = strlen(hdrpubkeyDER);
    const size_t biopubkeyDER_len = pubkeyDER_len + CERT_STR_HAF_SZ;

    // using only one buffer
    char *biopubkeyDER = malloc(biopubkeyDER_len);
    // Copy header of pub key
    strncpy(biopubkeyDER, hdrpubkeyDER, biopubkeyDER_len);
    // Copy body of pub key
    hex_to_base64(biopubkeyDER + hdrpubkeyDER_len, opt_keys[key_id].pk,
            *opt_keys[key_id].pk_len);
    // Copy footer of pub key
    // offset -1 to remove \0 at the end of base64 body
    strncpy(biopubkeyDER + hdrpubkeyDER_len + pubkeyDER_len - 1, fotpubkeyDER,
            biopubkeyDER_len - hdrpubkeyDER_len - pubkeyDER_len);
    bufio = BIO_new(BIO_s_mem());
    LOG_DEBUG("Debug Bio ECDSA Pub Key", biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ, false);
    int len = BIO_write(bufio, biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ);
    // Get EC_KEY first
    eckey = PEM_read_bio_EC_PUBKEY(bufio, NULL, NULL, NULL);
    if ( eckey == NULL || len <= 0 ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }
    // EC_KEY to EVP_PKEY
    pkey = EVP_PKEY_new();
    if( !EVP_PKEY_set1_EC_KEY(pkey, eckey) ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out_buf;
    }

    /* Initialize */
    if( !EVP_DigestVerifyInit(ecdsa_verify_ctx, NULL, EVP_sha256(), NULL, pkey) ){
        rc = VEFIFY_INIT_ERROR;
        goto out_buf;
    }
    /* Update with the hash */
    if( !EVP_DigestVerifyUpdate(ecdsa_verify_ctx, hash, hlen) ){
        rc = VEFIFY_UPDATE_ERROR;
        goto out_buf;
    }
    /* Verify with the signature */
    if( !EVP_DigestVerifyFinal(ecdsa_verify_ctx, tmp_buf, siglen) )
    {
        rc = VEFIFY_FINAL_ERROR;
        goto out_buf;
    }
    else
    {
        rc = VERIFY_SUCCESS;
        printf("Verification Success - \t");
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
    uint8_t hash[HASH_SZ];
    int rc;

    // validate the hash of the public key with the one stored in the OTP
    uint32_t pubkeys[] = { OFF_RSA_PK, OFF_ECDSA_PK };
    for( size_t i = 0; i < sizeof(pubkeys)/sizeof(uint32_t); ++i ) {
        int key_id = VERIFY_GENERIC_ERROR;
        rc = secureboot_hash_pubkey(payload, tmp_buf, tmp_buf_sz,
                    hash, &key_id, pubkeys[i]);
        if ( rc ||  0 > key_id || key_id > NUM_PK_OTP ) {
            // error means that hash of PK not matching ones in the OTP
            printf("Public Key verification is failed at %zu\n", i );
            goto out;
        }
    }

    // validate the hash of the image header and body with the one computed
    rc =  secureboot_hash_image_hdr_body(payload, tmp_buf,tmp_buf_sz, hash);
    if (rc) {
        // error means that sha is not done
        printf("Hash verification is failed\n" );
        goto out;
    }

    // Init OpenSSL and random generator
    init_openssl();

    // verify the signature of the image with RSA public key
    rc = secureboot_sig_verify_rsa(hash, HASH_SZ, payload , tmp_buf,
            tmp_buf_sz, 0);
    if (rc) {
        // error means that verification is incorrect
        printf("RSA Signature verification is failed\n" );
        goto out;
    }

    // verify the signature of the image with ECDSA public key
    rc = secureboot_sig_verify_ec(hash, HASH_SZ, payload , tmp_buf,
            tmp_buf_sz, 1);
    if (rc) {
        // error means that verification is incorrect
        printf("ECDSA Signature verification is failed\n" );
        goto out;
    }

    // verify the image version is not an old one
    rc = secureboot_rollback(payload, EMBEDDED_VERSION);
    if (rc) {
        // error means that the version of payload is deprecated
        printf("Image rollback is detected\n" );
        goto out;
    }

out:
    if (rc) {
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

    // No criteria for this test.
    // A pass/fail condition may be varied depends on the platform/HW.
    return 0;
}

/**
 * @brief Unit test for secureboot_memcmp()
 *
 * @return zero if success else nonzero
 */
int secureboot_unittest_memcmp(void)
{
    // Prepare the test vectors which have zero or single difference between the pair.
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

    const size_t iteration = 1000;

    // Test original memcmp()
    printf("- original memcmp() test\n");
    int res = _test_memcmp( tvs, sizeof(tvs) / sizeof(struct memcmp_testvectors), iteration,
            memcmp );

    // Test secureboot_memcmp()
    printf("- secureboot_memcmp() test\n");
    res |= _test_memcmp( tvs, sizeof(tvs) / sizeof(struct memcmp_testvectors), iteration,
            secureboot_memcmp );

    return res;
}
