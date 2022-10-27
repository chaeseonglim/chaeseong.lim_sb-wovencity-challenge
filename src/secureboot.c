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
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

// Future Support for the TLV structure in the trailer instead of info in header
#include "include/tlv.h"

/* Forward declarations */
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
 */
static int
secureboot_hash_pubkey(uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz, 
                uint8_t *hash_result, int *key_id)
{
    SHA256_CTX sha256_ctx;
    uint32_t blk_sz = 0;
    uint32_t size;
    uint32_t off;
    int rc = VERIFY_GENERIC_ERROR;

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    SHA256_Init(&sha256_ctx);
    // Hash is computed over public key.
    size = getFieldFromHeader(payload,OFF_PK_LEN);

    // for images bigger than 1000 to avoid overflowing tmp buffer
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        if (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }     
        memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_PK) + 1, blk_sz);
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
    size += getFieldFromHeader(payload, OFF_PK_LEN);
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
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_HASH) + 1, HASH_SZ );
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
static int secureboot_sig_verify_rsa(uint8_t *hash, uint32_t hlen, uint8_t *payload, uint8_t *tmp_buf, uint32_t tmp_buf_sz, 
  uint8_t key_id)   
{
    int rc = VERIFY_GENERIC_ERROR;
    RSA *rsa = NULL;

    EVP_PKEY *pkey = NULL;
    uint32_t siglen;
    EVP_MD_CTX* rsa_verify_ctx = NULL;
    BIO *bufio;

    init_openssl();
    
    siglen = getFieldFromHeader(payload, OFF_SIGN_LEN);

    if (siglen != SIG_BUF_SZ ){
        rc = IMAGE_FORMAT_ERROR;
        goto out;
    }

    // TODO: add sanity check to prevent overrun if size payload + size of image bigger than sizeof(uint32_t)
    memcpy(tmp_buf, payload + getFieldFromHeader(payload, OFF_SIGN) + 1 , siglen);
    LOG_DEBUG("signature", tmp_buf, siglen, true);
    rsa_verify_ctx = EVP_MD_CTX_create();

    if ( rsa_verify_ctx == NULL ) {
        rc = SSL_CTX_INIT_ERROR;
        goto out;
    }

    int pubkeyDER_len = base64_len(*opt_keys[key_id].pk_len);
    //TODO improve only one buffer 
    char *pubkeyDERformat= malloc(pubkeyDER_len);
    char *biopubkeyDER= malloc(pubkeyDER_len+CERT_STR_HAF_SZ);
    hex_to_base64(pubkeyDERformat, opt_keys[key_id].pk, *opt_keys[key_id].pk_len);
    snprintf(biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ ,
            "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", 
            pubkeyDERformat);
    bufio = BIO_new(BIO_s_mem());
    LOG_DEBUG("Debug Bio Pub Key", biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ, false);
    int len = BIO_write(bufio, biopubkeyDER, pubkeyDER_len+CERT_STR_HAF_SZ); 
    pkey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    if ( pkey == NULL || len <= 0 ) {
        rc = EVP_PKEY_INIT_ERROR;
        goto out;
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
    if (pubkeyDERformat) {
        free(pubkeyDERformat);
    }
    if (biopubkeyDER) {
        free(biopubkeyDER);
    }
out:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (rsa) {
        RSA_free(rsa);
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
 */
static int secureboot_rollback()
{
    return 0;
}

/**
 * @brief Challenge: Replace by a secure implementation of memcmp and replace in the code.
 * 
 * @return nonzero if s1 and s2 is different else zero
 *         It doesn't provide which one is greater or less unlike original memcmp.
 */
static int secureboot_memcmp(const void *s1, const void *s2, size_t n)
{
    // Perform comparisions in constant time to prevent timing attacks.
    // Inspired by https://security.stackexchange.com/questions/160808/why-should-memcmp-not-be-used-to-compare-security-critical-data

    int result = 0;
    for( size_t i = 0; i < n; ++i ) {
        // Ensure it consumes the same number of cycles whether they match or not.
        result |= (int) ( *( (const char*)s1 + i ) - *( (const char*)s2 + i ) );

        // And never break during the loop...
    }
    return result;
}

/**
 * @brief Challenge: Implement a signature verification supporting Eliptic Curve
 * using openssl primitives and provide a keys.h with example of keys
 */
static int secureboot_sig_verify_ec()
{
    return 0;
}

/**
 * @brief Validate the image.
 * 
 */
int
secureboot_validate_image(uint8_t *payload, uint8_t *tmp_buf,
                      uint32_t tmp_buf_sz)
{
    //int key_id = VERIFY_GENERIC_ERROR;
    uint8_t hash[HASH_SZ];
    int rc , key_id = VERIFY_GENERIC_ERROR;
 
    //validate the hash of the public key with the one stored in the OTP
    rc = secureboot_hash_pubkey(payload, tmp_buf, tmp_buf_sz, 
                hash, &key_id);
    if ( rc ||  0 > key_id || key_id > NUM_PK_OTP ) {
        // error means that hash of PK not matching ones in the OTP 
        goto out;
    }
    //validate the hash of the image header and body with the one computed
    rc =  secureboot_hash_image_hdr_body(payload, tmp_buf,tmp_buf_sz, hash);
    if (rc) {
        // error means that sha is not done
        goto out;
    }
    
    // verify the signature of the image with public key
    rc = secureboot_sig_verify_rsa(hash, HASH_SZ, payload , tmp_buf,
            tmp_buf_sz, 0);
    if (rc) {
        // error means that verification is incorrect
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
 * @brief Structure used for secureboot_unittest_memcmp()
 */
struct str_pair
{
    const char* s1;
    const char* s2;
};

/**
 * @brief Unit test for secureboot_memcmp()
 */
int secureboot_unittest_memcmp(void)
{
    // Prepare the sample string pairs which has zero or one difference between them.
    const struct str_pair pairs[] = {
        { "A123456789123456789123456789123456789123456789",
          "A123456789123456789123456789123456789123456789" }, // same
        { "B123456789123456789123456789123456789123456789",
          "B123456089123456789123456789123456789123456789" }, // 8-th ch
        { "C123456789123456789123456789123456789123456789",
          "C123456789123456089123456789123456789123456789" }, // 17-th ch
        { "D123456789123456789123456789123456789123456789",
          "D123456789123456789123456789123456789123456780" }, // the last ch
    };

    const int test_iteration = 1000;
    clock_t start, end;
    double cpu_time_used;

    // Check the duration of original memcmp() with sample string pairs.
    for( size_t i = 0; i < sizeof(pairs) / sizeof(struct str_pair); ++i )
    {
        start = clock();

        for( size_t j = 0; j < test_iteration; ++j ) {
            // prevent being optimized out
            volatile int res = memcmp( pairs[i].s1, pairs[i].s2, strlen( pairs[i].s2 ) );
        }

        end = clock();
        cpu_time_used = ( (double) (end - start) ) / CLOCKS_PER_SEC;

        printf( "memcmp - %d-th test: %f sec\n", i + 1, cpu_time_used );
    }

    // Check the duration of secureboot_memcmp() with sample string pairs.
    for( size_t i = 0; i < sizeof(pairs) / sizeof(struct str_pair); ++i )
    {
        start = clock();

        for( size_t j = 0; j < test_iteration; ++j ) {
            // do secureboot_memcmp()
            // prevent being optimized out
            volatile int res = secureboot_memcmp( pairs[i].s1, pairs[i].s2, strlen( pairs[i].s2 ) );
        }

        end = clock();
        cpu_time_used = ( (double) (end - start) ) / CLOCKS_PER_SEC;

        printf( "secureboot_memcmp - %d-th test: %f sec\n", i + 1, cpu_time_used );
    }

    // No hard decision for this test yet.
    // A pass/fail condition can be different depends on the platform/HW.
    return 1;
}
