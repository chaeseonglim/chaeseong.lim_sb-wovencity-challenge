#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <assert.h>
#include "include/secureboot.h"

/**
 * @brief Do unit tests for newly added implementations.
 *        Those functions are not intended to run at runtime path.
 *        It's suitable to run them at a separate debug path or on sort of gtest with CI/CD.
 *
 * @return VERIFY_SUCCESS if successful else any other error code
 */
int do_unittest(void)
{
    int rc = VERIFY_GENERIC_ERROR;

    // Test secureboot_memcmp()
    printf("Testing secureboot_unittest_memcmp()..\n");
    if( ( rc = secureboot_unittest_memcmp() ) != VERIFY_SUCCESS ) {
        goto out;
    }

    // Test secureboot_rollback()
    printf("Testing secureboot_unittest_rollback()..\n");
    if( ( rc = secureboot_unittest_rollback() ) != VERIFY_SUCCESS ) {
        goto out;
    }

    // Test secureboot_sig_verify_ec()
    printf("Testing secureboot_unittest_ec()..\n");
    if( ( rc = secureboot_unittest_ec() ) != VERIFY_SUCCESS ) {
        goto out;
    }

out:
    return rc;
}

int main(int argc, char *argv[])
{
    uint8_t tmpbuf[TMPBUF_SZ];
    int rc = 0;

    if ( argc != 2 ){
        perror("wrong arguments");
        exit(VERIFY_GENERIC_ERROR);
    }

    /* do some unit tests first */
    rc = do_unittest();
    if( rc != VERIFY_SUCCESS ) {
        perror("unit test failed");
        exit(VERIFY_GENERIC_ERROR);
    }

    FILE *in_file = fopen(argv[1], "rb");
    if ( !in_file ){
        perror("fopen");
        exit(VERIFY_GENERIC_ERROR);
    }

    struct stat sb;
    if ( stat(argv[1], &sb) == -1 ){
        perror("stat");
        exit(VERIFY_GENERIC_ERROR);
    }

    uint8_t *file_content = malloc(sb.st_size);
    if ( file_content == NULL ) {
        perror("malloc");
        exit(VERIFY_GENERIC_ERROR);
    }

    fread(file_content, sb.st_size , 1, in_file);

    /* perform the verification */
    rc = secureboot_validate_image(file_content, tmpbuf, TMPBUF_SZ);

    assert( rc == VERIFY_SUCCESS);

    /* clean and exit */
    free(file_content);
    fclose(in_file);
    return VERIFY_SUCCESS;
}
