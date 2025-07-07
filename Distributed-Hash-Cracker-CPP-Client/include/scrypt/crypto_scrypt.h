#ifndef CRYPTO_SCRYPT_H_
#define CRYPTO_SCRYPT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
     * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
     * p, buflen) and write the result into buf.  The parameters r, p, and buflen
     * must satisfy 0 < r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter
     * N must be a power of 2 greater than 1.
     *
     * Return 0 on success; or -1 on error.
     */
    int crypto_scrypt(const uint8_t*, size_t, const uint8_t*, size_t, uint64_t,
        uint32_t, uint32_t, uint8_t*, size_t);

#ifdef __cplusplus
}
#endif

#endif /* !CRYPTO_SCRYPT_H_ */
