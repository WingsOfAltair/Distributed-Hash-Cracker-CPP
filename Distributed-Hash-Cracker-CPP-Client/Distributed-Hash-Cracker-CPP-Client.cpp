#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string.hpp>    
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include "bcrypt/BCrypt.hpp"
#include <openssl/evp.h>    
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <filesystem>
#include "argon2/argon2.h"
#include <queue>
#include <cwctype> 
#include <boost/locale.hpp>
#include <codecvt>
#include <algorithm>
#include "../shared/AsyncLogger.h"
#include <scrypt/sodium.h>
#include "include/scrypt/crypto_scrypt.h"       
#include <openssl/sha.h>
#include <scrypt/libscrypt.h>     
#include "../Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/util/sysendian.h"

namespace asio = boost::asio;

using boost::asio::ip::tcp;

// Globals
asio::io_context io_context;
tcp::socket client_socket(io_context);

std::map<std::string, std::string> config;
std::map<std::string, std::string> mutation_list;

std::string WORDLIST_FILE = "";
std::string LINE_COUNT = "";
std::string SERVER_IP = "";
int SERVER_PORT = 0;
std::string SHOW_PROGRESS = "";
std::string AUTO_RECONNECT = "";
std::string MULTI_THREADED = "";
std::vector<std::string> MUTATION_RULES;
AsyncLogger logger("client.log");

bool match_found = false;

int total_lines;

std::mutex send_mutex;           // Mutex for sending messages to the server
std::atomic<bool> stop_processing(false);  // Global flag for stopping threads
std::atomic<bool> server_disconnected(false);

// Pointer to client socket, shared for reading thread and workers
boost::asio::ip::tcp::socket* global_socket_ptr = nullptr;

// Thread-safe message queue
std::queue<std::string> message_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define SHR(x, n)   (x >> n)
#define ROTR(x, n)  ((x >> n) | (x << (32 - n)))
#define S0(x)       (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)       (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)       (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)       (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)          \
    t0 = h + S1(e) + Ch(e, f, g) + k;       \
    t1 = S0(a) + Maj(a, b, c);          \
    d += t0;                    \
    h  = t0 + t1;

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k)            \
    RND(S[(64 - i) % 8], S[(65 - i) % 8],   \
        S[(66 - i) % 8], S[(67 - i) % 8],   \
        S[(68 - i) % 8], S[(69 - i) % 8],   \
        S[(70 - i) % 8], S[(71 - i) % 8],   \
        W[i] + k)

typedef struct SHA256Context2 {
    uint32_t state[8];
    uint32_t count[2];
    unsigned char buf[64];
} SHA256_CTX2;

typedef struct HMAC_SHA256Context {
    SHA256_CTX2 ictx;
    SHA256_CTX2 octx;
} HMAC_SHA256_CTX2;

inline void* safe_emalloc(size_t nmemb, size_t size, size_t offset = 0) {
    if (size != 0 && nmemb > (std::numeric_limits<size_t>::max() - offset) / size) {
        throw std::overflow_error("size_t overflow in safe_emalloc");
    }

    size_t total = nmemb * size + offset;

    void* p = std::malloc(total);
    if (!p) throw std::bad_alloc();
    return p;
}

static void blkcpy(uint8_t* dest, const uint8_t* src, size_t len) {
    std::memcpy(dest, src, len);
}

static void blkxor(uint8_t* dest, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

static uint64_t integerify(const uint8_t* B, size_t r) {
    const uint8_t* X = &B[(2 * r - 1) * 64]; // get last 64-byte block
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= ((uint64_t)X[i]) << (8 * i);
    }
    return result;
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static void
salsa20_8(uint8_t B[64])
{
    uint32_t B32[16];
    uint32_t x[16];
    size_t i;

    /* Convert little-endian values in. */
    for (i = 0; i < 16; i++)
        B32[i] = le32dec(&B[i * 4]);

    /* Compute x = doubleround^4(B32). */
    for (i = 0; i < 16; i++)
        x[i] = B32[i];
    for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x[4] ^= R(x[0] + x[12], 7);  x[8] ^= R(x[4] + x[0], 9);
        x[12] ^= R(x[8] + x[4], 13);  x[0] ^= R(x[12] + x[8], 18);

        x[9] ^= R(x[5] + x[1], 7);  x[13] ^= R(x[9] + x[5], 9);
        x[1] ^= R(x[13] + x[9], 13);  x[5] ^= R(x[1] + x[13], 18);

        x[14] ^= R(x[10] + x[6], 7);  x[2] ^= R(x[14] + x[10], 9);
        x[6] ^= R(x[2] + x[14], 13);  x[10] ^= R(x[6] + x[2], 18);

        x[3] ^= R(x[15] + x[11], 7);  x[7] ^= R(x[3] + x[15], 9);
        x[11] ^= R(x[7] + x[3], 13);  x[15] ^= R(x[11] + x[7], 18);

        /* Operate on rows. */
        x[1] ^= R(x[0] + x[3], 7);  x[2] ^= R(x[1] + x[0], 9);
        x[3] ^= R(x[2] + x[1], 13);  x[0] ^= R(x[3] + x[2], 18);

        x[6] ^= R(x[5] + x[4], 7);  x[7] ^= R(x[6] + x[5], 9);
        x[4] ^= R(x[7] + x[6], 13);  x[5] ^= R(x[4] + x[7], 18);

        x[11] ^= R(x[10] + x[9], 7);  x[8] ^= R(x[11] + x[10], 9);
        x[9] ^= R(x[8] + x[11], 13);  x[10] ^= R(x[9] + x[8], 18);

        x[12] ^= R(x[15] + x[14], 7);  x[13] ^= R(x[12] + x[15], 9);
        x[14] ^= R(x[13] + x[12], 13);  x[15] ^= R(x[14] + x[13], 18);
#undef R
    }

    /* Compute B32 = B32 + x. */
    for (i = 0; i < 16; i++)
        B32[i] += x[i];

    /* Convert little-endian values out. */
    for (i = 0; i < 16; i++)
        le32enc(&B[4 * i], B32[i]);
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
blockmix_salsa8(uint8_t* B, uint8_t* Y, size_t r)
{
    uint8_t X[64];
    size_t i;

    /* 1: X <-- B_{2r - 1} */
    blkcpy(X, &B[(2 * r - 1) * 64], 64);

    /* 2: for i = 0 to 2r - 1 do */
    for (i = 0; i < 2 * r; i++) {
        /* 3: X <-- H(X \xor B_i) */
        blkxor(X, &B[i * 64], 64);
        salsa20_8(X);

        /* 4: Y_i <-- X */
        blkcpy(&Y[i * 64], X, 64);
    }

    /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
    for (i = 0; i < r; i++)
        blkcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
    for (i = 0; i < r; i++)
        blkcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
}

/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
smix(uint8_t* B, size_t r, uint64_t N, uint8_t* V, uint8_t* XY)
{
    uint8_t* X = XY;
    uint8_t* Y = &XY[128 * r];
    uint64_t i;
    uint64_t j;

    /* 1: X <-- B */
    blkcpy(X, B, 128 * r);

    /* 2: for i = 0 to N - 1 do */
    for (i = 0; i < N; i++) {
        /* 3: V_i <-- X */
        blkcpy(&V[i * (128 * r)], X, 128 * r);

        /* 4: X <-- H(X) */
        blockmix_salsa8(X, Y, r);
    }

    /* 6: for i = 0 to N - 1 do */
    for (i = 0; i < N; i++) {
        /* 7: j <-- Integerify(X) mod N */
        j = integerify(X, r) & (N - 1);

        /* 8: X <-- H(X \xor V_j) */
        blkxor(X, &V[j * (128 * r)], 128 * r);
        blockmix_salsa8(X, Y, r);
    }

    /* 10: B' <-- X */
    blkcpy(B, X, 128 * r);
}

void be32enc(uint8_t* dst, uint32_t num) {
    dst[0] = (num >> 24) & 0xff;
    dst[1] = (num >> 16) & 0xff;
    dst[2] = (num >> 8) & 0xff;
    dst[3] = num & 0xff;
}

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void
SHA256_Init_SCRYPT(SHA256_CTX2* ctx)
{

    /* Zero bits processed so far */
    ctx->count[0] = ctx->count[1] = 0;

    /* Magic initialization constants */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
static void
be32dec_vect(uint32_t* dst, const unsigned char* src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        dst[i] = be32dec(src + i * 4);
}

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void
be32enc_vect(unsigned char* dst, const uint32_t* src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 4; i++)
        be32enc(dst + i * 4, src[i]);
}

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
SHA256_Transform2(uint32_t* state, const unsigned char block[64])
{
    uint32_t W[64];
    uint32_t S[8];
    uint32_t t0, t1;
    int i;

    /* 1. Prepare message schedule W. */
    be32dec_vect(W, block, 64);
    for (i = 16; i < 64; i++)
        W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

    /* 2. Initialize working variables. */
    memcpy(S, state, 32);

    /* 3. Mix. */
    RNDr(S, W, 0, 0x428a2f98);
    RNDr(S, W, 1, 0x71374491);
    RNDr(S, W, 2, 0xb5c0fbcf);
    RNDr(S, W, 3, 0xe9b5dba5);
    RNDr(S, W, 4, 0x3956c25b);
    RNDr(S, W, 5, 0x59f111f1);
    RNDr(S, W, 6, 0x923f82a4);
    RNDr(S, W, 7, 0xab1c5ed5);
    RNDr(S, W, 8, 0xd807aa98);
    RNDr(S, W, 9, 0x12835b01);
    RNDr(S, W, 10, 0x243185be);
    RNDr(S, W, 11, 0x550c7dc3);
    RNDr(S, W, 12, 0x72be5d74);
    RNDr(S, W, 13, 0x80deb1fe);
    RNDr(S, W, 14, 0x9bdc06a7);
    RNDr(S, W, 15, 0xc19bf174);
    RNDr(S, W, 16, 0xe49b69c1);
    RNDr(S, W, 17, 0xefbe4786);
    RNDr(S, W, 18, 0x0fc19dc6);
    RNDr(S, W, 19, 0x240ca1cc);
    RNDr(S, W, 20, 0x2de92c6f);
    RNDr(S, W, 21, 0x4a7484aa);
    RNDr(S, W, 22, 0x5cb0a9dc);
    RNDr(S, W, 23, 0x76f988da);
    RNDr(S, W, 24, 0x983e5152);
    RNDr(S, W, 25, 0xa831c66d);
    RNDr(S, W, 26, 0xb00327c8);
    RNDr(S, W, 27, 0xbf597fc7);
    RNDr(S, W, 28, 0xc6e00bf3);
    RNDr(S, W, 29, 0xd5a79147);
    RNDr(S, W, 30, 0x06ca6351);
    RNDr(S, W, 31, 0x14292967);
    RNDr(S, W, 32, 0x27b70a85);
    RNDr(S, W, 33, 0x2e1b2138);
    RNDr(S, W, 34, 0x4d2c6dfc);
    RNDr(S, W, 35, 0x53380d13);
    RNDr(S, W, 36, 0x650a7354);
    RNDr(S, W, 37, 0x766a0abb);
    RNDr(S, W, 38, 0x81c2c92e);
    RNDr(S, W, 39, 0x92722c85);
    RNDr(S, W, 40, 0xa2bfe8a1);
    RNDr(S, W, 41, 0xa81a664b);
    RNDr(S, W, 42, 0xc24b8b70);
    RNDr(S, W, 43, 0xc76c51a3);
    RNDr(S, W, 44, 0xd192e819);
    RNDr(S, W, 45, 0xd6990624);
    RNDr(S, W, 46, 0xf40e3585);
    RNDr(S, W, 47, 0x106aa070);
    RNDr(S, W, 48, 0x19a4c116);
    RNDr(S, W, 49, 0x1e376c08);
    RNDr(S, W, 50, 0x2748774c);
    RNDr(S, W, 51, 0x34b0bcb5);
    RNDr(S, W, 52, 0x391c0cb3);
    RNDr(S, W, 53, 0x4ed8aa4a);
    RNDr(S, W, 54, 0x5b9cca4f);
    RNDr(S, W, 55, 0x682e6ff3);
    RNDr(S, W, 56, 0x748f82ee);
    RNDr(S, W, 57, 0x78a5636f);
    RNDr(S, W, 58, 0x84c87814);
    RNDr(S, W, 59, 0x8cc70208);
    RNDr(S, W, 60, 0x90befffa);
    RNDr(S, W, 61, 0xa4506ceb);
    RNDr(S, W, 62, 0xbef9a3f7);
    RNDr(S, W, 63, 0xc67178f2);

    /* 4. Mix local working variables into global state */
    for (i = 0; i < 8; i++)
        state[i] += S[i];

    /* Clean the stack. */
    memset(W, 0, 256);
    memset(S, 0, 32);
    t0 = t1 = 0;
}

/* Add bytes into the hash */
void
SHA256_Update_SCRYPT(SHA256_CTX2* ctx, const void* in, size_t len)
{
    uint32_t bitlen[2];
    uint32_t r;
    const unsigned char* src = static_cast<const unsigned char*>(in);

    /* Number of bytes left in the buffer from previous updates */
    r = (ctx->count[1] >> 3) & 0x3f;

    /* Convert the length into a number of bits */
    bitlen[1] = ((uint32_t)len) << 3;
    bitlen[0] = (uint32_t)(len >> 29);

    /* Update number of bits */
    if ((ctx->count[1] += bitlen[1]) < bitlen[1])
        ctx->count[0]++;
    ctx->count[0] += bitlen[0];

    /* Handle the case where we don't need to perform any transforms */
    if (len < 64 - r) {
        memcpy(&ctx->buf[r], src, len);
        return;
    }

    /* Finish the current block */
    memcpy(&ctx->buf[r], src, 64 - r);
    SHA256_Transform2(ctx->state, ctx->buf);
    src += 64 - r;
    len -= 64 - r;

    /* Perform complete blocks */
    while (len >= 64) {
        SHA256_Transform2(ctx->state, src);
        src += 64;
        len -= 64;
    }

    /* Copy left over data into buffer */
    memcpy(ctx->buf, src, len);
}

static unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Add padding and terminating bit-count. */
static void
SHA256_Pad(SHA256_CTX2* ctx)
{
    unsigned char len[8];
    uint32_t r, plen;

    /*
     * Convert length to a vector of bytes -- we do this now rather
     * than later because the length will change after we pad.
     */
    be32enc_vect(len, ctx->count, 8);

    /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
    r = (ctx->count[1] >> 3) & 0x3f;
    plen = (r < 56) ? (56 - r) : (120 - r);
    SHA256_Update_SCRYPT(ctx, PAD, (size_t)plen);

    /* Add the terminating bit-count */
    SHA256_Update_SCRYPT(ctx, len, 8);
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void
SHA256_Final_SCRYPT(unsigned char digest[32], SHA256_CTX2* ctx)
{

    /* Add padding */
    SHA256_Pad(ctx);

    /* Write the hash */
    be32enc_vect(digest, ctx->state, 32);

    /* Clear the context state */
    memset((void*)ctx, 0, sizeof(*ctx));
}

/* Initialize an HMAC-SHA256 operation with the given key. */
void
HMAC_SHA256_Init_SCRYPT(HMAC_SHA256_CTX2* ctx, const void* _K, size_t Klen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    const unsigned char* K = static_cast<const unsigned char*>(_K);
    size_t i;

    /* If Klen > 64, the key is really SHA256(K). */
    if (Klen > 64) {
        SHA256_Init_SCRYPT(&ctx->ictx);
        SHA256_Update_SCRYPT(&ctx->ictx, K, Klen);
        SHA256_Final_SCRYPT(khash, &ctx->ictx);
        K = khash;
        Klen = 32;
    }

    /* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
    SHA256_Init_SCRYPT(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];

    SHA256_Update_SCRYPT(&ctx->ictx, pad, 64);

    /* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
    SHA256_Init_SCRYPT(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    SHA256_Update_SCRYPT(&ctx->octx, pad, 64);

    /* Clean the stack. */
    memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
void
HMAC_SHA256_Update_SCRYPT(HMAC_SHA256_CTX2* ctx, const void* in, size_t len)
{

    /* Feed data to the inner SHA256 operation. */
    SHA256_Update_SCRYPT(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
void
HMAC_SHA256_Final_SCRYPT(unsigned char digest[32], HMAC_SHA256_CTX2* ctx)
{
    unsigned char ihash[32];

    /* Finish the inner SHA256 operation. */
    SHA256_Final_SCRYPT(ihash, &ctx->ictx);

    /* Feed the inner hash to the outer SHA256 operation. */
    SHA256_Update_SCRYPT(&ctx->octx, ihash, 32);

    /* Finish the outer SHA256 operation. */
    SHA256_Final_SCRYPT(digest, &ctx->octx);

    /* Clean the stack. */
    memset(ihash, 0, 32);
}

void
PBKDF2_SHA256_SCRYPT(const uint8_t* passwd, size_t passwdlen, const uint8_t* salt,
    size_t saltlen, uint64_t c, uint8_t* buf, size_t dkLen)
{
    HMAC_SHA256_CTX2 PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    HMAC_SHA256_Init_SCRYPT(&PShctx, passwd, passwdlen);

    HMAC_SHA256_Update_SCRYPT(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX2));
        HMAC_SHA256_Update_SCRYPT(&hctx, ivec, 4);
        HMAC_SHA256_Final_SCRYPT(U, &hctx);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            HMAC_SHA256_Init_SCRYPT(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update_SCRYPT(&hctx, U, 32);
            HMAC_SHA256_Final_SCRYPT(U, &hctx);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX2));
}

// Function to read config/settings files
std::map<std::string, std::string> readFile(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    std::filesystem::path fullPath = std::filesystem::absolute(filename);
    std::ifstream configFile(fullPath);
    std::string line;

    if (configFile.is_open()) {
        while (std::getline(configFile, line)) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string key = line.substr(0, delimiterPos);
                std::string value = line.substr(delimiterPos + 1);
                configMap[key] = value;
            }
        }
        configFile.close();
    }
    else {
        std::cerr << "Unable to open config file: " << filename << std::endl;
    }
    return configMap;
}  

// Function to calculate hash using EVP
std::string calculate_hash(const std::string& hash_type, const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;

    const EVP_MD* md = nullptr;

    if (hash_type == "md5") {
        md = EVP_md5();
    }
    else if (hash_type == "sha1") {
        md = EVP_sha1();
    }
    else if (hash_type == "sha512") {
        md = EVP_sha512();
    }
    else if (hash_type == "sha384") {
        md = EVP_sha384();
    }
    else if (hash_type == "sha256") {
        md = EVP_sha256();
    }
    else if (hash_type == "sha224") {
        md = EVP_sha224();
    }
    else if (hash_type == "sha3-512") {
        md = EVP_sha3_512();
    }
    else if (hash_type == "sha3-384") {
        md = EVP_sha3_384();
    }
    else if (hash_type == "sha3-256") {
        md = EVP_sha3_256();
    }
    else if (hash_type == "sha3-224") {
        md = EVP_sha3_224();
    }
    else if (hash_type == "ripemd160") {
        md = EVP_ripemd160();
    }
    else {
        std::cerr << "Unsupported hash type: " << hash_type << std::endl;
        return "";
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, digest, &digest_length);
    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return oss.str();
}

std::string to_lowercase(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}  

std::string wstring_to_utf8(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

// Returns a trimmed copy of the input string
inline std::string trim(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(),
        [](unsigned char ch) { return std::isspace(ch); });

    auto end = std::find_if_not(s.rbegin(), s.rend(),
        [](unsigned char ch) { return std::isspace(ch); }).base();

    if (start >= end) return ""; // All whitespace or empty
    return std::string(start, end);
}

void splitAndAppend(const std::string& input, std::vector<std::string>& output) {
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, ',')) {
        std::stringstream subss(token);
        std::string word;

        while (subss >> word) {
            output.push_back(word);
        }
    }
}

int count_lines(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return 0;
    }

    auto start = std::chrono::high_resolution_clock::now();

    const size_t buffer_size = 1024 * 1024; // 1 MB buffer
    char* buffer = new char[buffer_size];
    std::uintmax_t line_count = 0;

    std::cout << "Counting lines in wordlist..." << std::endl;

    while (file) {
        file.read(buffer, buffer_size);
        std::streamsize bytes_read = file.gcount();
        for (std::streamsize i = 0; i < bytes_read; ++i) {
            if (buffer[i] == '\n') {
                ++line_count;
            }
        }
    }

    delete[] buffer;

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ms = end - start;

    std::cout << "Line count in wordlist: " + filepath + " is: " + std::to_string(++line_count) <<
        std::endl << "Counting elapsed time: " << duration_ms.count() << " ms." << std::endl;

    return line_count;
}

std::string applyRule(const std::wstring& password, const std::string& rule) {
    // Convert UTF-8 input to wide string for Unicode-safe processing
    std::wstring wresult = password;

    if (rule == "normal") {
        return wstring_to_utf8(password);
    }

    for (size_t i = 0; i < rule.size(); ++i) {
        char cmd = rule[i];

        switch (cmd) {
        case 'l': // Lowercase (Unicode-aware)
            std::transform(wresult.begin(), wresult.end(), wresult.begin(),
                [](wchar_t ch) { return std::towlower(ch); });
            continue;

        case 'u': // Uppercase (Unicode-aware)
            std::transform(wresult.begin(), wresult.end(), wresult.begin(),
                [](wchar_t ch) { return std::towupper(ch); });
            continue;

        case 'r': // Reverse
            std::reverse(wresult.begin(), wresult.end());
            continue;

        case 'c': // Capitalize first letter (Unicode-aware)
            if (!wresult.empty())
                wresult[0] = std::towupper(wresult[0]);
            continue;

        case 't': // Toggle case (Unicode-aware)
            for (wchar_t& ch : wresult) {
                if (std::iswlower(ch))
                    ch = std::towupper(ch);
                else if (std::iswupper(ch))
                    ch = std::towlower(ch);
                // else leave as is (e.g., digits, punctuation)
            }
            continue;

        case 'd': // Duplicate
            wresult += wresult;
            continue;

        case 's': // Substitute sXY (simple char replacement on wide chars)
            if (i + 2 < rule.size()) {
                // Convert src and dst from char (assumed ASCII) to wchar_t for substitution
                wchar_t src = static_cast<wchar_t>(rule[++i]);
                wchar_t dst = static_cast<wchar_t>(rule[++i]);
                for (wchar_t& ch : wresult) {
                    if (ch == src)
                        ch = dst;
                }
            }
            continue;

        case 'n': // Append Numbers (append ASCII digits as wide chars)
            wresult.append(boost::locale::conv::to_utf<wchar_t>("123", "UTF-8"));
            continue;

        case '1': // Prepends !
            wresult.insert(wresult.begin(), L'!');
            continue;

        case '2': // Postpends !   
            wresult.append(boost::locale::conv::to_utf<wchar_t>("!", "UTF-8"));
            continue;

        case '3': // Prepends @
            wresult.insert(wresult.begin(), L'@');
            continue;

        case '4': // Postpends @   
            wresult.append(boost::locale::conv::to_utf<wchar_t>("@", "UTF-8"));
            continue;

        case '5': // Replaces @ with 4
            for (auto& ch : wresult) {
                if (ch == L'@') {
                    ch = L'4';
                }
            }
            continue;

        case 'p': // L33tSpeak substitution - works only on ASCII letters
        {
            static const std::unordered_map<wchar_t, wchar_t> leet = {
                {L'a', L'@'}, {L'e', L'3'}, {L'i', L'1'}, {L'o', L'0'}, {L's', L'$'}, {L't', L'7'}
            };

            for (wchar_t& ch : wresult) {
                wchar_t lower = std::towlower(ch);
                auto it = leet.find(lower);
                if (it != leet.end()) {
                    ch = it->second;
                }
            }
            continue;
        }

        default:
            std::cerr << "Unsupported rule command: " << cmd << ", removing now.\n";
            MUTATION_RULES.erase(
                std::remove(MUTATION_RULES.begin(), MUTATION_RULES.end(), rule),
                MUTATION_RULES.end()
            );
            break;
        }
    }

    // Convert back to UTF-8 before returning
    return wstring_to_utf8(wresult);
}  

std::vector<unsigned char> base64_decode(const std::string& input) {
    std::string padded = input;
    while (padded.size() % 4 != 0) {
        padded.push_back('=');
    }

    BIO* bio = BIO_new_mem_buf(padded.data(), static_cast<int>(padded.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Disable line breaks
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> decoded(padded.size());
    int decodedLen = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));

    BIO_free_all(bio);

    if (decodedLen <= 0) {
        throw std::runtime_error("Base64 decode failed");
    }

    decoded.resize(decodedLen);
    return decoded;
}

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream tokenStream(s);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool is_base64_char(char c) {
    return (std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=');
}

bool is_base64_scrypt_hash(const std::string& hash) {
    // Check length roughly 43-44
    if (hash.length() < 43 || hash.length() > 44)
        return false;

    // Check all chars are valid base64 chars
    for (char c : hash) {
        if (!is_base64_char(c)) return false;
    }
    return true;
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

// validate Nodejs's scrypt hash format crypto.scrypt backed by OpenSSL
bool validate_scrypt(const std::string& password, const std::string& salt, 
    const std::string& expected_hex) {
    uint64_t N = 16384;
    uint32_t r = 8;
    uint32_t p = 1;
    size_t key_len = 64;

    std::vector<unsigned char> out(key_len);

    if (crypto_pwhash_scryptsalsa208sha256_ll(
        (const uint8_t*)password.data(), password.size(),
        (const uint8_t*)salt.data(), salt.size(),
        N, r, p, out.data(), key_len) != 0) {
        std::cerr << "scrypt failed (out-of-memory?)\n";
        return false;
    }

    std::string result_hex = to_hex(out.data(), key_len);
    return result_hex == expected_hex;
}

// Constant-time memory comparison
bool secure_compare(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/**
 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
 * must be a power of 2.
 *
 * Return 0 on success; or -1 on error.
 */
int
crypto_scrypt_php(const uint8_t* passwd, size_t passwdlen,
    const uint8_t* salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t* buf, size_t buflen)
{
    uint8_t* B = nullptr;
    uint8_t* V = nullptr;
    uint8_t* XY = nullptr;
    uint32_t i;

#if SIZE_MAX > UINT32_MAX
    if (buflen > (((uint64_t)(1) << 32) - 1) * 32) {
        errno = EFBIG;
        return -1;
    }
#endif
    if ((uint64_t)(r) * (uint64_t)(p) >= (1 << 30)) {
        errno = EFBIG;
        return -1;
    }
    if (((N & (N - 1)) != 0) || (N == 0)) {
        errno = EINVAL;
        return -1;
    }
    if ((r > SIZE_MAX / 128 / p) ||
#if SIZE_MAX / 256 <= UINT32_MAX
    (r > SIZE_MAX / 256) ||
#endif
        (N > SIZE_MAX / 128 / r)) {
        errno = ENOMEM;
        return -1;
    }

    try {
        B = static_cast<uint8_t*>(safe_emalloc(128, r * p, 0));
        XY = static_cast<uint8_t*>(safe_emalloc(256, r, 0));
        V = static_cast<uint8_t*>(safe_emalloc(128, r * N, 0));
    }
    catch (const std::exception&) {
        if (V) free(V);
        if (XY) free(XY);
        if (B) free(B);
        return -1;
    }

    // Step 1: PBKDF2(password, salt, 1, p * 128 * r) => B
    PBKDF2_SHA256_SCRYPT(passwd, passwdlen, salt, saltlen, 1, B, p * 128 * r);

    // Step 2: smix each block B_i
    for (i = 0; i < p; i++) {
        smix(&B[i * 128 * r], r, N, V, XY);
    }

    // Step 3: PBKDF2(password, B, 1, dkLen) => buf
    PBKDF2_SHA256_SCRYPT(passwd, passwdlen, B, p * 128 * r, 1, buf, buflen);

    free(V);
    free(XY);
    free(B);

    return 0;
}

// Hash a password using libsodium's low-level Scrypt and a custom salt.
// Returns the hash as a base64 string.
std::string scrypt_hash_password_libsodium(const std::string& password, const std::string& salt_str) {
    const std::size_t HASH_LEN = 32;
    const std::uint64_t N = 1 << 15;  // CPU cost
    const std::uint32_t r = 8;        // Memory cost
    const std::uint32_t p = 1;        // Parallelism

    unsigned char hash[HASH_LEN];

    const uint8_t* salt = reinterpret_cast<const uint8_t*>(salt_str.data());
    std::size_t salt_len = salt_str.size();

    if (crypto_pwhash_scryptsalsa208sha256_ll(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt, salt_len,
        N, r, p,
        hash, HASH_LEN) != 0) {
        throw std::runtime_error("Scrypt hash failed (likely out of memory)");
    }

    // Calculate base64 buffer size manually
    size_t base64_len = 4 * ((HASH_LEN + 2) / 3) + 1;

    std::vector<char> b64(base64_len);

    sodium_bin2base64(b64.data(), base64_len, hash, HASH_LEN, sodium_base64_VARIANT_ORIGINAL);

    return std::string(b64.data());
}

bool verify_libsodium_hash(const std::string& password, const std::string& stored_b64_hash, const std::string& salt_str) {
    std::string computed_b64_hash = scrypt_hash_password_libsodium(password, salt_str);

    // Constant-time comparison to avoid timing attacks
    return sodium_memcmp(computed_b64_hash.data(), stored_b64_hash.data(), stored_b64_hash.size()) == 0;
}

// Verify PHP-scrypt style hash: N$r$p$salt$hash
bool verify_php_scrypt_hash(const std::string& password, const std::string& fullHash) {
    auto parts = split(fullHash, '$');
    if (parts.size() != 5) return false;

    uint64_t N, r, p;
    try {
        N = std::stoull(parts[0]);
        r = std::stoul(parts[1]);
        p = std::stoul(parts[2]);
    }
    catch (...) {
        return false;
    }

    std::vector<unsigned char> salt = base64_decode(parts[3]);
    std::vector<unsigned char> targetHash = base64_decode(parts[4]);

    if (salt.size() != 16 || targetHash.size() != 32) {
        std::cerr << "Invalid salt or hash length\n";
        return false;
    }

    std::vector<unsigned char> computedHash(targetHash.size());

    int rc = crypto_scrypt_php(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(),
        N, r, p,
        computedHash.data(), computedHash.size());

    if (rc != 0) {
        std::cerr << "crypto_scrypt failed\n";
        return false;
    }

    auto print_hex = [](const std::string& label, const std::vector<unsigned char>& data) {
        std::cout << label << ": ";
        for (unsigned char c : data)
            printf("%02x", c);
        std::cout << "\n";
        };

    print_hex("Computed", computedHash);
    print_hex("Target  ", targetHash);
    print_hex("Salt    ", salt);

    return secure_compare(computedHash, targetHash);
}

// Verify PHP-scrypt style hash: N$r$p$salt$hash
bool verify_Colin_Percival_scrypt_hash(const std::string& password, const std::string& fullHash) {
    auto parts = split(fullHash, '$');
    if (parts.size() != 5) return false;

    uint64_t N = std::stoull(parts[0]);
    uint32_t r = std::stoul(parts[1]);
    uint32_t p = std::stoul(parts[2]);

    std::vector<unsigned char> salt = base64_decode(parts[3]);
    std::vector<unsigned char> targetHash = base64_decode(parts[4]);

    std::vector<unsigned char> computedHash(targetHash.size());

    int rc = crypto_scrypt(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(),
        N, r, p,
        computedHash.data(), computedHash.size());

    if (rc != 0) {
        std::cerr << "crypto_scrypt failed\n";
        return false;
    }

    auto print_hex = [](const std::string& label, const std::vector<unsigned char>& data) {
        std::cout << label << ": ";
        for (unsigned char c : data)
            printf("%02x", c);
        std::cout << "\n";
        };

    print_hex("Computed", computedHash);
    print_hex("Target  ", targetHash);
    print_hex("Salt", salt);
    std::cout << "Salt size: " << salt.size() << std::endl;          // Should be 16
    std::cout << "Target hash size: " << targetHash.size() << std::endl; // Should be 32

    return secure_compare(computedHash, targetHash);
}

bool verify_scrypt_hash_base64(const std::string& password, const std::string& salt_raw, const std::string& base64_hash) {
    const std::size_t HASH_LEN = 32;
    const std::uint64_t N = 2048;
    const std::uint32_t r = 8;
    const std::uint32_t p = 1;

    unsigned char computed_hash[HASH_LEN];
    unsigned char stored_hash[HASH_LEN];
    unsigned char salt[64]; // Use correct length if salt is binary

    // Use raw salt data directly
    std::memcpy(salt, salt_raw.data(), salt_raw.size());

    // Decode base64 hash into binary
    size_t decoded_len = 0;
    if (sodium_base642bin(stored_hash, HASH_LEN,
        base64_hash.c_str(), base64_hash.length(),
        nullptr, &decoded_len, nullptr,
        sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::cerr << "Failed to decode base64 hash" << std::endl;
        return false;
    }

    if (decoded_len != HASH_LEN) {
        std::cerr << "Hash length mismatch" << std::endl;
        return false;
    }

    // Compute hash
    if (crypto_pwhash_scryptsalsa208sha256_ll(
        reinterpret_cast<const uint8_t*>(password.c_str()), password.size(),
        salt, salt_raw.size(),  // match real salt size
        N, r, p,
        computed_hash, HASH_LEN) != 0) {
        std::cerr << "Out of memory while computing scrypt.\n";
        return false;
    }

    return sodium_memcmp(computed_hash, stored_hash, HASH_LEN) == 0;
}

// Main verify dispatcher
bool verify_scrypt_hash(const std::string& password, std::string& stored_salt_hex, const std::string& hash) {
    if (hash.empty()) return false;

    if (is_base64_scrypt_hash(hash)) {
        // Libsodium modular crypt format
        return verify_libsodium_hash(password, hash, stored_salt_hex) || verify_scrypt_hash_base64(password, stored_salt_hex, hash);
    }
    else if (std::count(hash.begin(), hash.end(), '$') == 4) {
        // PHP style: N$r$p$salt$hash
        return (verify_Colin_Percival_scrypt_hash(password, hash) || verify_php_scrypt_hash(password, hash));
    }
    else {
        return validate_scrypt(password, stored_salt_hex, hash);
    }
}

// Convert hex string to binary
std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

argon2_type detect_argon2_type(const std::string& encoded_hash) {
    if (encoded_hash.rfind("$argon2id$", 0) == 0) return Argon2_id;
    if (encoded_hash.rfind("$argon2i$", 0) == 0) return Argon2_i;
    if (encoded_hash.rfind("$argon2d$", 0) == 0) return Argon2_d;
    // Default fallback or invalid format
    return Argon2_id;
}

bool verify_argon2_encoded(const std::string& password, const std::string& encoded_hash) {
    argon2_type type = detect_argon2_type(encoded_hash);

    int result = argon2_verify(encoded_hash.c_str(), password.c_str(), password.size(), type);

    return result == ARGON2_OK;
}

// Function to report match found to the server
void report_match(const std::string& word, int line, boost::asio::ip::tcp::socket& socket, const std::string& wordlist_file) {
    match_found = true;
    std::ostringstream match_message_self;
    match_message_self << "Match found: " << word << " in wordlist: " << wordlist_file
        << ", line: " << line;

    std::string match_message = "MATCH:" + word + " in wordlist: " + wordlist_file + ", line: " + std::to_string(line);
    {
        logger.log(match_message);
        std::lock_guard<std::mutex> lock(send_mutex);
        boost::asio::write(socket, boost::asio::buffer(match_message + "\n"));
    }
    std::cout << match_message_self.str() << std::endl;
}

// Dedicated socket reader thread function
void socket_reader() {
    char temp[1024];
    boost::system::error_code ec;

    while (!stop_processing) {
        size_t bytes_received = global_socket_ptr->read_some(boost::asio::buffer(temp), ec);
        if (ec) {
            std::cerr << "Disconnected from server or error occurred: " << ec.message() << std::endl;
            stop_processing = true;
            server_disconnected.store(true);
            queue_cv.notify_all();  // Wake up main thread if it's waiting
            return;
        }

        std::string message(temp, bytes_received);

        if (message.find("STOP") == 0) {
            std::cout << "Received STOP command. Stopping processing.\n";
            stop_processing.store(true, std::memory_order_release);
            break;  // Exit the reader thread or continue to clean shutdown
        }

        if (message.find("reload") == 0) {
            std::cout << "Received Reload command. Disconnecting & reloading wordlist & mutations' options list.\n";

            config = readFile("config.ini");
            mutation_list = readFile("mutation_list.txt");

            SERVER_IP = config["SERVER_IP"];
            SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
            WORDLIST_FILE = config["WORDLIST_FILE"];
            LINE_COUNT = config["LINE_COUNT"];
            SHOW_PROGRESS = config["SHOW_PROGRESS"];
            MULTI_THREADED = config["MULTI_THREADED"];
            std::string MUTE_RULES = mutation_list["MUTATION_RULES"];

            if (!trim(MUTE_RULES).empty())
                splitAndAppend(MUTE_RULES, MUTATION_RULES);

            if (to_lowercase(MULTI_THREADED) == "true")
            {
                if (to_lowercase(LINE_COUNT) == "auto")
                {
                    total_lines = -1;
                }
                else {
                    total_lines = std::stoi(LINE_COUNT);
                }

                if (total_lines == -1) {
                    total_lines = count_lines(WORDLIST_FILE);
                }
            }
            else {
                total_lines = -1;
            }

            stop_processing.store(true, std::memory_order_release);
            client_socket.close();
            server_disconnected.store(true);
            queue_cv.notify_all();  // Wake up main thread if it's waiting
            break;
        }

        size_t newline_pos;
        while ((newline_pos = message.find('\n')) != std::string::npos) {
            std::string line = message.substr(0, newline_pos);   // Extract one line
            message.erase(0, newline_pos + 1);                    // Remove extracted line + '\n' from the original string
            boost::algorithm::trim(line);                         // Trim the extracted line

            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                message_queue.push(line);
            }
            queue_cv.notify_one();
        }
    }
}

// Process chunk - NO socket reading here!
void process_chunk(int start_line, int end_line, const std::string& hash_type, const std::string& hash_value, std::string& salt) {
    std::ifstream wordlist(WORDLIST_FILE, std::ios::binary);
    if (!wordlist.is_open()) {
        std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
        return;
    }

    // Skip UTF-8 BOM if present
    char bom[3] = { 0 };
    wordlist.read(bom, 3);
    if (!(bom[0] == '\xEF' && bom[1] == '\xBB' && bom[2] == '\xBF')) {
        wordlist.seekg(0);  // rewind if no BOM
    }
    std::string utf8_word;
    int current_line = 0;

    // Skip lines before the chunk
    while (current_line < start_line && std::getline(wordlist, utf8_word)) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        ++current_line;
    }

    // Process assigned chunk
    while (current_line < end_line && std::getline(wordlist, utf8_word)) { 
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        std::wstring utf8_word_str_w = boost::locale::conv::to_utf<wchar_t>(utf8_word, "UTF-8");
        boost::algorithm::trim_right_if(utf8_word_str_w, boost::is_any_of("\r\n"));
        std::string utf8_word_str= wstring_to_utf8(utf8_word_str_w);

        try {

            if (MUTATION_RULES.size() > 0)
            {
                for (const std::string& rule : MUTATION_RULES) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    std::string mutated = applyRule(utf8_word_str_w, rule);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Rule: " << rule << " = " << mutated << std::endl;

                    if (to_lowercase(hash_type) == "bcrypt") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (BCrypt::validatePassword(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else if (to_lowercase(hash_type) == "scrypt") {
                        std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_scrypt_hash(mutated, salt, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else if (to_lowercase(hash_type) == "argon2") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_argon2_encoded(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else {
                        std::string input_with_salt = mutated + salt;
                        std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Calculated password: " << mutated << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                        if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                }
            }
            else {
                if (to_lowercase(hash_type) == "bcrypt") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (BCrypt::validatePassword(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else if (to_lowercase(hash_type) == "scrypt") {
                    std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_scrypt_hash(utf8_word_str, salt, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else if (to_lowercase(hash_type) == "argon2") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_argon2_encoded(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else {
                    std::string input_with_salt = utf8_word_str + salt;
                    std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Calculated password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                    if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
            }
            current_line++;
        }
        catch (const std::exception& err) { 
            std::ostringstream oss;
            oss << "Error occurred during processing word: " << utf8_word_str
                << " on line: " << current_line << "." << std::endl
                << err.what();
            std::string errText = oss.str();
            std::cerr << errText << std::endl;
            logger.log(errText);
            current_line++;
        }
    }
}

// Process chunk - NO socket reading here!
void process_chunk_single_threaded(const std::string& hash_type, const std::string& hash_value, std::string& salt) {
    std::ifstream wordlist(WORDLIST_FILE, std::ios::binary);
    if (!wordlist.is_open()) {
        std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
        return;
    }

    // Skip UTF-8 BOM if present
    char bom[3] = { 0 };
    wordlist.read(bom, 3);
    if (!(bom[0] == '\xEF' && bom[1] == '\xBB' && bom[2] == '\xBF')) {
        wordlist.seekg(0);  // rewind if no BOM
    }
    std::string utf8_word;
    int current_line = 0;

    // Process assigned chunk
    while (std::getline(wordlist, utf8_word)) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        std::wstring utf8_word_str_w = boost::locale::conv::to_utf<wchar_t>(utf8_word, "UTF-8");
        boost::algorithm::trim_right_if(utf8_word_str_w, boost::is_any_of("\r\n"));
        std::string utf8_word_str = wstring_to_utf8(utf8_word_str_w);

        try {

            if (MUTATION_RULES.size() > 0)
            {
                for (const std::string& rule : MUTATION_RULES) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    std::string mutated = applyRule(utf8_word_str_w, rule);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Rule: " << rule << " = " << mutated << std::endl;

                    if (to_lowercase(hash_type) == "bcrypt") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (BCrypt::validatePassword(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else if (to_lowercase(hash_type) == "scrypt") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_scrypt_hash(mutated, salt, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else if (to_lowercase(hash_type) == "argon2") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_argon2_encoded(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else {
                        std::string input_with_salt = mutated + salt;
                        std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Calculated password: " << mutated << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                        if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                }
            }
            else {
                if (to_lowercase(hash_type) == "bcrypt") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (BCrypt::validatePassword(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else if (to_lowercase(hash_type) == "scrypt") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_scrypt_hash(utf8_word_str, salt, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                } 
                else if (to_lowercase(hash_type) == "argon2") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_argon2_encoded(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else {
                    std::string input_with_salt = utf8_word_str + salt;
                    std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Calculated password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                    if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
            }
            current_line++;
        }
        catch (const std::exception& err) {
            std::ostringstream oss;
            oss << "Error occurred during processing word: " << utf8_word_str
                << " on line: " << current_line << "." << std::endl
                << err.what();
            std::string errText = oss.str();
            std::cerr << errText << std::endl;
            logger.log(errText);
            current_line++;
        }
    }
}

bool udp_ping(const std::string& ip, int port, int timeout_ms = 1000) {
    using namespace boost::asio;
    boost::asio::io_context io;

    // Replace the problematic line with the following:  
    boost::asio::ip::address server_address = boost::asio::ip::make_address(ip);  
    ip::udp::socket socket(io);
    boost::system::error_code ec;

    socket.open(ip::udp::v4(), ec);
    if (ec) return false;

    boost::asio::ip::udp::endpoint server_endpoint(server_address, port);
    ip::udp::endpoint sender_endpoint;

    // Send "ping"
    std::string message = "ping";
    socket.send_to(buffer(message), server_endpoint, 0, ec);
    if (ec) return false;

    // Set receive timeout
    socket.non_blocking(true);
    char reply[128];
    std::size_t len = 0;

    auto start = std::chrono::steady_clock::now();
    while (true) {
        ec.clear();
        len = socket.receive_from(buffer(reply), sender_endpoint, 0, ec);

        if (!ec && len > 0) {
            std::string response(reply, len);
            return response == "pong";  // or whatever your expected response is
        }

        if ((std::chrono::steady_clock::now() - start) > std::chrono::milliseconds(timeout_ms)) {
            return false;  // timeout
        }

        // Yield to avoid CPU burn
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Base64 encode a byte vector using libsodium
std::string base64Encode(const std::vector<uint8_t>& data) {
    size_t len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> encoded(len);
    sodium_bin2base64(encoded.data(), len,
        data.data(), data.size(),
        sodium_base64_VARIANT_ORIGINAL);
    return std::string(encoded.data());
}

// Generate deterministic salt from string like PHP
std::vector<uint8_t> generate_salt_from_string(const std::string& input) {
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256())); // 32 bytes for SHA256
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP SHA256 digest failed");
    }

    EVP_MD_CTX_free(mdctx);

    // Return first 16 bytes as salt
    return std::vector<uint8_t>(hash.begin(), hash.begin() + 16);
}

void test_php_crypto_scrypt()
{
    std::string password = "jesperhp10";
    std::string salt_str = "123";
    uint64_t N = 16384; // Must be power of 2
    uint32_t r = 8;
    uint32_t p = 1;
    size_t dkLen = 32; // Length of derived key (same as PHP output)

    // Output buffer                                                 
    std::vector<uint8_t> salt2 = generate_salt_from_string(salt_str);
    std::string salt_base64 = base64Encode(salt2);
    std::vector<uint8_t> derivedKey(dkLen);

    // Call scrypt
    int rc = crypto_scrypt_php(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt2.data(), salt2.size(),
        N, r, p,
        derivedKey.data(), dkLen
    );

    if (rc != 0) {
        std::cerr << "scrypt failed with error code: " << rc << std::endl;
        return;// originally return 1;
    }

    std::cout << N << "$" << r << "$" << p << "$"
        << base64Encode(salt2) << "$"
        << base64Encode(derivedKey) << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Libsodium init failed\n";
        return 1;
    }
    test_php_crypto_scrypt();
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::locale::global(boost::locale::generator().generate("en_US.UTF-8"));
    std::wcin.imbue(std::locale());
    std::wcout.imbue(std::locale());

    // Read configuration from the file
    config = readFile("config.ini");
    mutation_list = readFile("mutation_list.txt");

    SERVER_IP = config["SERVER_IP"];
    SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
    WORDLIST_FILE = config["WORDLIST_FILE"];
    LINE_COUNT = config["LINE_COUNT"];
    SHOW_PROGRESS = config["SHOW_PROGRESS"];
    MULTI_THREADED = config["MULTI_THREADED"];

    if (to_lowercase(MULTI_THREADED) == "true")
    {
        if (to_lowercase(LINE_COUNT) == "auto")
        {
            total_lines = -1;
        }
        else {
            total_lines = std::stoi(LINE_COUNT);
        }
    }
    else {
        total_lines = -1;
    }

    std::string MUTE_RULES = mutation_list["MUTATION_RULES"];

    if (!trim(MUTE_RULES).empty())
        splitAndAppend(MUTE_RULES, MUTATION_RULES);

    // Attempt to check if server is online or offline.
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(SERVER_IP, std::to_string(SERVER_PORT));

    if (udp_ping(SERVER_IP, SERVER_PORT))
    {
        std::cout << "Server is online." << std::endl;
        stop_processing.store(false);
        server_disconnected.store(true);
    }
    else {
        std::cerr << "Server is offline or the ip/port combination is incorrect." << std::endl;
        server_disconnected.store(true);
    }

    AUTO_RECONNECT = "true";

    std::ifstream wordlist(WORDLIST_FILE);

    if (to_lowercase(MULTI_THREADED) == "true")
    {
        if (total_lines == -1)
        {
            // Count total lines in wordlist
            if (!wordlist.is_open()) {
                std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
                logger.log("Failed to open wordlist file: " + WORDLIST_FILE);
                return 0;
            }

            total_lines = count_lines(WORDLIST_FILE);
            wordlist.close();
        }
    }

    while (to_lowercase(AUTO_RECONNECT) == "true") {
        AUTO_RECONNECT = config["AUTO_RECONNECT"];
        // Attempt to connect to the server in a loop
        while (server_disconnected && ((to_lowercase(MULTI_THREADED) == "true" && total_lines >= 0) || (to_lowercase(MULTI_THREADED) == "false" && total_lines == -1))) {
            try {
                asio::connect(client_socket, endpoints);
                server_disconnected.store(false);
                stop_processing.store(false);
                std::cout << "Connected to server." << std::endl;
                break; // Successfully connected
            }
            catch (std::exception& e) {
                std::cerr << "Connection failed: " << e.what() << ". Retrying..." << std::endl;
                boost::this_thread::sleep_for(boost::chrono::seconds(1));
            }
        }

        if (to_lowercase(MULTI_THREADED) == "true") {
            if (total_lines == -1)
            {
                std::string message = "Shutting down due to incorrect wordlist file.";
                std::cout << message << std::endl;
                logger.log(message);
                return 0;
            }
        }

        global_socket_ptr = &client_socket;

        while (!server_disconnected && ((to_lowercase(MULTI_THREADED) == "true" && total_lines >= 0) || (to_lowercase(MULTI_THREADED) == "false" && total_lines == -1))) {
            match_found = false;
            stop_processing.store(false);
            boost::thread reader_thread(socket_reader);
            std::string readyStr = "Ready to accept new requests.";
            std::cout << readyStr << std::endl;

            // Send ready message to server
            asio::write(client_socket, asio::buffer(readyStr + "\n"));

            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [] { return !message_queue.empty() || server_disconnected.load(); });

			if (server_disconnected.load()) {
                stop_processing.store(false);
				continue; // Exit the loop if server is disconnected
			}

            std::string message = message_queue.front();
            message_queue.pop();
            lock.unlock();

            if (message.find("STOP") == 0) {
                std::cout << "Received STOP command. Stopping processing.\n";
                stop_processing = true;
                continue;
            }

            size_t delimiter_pos = message.find(':');

            if (delimiter_pos == std::string::npos) {
                std::cerr << "Malformed request from server: " << message << std::endl;
                continue;
            }

            std::string hash_type = message.substr(0, delimiter_pos);
            std::string hash_value, salt;
            size_t second_delimiter_pos = message.find(':', delimiter_pos + 1);

            if (second_delimiter_pos != std::string::npos) {
                hash_value = message.substr(delimiter_pos + 1, second_delimiter_pos - delimiter_pos - 1);
                salt = message.substr(second_delimiter_pos + 1);
            }
            else {
                hash_value = message.substr(delimiter_pos + 1);
                salt = "";
            }

			if (hash_type.empty() || hash_value.empty()) {
				std::cerr << "Invalid request from server: " << message << std::endl;
				continue;
			}

            if (to_lowercase(MULTI_THREADED) == "true")
            {
                int num_threads = boost::thread::hardware_concurrency();
                if (num_threads == 0) num_threads = 2; // fallback to 2 if undetectable   
                if (total_lines < num_threads) {
                    num_threads = total_lines; // avoid having more threads than lines
                }
                int chunk_size = total_lines / num_threads;
                int remainder = total_lines % num_threads; // for better load balancing

                int start_line = 0;
                // Start worker threads
                std::vector<boost::thread> threads;
                for (int i = 0; i < num_threads; ++i) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    int lines_for_this_thread = chunk_size + (i < remainder ? 1 : 0);
                    int end_line = start_line + lines_for_this_thread;
                    threads.emplace_back(process_chunk, start_line, end_line, hash_type, hash_value, salt);
                    start_line = end_line;
                }

                // Join worker threads
                for (auto& t : threads) {
                    if (t.joinable()) t.join();
                }
            }
            else {
                process_chunk_single_threaded(hash_type, hash_value, salt);
            }

            // Only send NO_MATCH once if no password was found
            if (!match_found && (message.find("STOP") == 0)) {
                std::lock_guard<std::mutex> lock(send_mutex);
                boost::asio::write(client_socket, boost::asio::buffer("NO_MATCH\n"));
            }
        }
    }
    client_socket.close();
    return 0;
}