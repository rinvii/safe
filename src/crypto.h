#pragma once
#include <sodium.h>
#include <stdint.h>
#include <string.h>

#define SAFE_VERSION "1.0"

#ifndef BUILD_SEED
#define BUILD_SEED 0UL
#endif

#define ENABLE_MLOCKALL 1
#define ENABLE_SEALING 1
#define ENABLE_ARGON2ID 1

#define CRYPTO_MAGIC_LEN 8
#define CRYPTO_VERSION 1
#define CRYPTO_FLAGS 0

// unified KDF params (for encrypt/decrypt consistency)
#define KDF_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define KDF_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE
#define KDF_ALG crypto_pwhash_ALG_ARGON2ID13

struct __attribute__((__packed__)) enc_header {
  char magic[CRYPTO_MAGIC_LEN];
  uint8_t version;
  uint8_t flags;
  unsigned char seed_marker[8];
  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
};

#define CRYPTO_MAGIC_LEN 8 // will derive 8-byte magic at runtime

void derive_magic(unsigned char out[CRYPTO_MAGIC_LEN],
                  const unsigned char seed_marker[8], unsigned long build_seed,
                  const char *ctx);

void fill_enc_header(struct enc_header *h, unsigned long seed);

_Static_assert(sizeof(struct enc_header) ==
                   CRYPTO_MAGIC_LEN + 1 + 1 + 8 + crypto_pwhash_SALTBYTES +
                       crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
               "enc_header padding mismatch");