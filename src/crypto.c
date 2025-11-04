#include "crypto.h"

void derive_magic(unsigned char out[CRYPTO_MAGIC_LEN],
                  const unsigned char seed_marker[8],
                  unsigned long build_seed, const char *ctx) {
    unsigned char buf[8 + 8 + 16];
    memset(buf, 0, sizeof buf);
    memcpy(buf, seed_marker, 8);
    for (size_t i = 0; i < 8; i++)
        buf[8 + i] = (unsigned char)((build_seed >> (i * 8)) & 0xff);
    size_t ctxlen = strlen(ctx);
    if (ctxlen > 16)
        ctxlen = 16;
    memcpy(buf + 8 + 8, ctx, ctxlen);


    // fprintf(stderr, "derive_magic DEBUG: ctx=\"%s\" build_seed=%lu\n", ctx, build_seed);
    // fprintf(stderr, "  buffer =");
    // for (size_t i = 0; i < sizeof(buf); i++)
    //     fprintf(stderr, " %02x", buf[i]);
    // fprintf(stderr, "\n");

    crypto_generichash(out, CRYPTO_MAGIC_LEN, buf, sizeof(buf), NULL, 0);
}



void fill_enc_header(struct enc_header *h, unsigned long seed) {
    h->version = CRYPTO_VERSION;
    h->flags = CRYPTO_FLAGS;
    for (int i = 0; i < 8; i++)
        h->seed_marker[i] = (unsigned char)((seed >> (i * 8)) & 0xFF);
    randombytes_buf(h->salt, sizeof h->salt);
    randombytes_buf(h->nonce, sizeof h->nonce);
    derive_magic((unsigned char *)h->magic, h->seed_marker, seed, "hdr");
}
