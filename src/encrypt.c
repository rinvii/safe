#include "crypto.h"
#include "sodium/utils.h"
#include "utils.h"
#include <errno.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#ifndef BUILD_SEED
#define BUILD_SEED 0UL
#endif
static const unsigned long build_seed = BUILD_SEED;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <plain-ELF>\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0)
        die("libsodium init failed");

    const char* in = argv[1];
    char out[4096];
    snprintf(out, sizeof(out), "%s.enc", in);

    FILE* f = fopen(in, "rb");
    if (!f) {
        perror("open input");
        return 1;
    }
    struct stat st;
    if (fstat(fileno(f), &st)) {
        perror("stat");
        fclose(f);
        return 1;
    }
    size_t n = st.st_size;
    unsigned char* buf = sodium_allocarray(n, 1);
    if (!buf)
        die("sodium_allocarray failed");
    if (sodium_mlock(buf, n) != 0) {
        fprintf(stderr, "warning: mlock buf failed\n");
    }
    if (fread(buf, 1, n, f) != n) {
        perror("read");
        fclose(f);
        sodium_free(buf);
        return 1;
    }
    fclose(f);

    // build encryption header
    struct enc_header hdr;
    fill_enc_header(&hdr, build_seed);

    // fprintf(stderr, "ENCRYPT DEBUG: BUILD_SEED=%lu\n", (unsigned long)BUILD_SEED);
    // fprintf(stderr, "hdr.magic =");
    // for (int i = 0; i < 8; i++) fprintf(stderr, " %02x", (unsigned char)hdr.magic[i]);
    // fprintf(stderr, "\nseed_marker =");
    // for (int i = 0; i < 8; i++) fprintf(stderr, " %02x", hdr.seed_marker[i]);
    // fprintf(stderr, "\n");

    // fprintf(stderr, "sizeof(struct enc_header) = %zu\n", sizeof(struct enc_header));

    // read passphrase
    char pw[4096];
    if (sodium_mlock(pw, sizeof pw) != 0)
        fprintf(stderr, "warning: mlock pw failed: %s\n", strerror(errno));

    fprintf(stdout, "New password: ");
    fflush(stdout);
    if (!fgets(pw, sizeof pw, stdin)) {
        fprintf(stderr, "no password provided\n");
        sodium_munlock(pw, sizeof pw);
        sodium_free(buf);
        return 1;
    }
    size_t pwlen = strcspn(pw, "\n");
    pw[pwlen] = '\0';

    unsigned char* key = sodium_malloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (!key)
        die("sodium_malloc key failed");
    if (crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES, pw, pwlen, hdr.salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG) != 0) {
        sodium_munlock(pw, sizeof pw);
        sodium_free(buf);
        die("KDF failed");
    }

    // fprintf(stderr, "Derived key: ");
    // for (size_t i = 0; i < sizeof key; i++) fprintf(stderr, "%02x", key[i]);
    // fprintf(stderr, "\n");
    sodium_munlock(pw, sizeof pw);
    sodium_stackzero(sizeof pw);

    if (sodium_mlock(key, sizeof key) != 0)
        fprintf(stderr, "warning: mlock key failed: %s\n", strerror(errno));

    size_t csz = n + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char* ct = sodium_malloc(csz);
    if (!ct)
        die("oom allocating ciphertext");
    unsigned long long outlen = 0;

    // compress plaintext before encryption
    unsigned char* comp = NULL;
    size_t comp_len = 0;
    if (zlib_compress(buf, n, &comp, &comp_len) != 0)
        die("compression failed");

    // replace plaintext with compressed buffer
    sodium_free(buf);
    buf = comp;
    n = comp_len;
    hdr.flags |= 1; // mark compressed

    crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &outlen, buf, n, (const unsigned char*)&hdr,
                                               sizeof hdr, NULL, hdr.nonce, key);

    FILE* g = fopen(out, "wb");
    if (!g) {
        perror("open output");
        sodium_free(buf);
        sodium_free(ct);
        return 1;
    }
    fwrite(&hdr, 1, sizeof hdr, g);
    fwrite(ct, 1, outlen, g);
    fclose(g);

    sodium_memzero(buf, n);
    sodium_free(buf);
    sodium_free(ct);
    sodium_free(key);

    printf("Encrypted → %s (version=%d)\n", out, hdr.version);
    return 0;
}
