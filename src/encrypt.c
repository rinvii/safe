#include "crypto.h"
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
    unsigned char* buf = malloc(n);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, n, f) != n) {
        perror("read");
        fclose(f);
        free(buf);
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
    fprintf(stdout, "New password: ");
    fflush(stdout);
    if (!fgets(pw, sizeof pw, stdin)) {
        fprintf(stderr, "no password provided\n");
        free(buf);
        return 1;
    }
    size_t pwlen = strcspn(pw, "\n");
    pw[pwlen] = '\0';

    if (mlock(pw, sizeof pw) != 0)
        fprintf(stderr, "warning: mlock pw failed: %s\n", strerror(errno));

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (crypto_pwhash(key, sizeof key, pw, pwlen, hdr.salt, KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG) !=
        0) {
        secure_zero(pw, sizeof pw);
        free(buf);
        die("KDF failed");
    }

    // fprintf(stderr, "Derived key: ");
    // for (size_t i = 0; i < sizeof key; i++) fprintf(stderr, "%02x", key[i]);
    // fprintf(stderr, "\n");
    secure_zero(pw, sizeof pw);

    if (mlock(key, sizeof key) != 0)
        fprintf(stderr, "warning: mlock key failed: %s\n", strerror(errno));

    size_t csz = n + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char* ct = malloc(csz);
    if (!ct)
        die("oom allocating ciphertext");
    unsigned long long outlen = 0;

    // compress plaintext before encryption
    unsigned char* comp = NULL;
    size_t comp_len = 0;
    if (zlib_compress(buf, n, &comp, &comp_len) != 0)
        die("compression failed");

    // replace plaintext with compressed buffer
    free(buf);
    buf = comp;
    n = comp_len;
    hdr.flags |= 1; // mark compressed

    crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &outlen, buf, n, (const unsigned char*)&hdr,
                                               sizeof hdr, NULL, hdr.nonce, key);

    FILE* g = fopen(out, "wb");
    if (!g) {
        perror("open output");
        free(buf);
        free(ct);
        return 1;
    }
    fwrite(&hdr, 1, sizeof hdr, g);
    fwrite(ct, 1, outlen, g);
    fclose(g);

    secure_zero(key, sizeof key);
    secure_zero(buf, n);
    free(buf);
    free(ct);

    printf("Encrypted → %s (version=%d)\n", out, hdr.version);
    return 0;
}
