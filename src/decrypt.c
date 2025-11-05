#include "crypto.h"
#include "utils.h"
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <out.enc> <output_file>\n", argv[0]);
        return 2;
    }

    const char* in_path = argv[1];
    const char* out_path = argv[2];

    if (sodium_init() < 0)
        die("libsodium init failed");

    int fd = open(in_path, O_RDONLY);
    if (fd < 0) {
        perror("open input");
        return 1;
    }

    /* --- read headers --- */
    char magic[CRYPTO_MAGIC_LEN];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (read_all(fd, magic, sizeof magic) != (ssize_t)sizeof magic)
        die("short file (magic)");
    if (read_all(fd, salt, sizeof salt) != (ssize_t)sizeof salt)
        die("short file (salt)");
    if (read_all(fd, ss_header, sizeof ss_header) != (ssize_t)sizeof ss_header)
        die("short file (stream header)");

    unsigned char expected_magic[CRYPTO_MAGIC_LEN];
    derive_magic(expected_magic, salt, BUILD_SEED, "out");

    if (memcmp(magic, expected_magic, CRYPTO_MAGIC_LEN) != 0)
        die("bad magic header (not a valid encrypted stream)");

    /* --- password input --- */
    char* pw = sodium_malloc(4096);
    if (!pw)
        die("sodium_malloc pw failed");

    if (sodium_mlock(pw, 4096) != 0)
        fprintf(stderr, "warning: mlock pw failed\n");

    if (prompt_hidden_tty(pw, 4096, "Password: ") < 0)
        die("no password entered");
    size_t pwlen = strcspn(pw, "\n");
    pw[pwlen] = '\0';

    /* --- derive key --- */
    unsigned char* key = sodium_malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    if (!key)
        die("sodium_malloc key failed");

    if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES, pw, pwlen, salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG) != 0)
        die("KDF failed (out of memory)");

    sodium_munlock(pw, 4096);
    sodium_free(pw);
    sodium_mprotect_readonly(key); /* key is now read-only */

    /* --- init stream --- */
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, ss_header, key) != 0)
        die("secretstream init_pull failed");

    int out_fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (out_fd < 0) {
        perror("open output");
        return 1;
    }

    /* --- decrypt chunks --- */
    for (;;) {
        uint8_t lenbuf[4];
        ssize_t got = read_all(fd, lenbuf, sizeof lenbuf);
        if (got == 0)
            break; /* EOF */
        if (got != (ssize_t)sizeof lenbuf)
            die("short file (chunk length)");

        uint32_t n = ((uint32_t)lenbuf[0] << 24) | ((uint32_t)lenbuf[1] << 16) |
                     ((uint32_t)lenbuf[2] << 8) | (uint32_t)lenbuf[3];
        if (n == 0)
            die("invalid chunk length 0");

        unsigned char* ct = sodium_allocarray(n, 1);
        if (!ct)
            die("sodium_allocarray ct failed");
        if (read_all(fd, ct, n) != (ssize_t)n)
            die("short file (ciphertext)");

        unsigned char* out = sodium_allocarray(n, 1);
        if (!out)
            die("sodium_allocarray out failed");

        unsigned long long outlen = 0;
        unsigned char tag = 0;

        if (crypto_secretstream_xchacha20poly1305_pull(&st, out, &outlen, &tag, ct,
                                                       (unsigned long long)n, NULL, 0) != 0)
            die("decryption failed (corrupted data or wrong password)");

        if (outlen > 0 && write(out_fd, out, outlen) != (ssize_t)outlen)
            die("write error");

        sodium_free(ct);
        sodium_free(out);

        if (tag & crypto_secretstream_xchacha20poly1305_TAG_FINAL)
            break;
    }

    sodium_mprotect_readwrite(key);
    sodium_free(key);

    close(fd);
    close(out_fd);

    sodium_stackzero(4096 + crypto_secretstream_xchacha20poly1305_KEYBYTES +
                     1024); // wipe stack traces of pw/pwlen/key locals
    return 0;
}
