#pragma once
#include <stddef.h>
#include <sys/types.h>
#include <zlib.h>

#ifdef DEBUG
void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
#else
#define die(...)                                                                                   \
    do {                                                                                           \
        exit(1);                                                                                   \
    } while (0)
#endif

ssize_t prompt_hidden_tty(char* buf, size_t cap, const char* prompt);
ssize_t read_all(int fd, void* buf, size_t size);
void deobf_xor(char* dst, const unsigned char* src, size_t n, unsigned long seed);
void subtle_jitter(void);
void add_syscall_noise(unsigned int calls);
int try_memfd_or_fallback(const char* name);
unsigned int seed_prng_from_build(void);
int zlib_compress(const unsigned char* in, size_t in_len, unsigned char** out, size_t* out_len);
int zlib_decompress(const unsigned char* in, size_t in_len, unsigned char** out, size_t* out_len);
int self_attach_ptrace();
