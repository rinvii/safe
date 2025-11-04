#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <sys/ioctl.h>
#endif

#include "utils.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <sys/random.h>

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

void secure_zero(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

ssize_t prompt_hidden_tty(char *buf, size_t cap, const char *prompt) {
    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (tty < 0) return -1;
    struct termios oldt, newt;
    if (tcgetattr(tty, &oldt)) { close(tty); return -1; }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(tty, TCSAFLUSH, &newt)) { close(tty); return -1; }
    write(tty, prompt, strlen(prompt));

    ssize_t n = 0;
    char *p = buf;
    while (n < (ssize_t)(cap - 1)) {
        ssize_t r = read(tty, p, 1);
        if (r <= 0) { n = -1; break; }
        if (*p == '\n' || *p == '\r') { *p = '\0'; break; }
        p++; n++;
    }

    tcsetattr(tty, TCSAFLUSH, &oldt);
    write(tty, "\n", 1);
    close(tty);
    if (n < 0) return -1;
    return n;
}

ssize_t read_all(int fd, void *buf, size_t size) {
    size_t off = 0;
    while (off < size) {
        ssize_t r = read(fd, (char*)buf + off, size - off);
        if (r <= 0) return r;
        off += (size_t)r;
    }
    return (ssize_t)off;
}

void deobf_xor(char *dst, const unsigned char *src, size_t n, unsigned long seed) {
    for (size_t i = 0; i < n; i++) {
        unsigned char mask = (unsigned char)((seed >> ((i % sizeof(seed)) * 8)) & 0xff);
        dst[i] = (char)(src[i] ^ mask);
    }
}

unsigned int seed_prng_from_build(void) {
    // combine time + pid + build seed for a runtime seed
    unsigned int s = (unsigned int)(time(NULL) ^ getpid() ^ (unsigned int)(BUILD_SEED & 0xffffffff));
    return s;
}

static uint64_t xorshift64star_state = 0;

static void seed_prng_once(void) {
#ifdef SAFE_DEBUG_PRNG_SEED
    if (xorshift64star_state == 0) xorshift64star_state = (uint64_t)SAFE_DEBUG_PRNG_SEED;
    return;
#endif
    if (xorshift64star_state != 0) return;
    uint64_t s = 0;
    if (getrandom(&s, sizeof s, 0) != (ssize_t)sizeof s) {
        s = ((uint64_t)time(NULL) << 32) ^ (uint64_t)getpid();
        s ^= (uint64_t)(uintptr_t)&s;
    }
    xorshift64star_state = s ? s : 0x9e3779b97f4a7c15ULL;
}

static inline uint64_t xorshift64star(void) {
    uint64_t x = xorshift64star_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xorshift64star_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

void subtle_jitter(void) {
    seed_prng_once();
    uint32_t tier = (uint32_t)(xorshift64star() & 0xffffffffU) % 100;
    if (tier < 95) {
        uint64_t r = xorshift64star() % 200000; // ns (0..200000)
        struct timespec jt = {0, (long)r};
        nanosleep(&jt, NULL);
    } else {
        uint64_t r = (xorshift64star() % 200) + 1; // ms (1..200)
        struct timespec jt = { (time_t)(r / 1000), (long)((r % 1000) * 1000000UL) };
        nanosleep(&jt, NULL);
    }
}

void add_syscall_noise(unsigned int calls) {
    for (unsigned int i = 0; i < calls; i++) {
        unsigned int choice = (unsigned int)(xorshift64star() & 0xffffffffU) % 10;
        switch (choice) {
            case 0: (void)getpid(); break;
            case 1: (void)getppid(); break;
            case 2: {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                break;
            }
            case 3: {
                uid_t u = getuid();
                (void)u;
                break;
            }
            case 4: {
                unsigned char tmp[8];
                int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
                if (fd >= 0) { read(fd, tmp, sizeof tmp); close(fd); }
                break;
            }
            case 5: {
                int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
                if (fd >= 0) { (void)write(fd, "", 0); close(fd); }
                break;
            }
            case 6: {
                char tmpl[] = "/tmp/noisexXXXXXX";
                int tfd = mkstemp(tmpl);
                if (tfd >= 0) {
                    unlink(tmpl);
                    char b[1] = {0};
                    write(tfd, b, 0);
                    close(tfd);
                }
                break;
            }
            case 7: {
                int d = dup(STDOUT_FILENO);
                if (d >= 0) close(d);
                break;
            }
            case 8: {
                (void)ioctl(STDOUT_FILENO, TCGETS, NULL);
                break;
            }
            default:
                (void)getppid();
                break;
        }
        subtle_jitter();
    }
}



int try_memfd_or_fallback(const char *name) {
    unsigned int s = seed_prng_from_build();
    char tmpname[32];
    snprintf(tmpname, sizeof tmpname, "%s_%08x", name, rand_r(&s));
    int fd = syscall(SYS_memfd_create, tmpname, 0);
    if (fd >= 0)
        return fd;

    // fallback: O_TMPFILE in /dev/shm or /tmp
    int tmpfd = -1;
    int dirs_to_try = 2;
    const char *dirs[2] = { "/dev/shm", "/tmp" };
    for (int i = 0; i < dirs_to_try; i++) {
        tmpfd = open(dirs[i], O_TMPFILE | O_RDWR | O_EXCL, 0700);
        if (tmpfd >= 0) break;
    }
    if (tmpfd >= 0) return tmpfd;

    // last resort mkstemp fallback with randomized name
    char tmpl[] = "/tmp/fallbackXXXXXX";
    tmpfd = mkstemp(tmpl);
    if (tmpfd >= 0) {
        unlink(tmpl);
        return tmpfd;
    }
    return -1;
}
