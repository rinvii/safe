#define _GNU_SOURCE
#include "crypto.h"
#include "utils.h"
#include <fcntl.h>
#include <sodium.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>

#ifdef EMBED_BLOB
extern const unsigned char _binary_target_enc_start[];
extern const unsigned char _binary_target_enc_end[];
#endif

#ifndef BUILD_SEED
#define BUILD_SEED 0UL
#endif
static const unsigned long build_seed = BUILD_SEED;

static ssize_t prompt_line_stdin(char *buf, size_t cap, const char *prompt) {
  fputs(prompt, stdout);
  fflush(stdout);
  if (!fgets(buf, (int)cap, stdin))
    return -1;
  size_t n = strcspn(buf, "\n");
  buf[n] = '\0';
  return (ssize_t)n;
}

static char **split_ws(char *line, int *outc) {
  int cap = 8, c = 0;
  char **v = calloc((size_t)cap + 1, sizeof(char *));
  char *s = line;
  while (*s) {
    while (*s == ' ' || *s == '\t')
      s++;
    if (!*s)
      break;
    char *st = s;
    while (*s && *s != ' ' && *s != '\t')
      s++;
    int L = (int)(s - st);
    char *t = malloc((size_t)L + 1);
    memcpy(t, st, (size_t)L);
    t[L] = '\0';
    if (c == cap) {
      cap *= 2;
      v = realloc(v, ((size_t)cap + 1) * sizeof(char *));
    }
    v[c++] = t;
  }
  v[c] = NULL;
  *outc = c;
  return v;
}

#ifndef SYS_memfd_create
#if defined(__x86_64__)
#define SYS_memfd_create 319
#elif defined(__i386__)
#define SYS_memfd_create 356
#else
#error "Define SYS_memfd_create for your arch"
#endif
#endif
static int memfd_create_wrap(const char *name, unsigned int flags) {
  return syscall(SYS_memfd_create, name, flags);
}

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static int decrypt_target_to_memfd(const unsigned char *enc_bytes,
                                   size_t enc_sz, int *out_mfd,
                                   char **out_pw, size_t *out_pwlen) {
    *out_mfd = -1;

    if (enc_sz < sizeof(struct enc_header) + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        die("encrypted blob too small");

    struct enc_header hdr;
    memcpy(&hdr, enc_bytes, sizeof hdr);
    unsigned char expected_magic[CRYPTO_MAGIC_LEN];
    // fprintf(stderr, "HDR DEBUG: launcher BUILD_SEED=%lu\n", (unsigned long)BUILD_SEED);
    derive_magic(expected_magic, hdr.seed_marker, BUILD_SEED, "hdr");

// fprintf(stderr, "hdr.magic =");
// for (int i = 0; i < 8; i++) fprintf(stderr, " %02x", (unsigned char)hdr.magic[i]);
// fprintf(stderr, "\nexpected =");
// for (int i = 0; i < 8; i++) fprintf(stderr, " %02x", (unsigned char)expected_magic[i]);
// fprintf(stderr, "\nseed_marker =");
// for (int i = 0; i < 8; i++) fprintf(stderr, " %02x", hdr.seed_marker[i]);
// fprintf(stderr, "\nBUILD_SEED=%lu\n", (unsigned long)BUILD_SEED);
    
    if (memcmp(hdr.magic, expected_magic, CRYPTO_MAGIC_LEN) != 0)
        die("bad magic in target.enc");
    if (hdr.version != CRYPTO_VERSION)
        die("unsupported format version");

    const unsigned char *ct = enc_bytes + sizeof hdr;
    size_t ctsz = enc_sz - sizeof hdr;

    enum { MAXPW = 4096 };
    char *pw = NULL;
    size_t pwlen = 0;
    bool pw_allocated_here = false;

    if (out_pw && *out_pw && *out_pwlen > 0) {
        pw = *out_pw;
        pwlen = *out_pwlen;
    } else {
        pw = malloc(MAXPW);
        if (!pw)
            die("oom");
        if (mlock(pw, MAXPW) != 0) {
            // fprintf(stderr, "warning: mlock pw failed: %s\n", strerror(errno));
        }

        ssize_t got = prompt_hidden_tty(pw, MAXPW, "");
        if (got <= 0) {
            secure_zero(pw, MAXPW);
            munlock(pw, MAXPW);
            free(pw);
            die("no password");
        }
        if (pw[got - 1] == '\n')
            got--;
        pw[got] = '\0';
        pwlen = (size_t)got;
        pw_allocated_here = true;
    }

    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (mlock(key, sizeof key) != 0) {
        // fprintf(stderr, "warning: mlock key failed: %s\n", strerror(errno));
    }

    if (crypto_pwhash(key, sizeof key, pw, pwlen, hdr.salt,
                      KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG) != 0) {
        secure_zero(pw, MAXPW);
        munlock(pw, MAXPW);
        if (pw_allocated_here)
            free(pw);
        die("KDF failed");
    }

    // if caller didn’t need password, wipe it immediately
    if (!(out_pw && *out_pw && *out_pwlen)) {
        secure_zero(pw, MAXPW);
        munlock(pw, MAXPW);
        if (pw_allocated_here)
            free(pw);
    }

    unsigned char *pt = malloc(ctsz);
    if (!pt) {
        secure_zero(key, sizeof key);
        munlock(key, sizeof key);
        die("oom");
    }
    if (mlock(pt, ctsz) != 0) {
        // fprintf(stderr, "warning: mlock plaintext failed: %s\n", strerror(errno));
    }

    unsigned long long ptsz = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &ptsz, NULL, ct, ctsz, (const unsigned char *)&hdr,
            sizeof hdr, hdr.nonce, key) != 0) {
        secure_zero(key, sizeof key);
        munlock(key, sizeof key);
        secure_zero(pt, ctsz);
        munlock(pt, ctsz);
        free(pt);
        die("decryption failed (wrong password or tampered header)");
    }

    secure_zero(key, sizeof key);
    munlock(key, sizeof key);

    if (ptsz < 4 || !(pt[0] == 0x7f && pt[1] == 'E' && pt[2] == 'L' && pt[3] == 'F')) {
        secure_zero(pt, ptsz);
        munlock(pt, ptsz);
        free(pt);
        die("plaintext not ELF");
    }

    unsigned int rseed = seed_prng_from_build();
    add_syscall_noise(rand_r(&rseed) % 5 + 1);
    int mfd = try_memfd_or_fallback("elf");
    add_syscall_noise(rand_r(&rseed) % 5);
    if (mfd < 0) {
        perror("memfd_create");
        secure_zero(pt, ptsz);
        munlock(pt, ptsz);
        free(pt);
        exit(1);
    }

    ssize_t w = write(mfd, pt, ptsz);
    if (w != (ssize_t)ptsz) {
        perror("write memfd");
        close(mfd);
        secure_zero(pt, ptsz);
        munlock(pt, ptsz);
        free(pt);
        exit(1);
    }

    add_syscall_noise(rand() % 2);

#ifdef F_ADD_SEALS
    int seals = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL;
    if (fcntl(mfd, F_ADD_SEALS, seals) != 0) {
        // fprintf(stderr, "warning: memfd seals not supported: %s\n", strerror(errno));
    }
#endif

    secure_zero(pt, ptsz);
    munlock(pt, ptsz);
    free(pt);

    lseek(mfd, 0, SEEK_SET);
    *out_mfd = mfd;
    return 0;
}




static volatile sig_atomic_t keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
}

static void capture_and_encrypt_output(int read_fd, const char *outfile,
                                       const unsigned char *outkey,
                                       const unsigned char *outsalt) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (mlock(key, sizeof key) != 0) {
        // fprintf(stderr, "warning: mlock key failed: %s\n", strerror(errno));
    }
    unsigned char ss_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    int fd = -1;
    ssize_t r;

    fd = open(outfile, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) {
        perror("open outfile");
        close(read_fd);
        secure_zero(key, sizeof key);
        munlock(key, sizeof key);
        secure_zero(salt, sizeof salt);
        exit(1);
    }

    // write the header only once if it's the first chunk being written
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == 0) {
        memcpy(key, outkey, sizeof key);
        memcpy(salt, outsalt, sizeof salt);

        crypto_secretstream_xchacha20poly1305_init_push(&st, ss_header, key);

        unsigned char out_magic[CRYPTO_MAGIC_LEN];
        // fprintf(stderr, "OUT DEBUG: launcher BUILD_SEED=%lu\n", (unsigned long)BUILD_SEED);
        derive_magic(out_magic, outsalt, build_seed, "out");
        write(fd, out_magic, CRYPTO_MAGIC_LEN);     // Magic header
        write(fd, salt, sizeof(salt));              // Write salt
        write(fd, ss_header, sizeof(ss_header));    // Stream header
    }

    unsigned char inbuf[8192];
    unsigned char outbuf[8192 + crypto_secretstream_xchacha20poly1305_ABYTES];
    mlock(inbuf, sizeof inbuf);
    mlock(outbuf, sizeof outbuf);
    while ((r = read(read_fd, inbuf, sizeof inbuf)) > 0) {
        unsigned long long outlen = 0;

        crypto_secretstream_xchacha20poly1305_push(
            &st, outbuf, &outlen, inbuf, (unsigned long long)r, NULL, 0, 0);

        uint32_t be_len = (uint32_t)outlen;
        unsigned char lenbuf[4] = {
            (be_len >> 24) & 0xff,
            (be_len >> 16) & 0xff,
            (be_len >> 8) & 0xff,
            be_len & 0xff
        };

        // write length of chunk (4 bytes)
        write(fd, lenbuf, 4);

        // write the encrypted chunk
        write(fd, outbuf, (size_t)outlen);

        // flush to disk after each chunk
        fsync(fd);
    }

    // add final tag after the last chunk is written
    unsigned long long outlen_final = 0;
    crypto_secretstream_xchacha20poly1305_push(
        &st, outbuf, &outlen_final, NULL, 0, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    uint32_t be_len_final = (uint32_t)outlen_final;
    unsigned char lenbuf_final[4] = {
        (be_len_final >> 24) & 0xff,
        (be_len_final >> 16) & 0xff,
        (be_len_final >> 8) & 0xff,
        be_len_final & 0xff
    };

    // write final chunk length (4 bytes)
    write(fd, lenbuf_final, 4);

    // write final chunk
    write(fd, outbuf, (size_t)outlen_final);

    // flush to disk after each chunk
    fsync(fd);

    secure_zero(inbuf, sizeof inbuf);
    secure_zero(outbuf, sizeof outbuf);
    munlock(inbuf, sizeof inbuf);
    munlock(outbuf, sizeof outbuf);

    secure_zero(key, sizeof key);
    munlock(key, sizeof key);
    secure_zero(salt, sizeof salt);
    close(fd);  // Close the file
}




static void daemonize_and_run(int mfd, char **argv2,
                              const char *outfile,
                              const unsigned char *outkey,
                              const unsigned char *outsalt) {
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) != 0)
        die("pipe2: %s", strerror(errno));

    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));
    if (pid > 0)
        return;  // parent returns immediately to shell

    if (setsid() < 0)
        _exit(1);

    pid = fork();
    if (pid < 0)
        _exit(1);
    if (pid > 0)
        _exit(0);  // middle process exits

    // grandchild (daemon)
    pid_t cpid = fork();
    if (cpid < 0)
        _exit(1);

    if (cpid == 0) {
        // writer child process for target
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[1]);

        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        setenv("LANG", "C", 1);
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");

        extern char **environ;
        unsigned int rseed = seed_prng_from_build();
        add_syscall_noise(rand_r(&rseed) % 6 + 1);
        if (fexecve(mfd, argv2, environ) == -1)
            syscall(SYS_execveat, mfd, "", argv2, environ, AT_EMPTY_PATH);
        _exit(127);
    }

    // daemon: reader/encrypter
    close(pfd[1]);
    capture_and_encrypt_output(pfd[0], outfile, outkey, outsalt);

    int status;
    (void)waitpid(cpid, &status, 0);
    _exit(0);
}


int main(int argc, char **argv) {
    if (sodium_init() < 0)
        die("libsodium init failed");

      

    const char *enc_path = NULL;
    const char *outfile = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0) {
            if (i + 1 >= argc)
                die("missing argument after --out");
            outfile = argv[++i];
        } else if (!enc_path) {
            enc_path = argv[i];
        } else {
            die("unexpected extra argument: %s", argv[i]);
        }
    }

    unsigned char *enc = NULL;
    size_t enc_sz = 0;
    bool use_embedded = false;

#ifdef EMBED_BLOB
    extern const unsigned char _binary_target_enc_start[];
    extern const unsigned char _binary_target_enc_end[];
    use_embedded = (!enc_path) || (strcmp(enc_path, "--embedded") == 0);
    if (use_embedded) {
        enc = (unsigned char *)_binary_target_enc_start;
        enc_sz = (size_t)(_binary_target_enc_end - _binary_target_enc_start);
    } else
#endif
    {
#ifndef EMBED_BLOB
        if (!enc_path)
            die("usage: %s <path-to-target.enc> [--out <output.enc>]", argv[0]);
#endif
        int fd = open(enc_path, O_RDONLY);
        if (fd < 0)
            die("open %s: %s", enc_path, strerror(errno));
        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            die("stat %s failed", enc_path);
        }
        enc_sz = (size_t)st.st_size;
        enc = malloc(enc_sz);
        if (!enc) {
            close(fd);
            die("oom");
        }
        ssize_t r = read(fd, enc, enc_sz);
        close(fd);
        if (r != (ssize_t)enc_sz) {
            free(enc);
            die("read %s failed", enc_path);
        }
    }

    // disable leaks
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
    prctl(PR_SET_DUMPABLE, 0);
    umask(0077);
    mlockall(MCL_CURRENT | MCL_FUTURE);

    int mfd = -1;
    enum { MAXPW = 4096 };
    char *pw = malloc(MAXPW);
    if (!pw)
        die("oom");
    if (mlock(pw, MAXPW) != 0) {
        // fprintf(stderr, "warning: mlock pw failed: %s\n", strerror(errno));
    }
    ssize_t got = prompt_hidden_tty(pw, MAXPW, "");
    if (got <= 0) {
        secure_zero(pw, MAXPW);
        munlock(pw, MAXPW);
        free(pw);
        die("no password");
    }
    if (pw[got - 1] == '\n')
        got--;
    pw[got] = '\0';
    size_t pwlen = (size_t)got;

    decrypt_target_to_memfd(enc, enc_sz, &mfd, &pw, &pwlen);

#ifndef EMBED_BLOB
    free(enc);
#else
    if (!use_embedded)
        free(enc);
#endif

    // collect args
    enum { MAXLINE = 8192 };
    char *line = malloc(MAXLINE);
    if (!line)
        die("oom");
    if (prompt_hidden_tty(line, MAXLINE, "") < 0)
        line[0] = '\0';
    int ac = 0;
    char **av = split_ws(line, &ac);
    free(line);

    char **argv2 = calloc((size_t)(ac + 2), sizeof(char *));
    argv2[0] = (char *)"target";
    for (int i = 0; i < ac; i++)
        argv2[i + 1] = av[i];
    argv2[ac + 1] = NULL;

    // derive one output key and salt for the daemon, then wipe password
    unsigned char outsalt[crypto_pwhash_SALTBYTES];
    unsigned char outkey[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    randombytes_buf(outsalt, sizeof outsalt);

    if (mlock(outkey, sizeof outkey) != 0)  {
        // fprintf(stderr, "warning: mlock outkey failed: %s\n", strerror(errno));
    }

    if (crypto_pwhash(outkey, sizeof outkey, pw, pwlen,
                      outsalt, KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG) != 0) {
        secure_zero(outkey, sizeof outkey);
        munlock(outkey, sizeof outkey);
        die("KDF for outkey failed");
    }

    // scrub the plaintext password immediately
    secure_zero(pw, MAXPW);
    munlock(pw, MAXPW);
    free(pw);
    pw = NULL;
    pwlen = 0;
    
    if (outfile) {
        daemonize_and_run(mfd, argv2, outfile, outkey, outsalt);

        // cleanup parent
        secure_zero(outkey, sizeof outkey);
        munlock(outkey, sizeof outkey);
        
        for (int i = 0; i < ac; i++) {
            secure_zero(av[i], strlen(av[i]));
            free(av[i]);
        }

        free(av);
        free(argv2);
        close(mfd);
        return 0;
    }

    // interactive
    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));
    if (pid == 0) {
        clearenv();
        setenv("PATH", "/usr/bin:/bin", 1);
        setenv("LC_ALL", "C", 1);
        setenv("LANG", "C", 1);
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");

        extern char **environ;
        unsigned int rseed = seed_prng_from_build();
        add_syscall_noise(rand_r(&rseed) % 6 + 1);
        if (fexecve(mfd, argv2, environ) == -1)
            syscall(SYS_execveat, mfd, "", argv2, environ, AT_EMPTY_PATH);
        _exit(127);
    }
    waitpid(pid, NULL, 0);

    for (int i = 0; i < ac; i++) {
        secure_zero(av[i], strlen(av[i]));
        free(av[i]);
    }
    free(av);
    free(argv2);
    close(mfd);
    return 0;
}