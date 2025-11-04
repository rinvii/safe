# safe

Safe is minimal toolchain to **compress**, **encrypt**, **embed**, and **execute** ELF binaries in memory without touching the disk.  

- `encrypt`: Encrypt ELF
- `launch`: Decrypts and runs encrypted ELF
- `decrypt`: Decrypts captured encrypted output

## Example workflow

```bash
# 1. Build all tools
make all

# 2. Encrypt your ELF (default: ./safety → safety.enc)
make pack
# or manually:
build/encrypt ./myelf

# 3. Run the encrypted binary
build/launch ./safety.enc

# 4. Capture encrypted stdout (optional)
build/launch ./safety.enc --out out.enc

# 5. Decrypt captured output
build/decrypt out.enc > plain.txt

# 6. Build a single-file embedded release
make release_embed

# 7. Run embedded binary and capture encrypted stdout
build/launch --out out.enc
```

## Override default target

```bash
make pack TARGET=./myelf
make release_embed TARGET=./myelf
```

## Roadmap

- [ ] Asymmetric encryption, passwordless mode, keyfile or environment-based decryption for CI/CD.
- [ ] macOS and Windows support, portable launcher backends.
- [ ] Header authentication, keyed integrity over encryption headers.
- [ ] Metadata inspector tool, view header metadata without decrypting payloads.
- [ ] Automated reproducibility check, verify identical builds for a given seed.
- [ ] Optional static analysis, make lint with clang-tidy/cppcheck.
- [ ] Unit test scaffolds, round-trip encrypt -> decrypt -> verify.
- [ ] Streaming encryption and decryption, constant-memory operation for large payloads and pipeline support.