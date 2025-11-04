# safe

Safe is minimal toolchain to **encrypt**, **embed**, and **execute** ELF binaries in memory.  

- `encrypt`: Encrypt ELF
- `launch`: Decrypts and runs encrypted ELF
- `decrypt`: Decrypts captured encrypted output
- `release_embed`: Builds a self-contained, embedded launcher

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
````

> Override default target:
>
> ```bash
> make pack TARGET=./myelf
> make release_embed TARGET=./myelf
> ```