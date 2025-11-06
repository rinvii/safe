CC              := musl-gcc

BUILD_DIR       := build
TARGET          ?= ./target
SEED_FILE       := .build_seed

ifeq ($(wildcard $(SEED_FILE)),)
  $(shell od -vAn -N4 -tu4 /dev/urandom | tr -d ' ' > $(SEED_FILE))
endif
BUILD_SEED := $(shell cat $(SEED_FILE))

CFLAGS_COMMON   := -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -static -s \
                   -I/usr/local/musl/include -Isrc -fpack-struct=1 \
                   -ffunction-sections -fdata-sections -DBUILD_SEED=$(BUILD_SEED) \
				   -DENABLE_ANTI_TAMPER=1
LDFLAGS_COMMON  := /usr/local/musl/lib/libsodium.a -L/usr/local/musl/lib -lz \
                   -Wl,-z,relro -Wl,-z,now -Wl,--gc-sections \
                   -Wl,--defsym,BUILD_SEED=$(BUILD_SEED)

CFLAGS_EXTRA    ?=
LDFLAGS_EXTRA   ?=

GREEN := \033[1;32m
RED   := \033[1;31m
BLUE  := \033[1;34m
YELL  := \033[1;33m
RESET := \033[0m

.DEFAULT_GOAL := help

SRCDIR := src
ENCRYPT_SRC := $(SRCDIR)/encrypt.c
DECRYPT_SRC := $(SRCDIR)/decrypt.c
LAUNCH_SRC  := $(SRCDIR)/launch.c

# ------------------------------------------------------------
# High-level targets
# ------------------------------------------------------------

all: noise $(BUILD_DIR)/encrypt $(BUILD_DIR)/launch $(BUILD_DIR)/decrypt
	@echo "$(GREEN)[OK]$(RESET) All tools built in $(BUILD_DIR)/ (seed=$(BUILD_SEED))"

newseed:
	@echo "$(YELL)==> Generating new BUILD_SEED$(RESET)"
	@od -vAn -N4 -tu4 /dev/urandom | tr -d ' ' > $(SEED_FILE)
	@echo "$(GREEN)[OK]$(RESET) New seed: $(shell cat $(SEED_FILE))"

pack:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f "$(TARGET)" ]; then \
		echo "$(RED)[ERR]$(RESET) Missing $(TARGET) (plain ELF to encrypt)"; \
		exit 1; \
	fi
	@echo "$(BLUE)==> Encrypting $(TARGET) → ./$(notdir $(TARGET)).enc$(RESET)"
	@$(BUILD_DIR)/encrypt $(TARGET)

release:
	@echo "$(YELL)==> Building polymorphic release$(RESET)"
	@$(MAKE) _release

release_embed:
	@echo "$(YELL)==> Building embedded polymorphic release$(RESET)"
	@$(MAKE) _release_embed

clean:
	@echo "$(RED)==> Cleaning all artifacts$(RESET)"
	rm -rf $(BUILD_DIR) target.enc target_enc.o **/*.o *.bin

clean_release:
	@echo "$(RED)==> Cleaning release artifacts$(RESET)"
	rm -f $(BUILD_DIR)/launch target_enc.o target.enc

help:
	@echo ""
	@echo "$(BLUE)Usage:$(RESET)"
	@echo "  make all              - Build all tools (seed stored in .build_seed)"
	@echo "  make newseed          - Generate new random build seed"
	@echo "  make pack             - Encrypt target"
	@echo "  make release          - Build release"
	@echo "  make release_embed    - Build embedded release"
	@echo "  make clean            - Remove all build artifacts"
	@echo ""
	@echo "$(BLUE)Notes:$(RESET)"
	@echo "  BUILD_SEED persists in .build_seed"
	@echo "  Delete .build_seed or run 'make newseed' to rotate it."
	@echo ""

noise:
	@echo "$(BLUE)[GEN]$(RESET) generating junk symbols"
	@echo "" > $(SRCDIR)/noise.c
	@for i in $(shell seq 1 $$((10 + $$(($(BUILD_SEED)%30))))); do \
		echo "void dummy_$$i(void){}" >> $(SRCDIR)/noise.c; \
	done

# ------------------------------------------------------------
# Low-level build rules
# ------------------------------------------------------------

OBJS_COMMON := $(SRCDIR)/utils.o $(SRCDIR)/crypto.o

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(SRCDIR)/utils.o: $(SRCDIR)/utils.c $(SRCDIR)/utils.h
	@echo "$(BLUE)[CC]$(RESET) utils.o"
	@$(CC) $(CFLAGS_COMMON) $(BUILD_FLAGS) -c $< -o $@

$(SRCDIR)/crypto.o: $(SRCDIR)/crypto.c $(SRCDIR)/crypto.h
	@echo "$(BLUE)[CC]$(RESET) crypto.o"
	@$(CC) $(CFLAGS_COMMON) $(BUILD_FLAGS) -c $< -o $@

$(BUILD_DIR)/encrypt: $(ENCRYPT_SRC) $(OBJS_COMMON) | $(BUILD_DIR)
	@echo "$(BLUE)[CC]$(RESET) $@"
	@$(CC) $(CFLAGS_COMMON) $(CFLAGS_EXTRA) -o $@ $(ENCRYPT_SRC) $(OBJS_COMMON) $(LDFLAGS_COMMON) $(LDFLAGS_EXTRA)

$(BUILD_DIR)/decrypt: $(DECRYPT_SRC) $(OBJS_COMMON) | $(BUILD_DIR)
	@echo "$(BLUE)[CC]$(RESET) $@"
	@$(CC) $(CFLAGS_COMMON) $(CFLAGS_EXTRA) -o $@ $(DECRYPT_SRC) $(OBJS_COMMON) $(LDFLAGS_COMMON) $(LDFLAGS_EXTRA)

$(BUILD_DIR)/launch: $(LAUNCH_SRC) $(OBJS_COMMON) | $(BUILD_DIR)
	@echo "$(BLUE)[CC]$(RESET) $@"
	@$(CC) $(CFLAGS_COMMON) $(CFLAGS_EXTRA) -o $@ $(LAUNCH_SRC) $(OBJS_COMMON) $(LDFLAGS_COMMON) $(LDFLAGS_EXTRA)

# ------------------------------------------------------------
# Release subroutines (internal)
# ------------------------------------------------------------

_release:
	@echo "Using persistent BUILD_SEED=$(BUILD_SEED)"
	@$(MAKE) clean_release >/dev/null
	@$(MAKE) BUILD_FLAGS="-DBUILD_SEED=$(BUILD_SEED)" \
	    CFLAGS_COMMON="$(CFLAGS_COMMON) -s -fno-ident -fno-asynchronous-unwind-tables" all
	@strip --strip-all --remove-section=.comment --remove-section=.note.* $(BUILD_DIR)/* || true
	@if ls $(BUILD_DIR)/* 1>/dev/null 2>&1; then \
	    for f in $(BUILD_DIR)/*; do \
	        if file "$$f" | grep -q ELF; then \
	            objcopy --strip-unneeded \
	                --remove-section=.comment \
	                --remove-section=.note* \
	                --remove-section=.eh_frame \
	                --remove-section=.eh_frame_hdr \
	                --remove-section=.gcc_except_table \
	                "$$f" || true; \
	        fi; \
	    done; \
	fi
	@echo "$(GREEN)[OK]$(RESET) Release build complete."

_release_embed:
	@echo "Using persistent BUILD_SEED=$(BUILD_SEED)"
	@$(MAKE) clean_release >/dev/null
	@rm -f $(BUILD_DIR)/*.o $(SRCDIR)/*.o $(BUILD_DIR)/encrypt

	@if [ ! -f "$(TARGET)" ]; then \
		echo "$(RED)[ERR]$(RESET) Missing $(TARGET) (plain ELF to encrypt)"; \
		exit 1; \
	fi

	@$(MAKE) -B BUILD_FLAGS="-DBUILD_SEED=$(BUILD_SEED)" \
	    CFLAGS_COMMON="$(CFLAGS_COMMON) -s -fno-ident -fno-asynchronous-unwind-tables" \
		CFLAGS_EXTRA="$(CFLAGS_EXTRA)" \
	    $(BUILD_DIR)/encrypt

	@$(BUILD_DIR)/encrypt $(TARGET)
	@if [ "$(notdir $(TARGET))" != "target" ]; then mv $(notdir $(TARGET)).enc target.enc; fi
	@test -f "target.enc" || { echo "$(RED)[ERR]$(RESET) Missing target.enc"; exit 1; }

	@echo "$(BLUE)[LD]$(RESET) Embedding target.enc → target_enc.o"
	@ld -r -b binary target.enc -o target_enc.o

	@echo "$(BLUE)[CC]$(RESET) build/launch (embedded)"
	@$(CC) $(CFLAGS_COMMON) $(CFLAGS_EXTRA) -s -fno-ident -fno-asynchronous-unwind-tables \
	    -DEMBED_BLOB -DBUILD_SEED=$(BUILD_SEED) \
	    -o $(BUILD_DIR)/launch $(LAUNCH_SRC) $(SRCDIR)/utils.o $(SRCDIR)/crypto.o target_enc.o \
	    $(LDFLAGS_COMMON) $(LDFLAGS_EXTRA)

	@strip --strip-all --remove-section=.comment --remove-section=.note.* $(BUILD_DIR)/launch || true
	@if ls $(BUILD_DIR)/* 1>/dev/null 2>&1; then \
	    for f in $(BUILD_DIR)/*; do \
	        if file "$$f" | grep -q ELF; then \
	            objcopy --strip-unneeded \
	                --remove-section=.comment \
	                --remove-section=.note* \
	                --remove-section=.eh_frame \
	                --remove-section=.eh_frame_hdr \
	                --remove-section=.gcc_except_table \
	                "$$f" || true; \
	        fi; \
	    done; \
	fi
	@echo "$(GREEN)[OK]$(RESET) Embedded release built (seed=$(BUILD_SEED)): $(BUILD_DIR)/launch"

.PHONY: all pack release release_embed clean clean_release help newseed _release _release_embed
