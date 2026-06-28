# Variables
CC ?= clang
BPFCC ?= $(CC)
BPFTOOL ?= bpftool
ARCH := x86_64

# List all your BPF source files here
BPF_SRCS := vm.bpf.c restrict.bpf.c

# Generate Object and Skeleton filenames automatically from the list above
BPF_OBJS := $(BPF_SRCS:.c=.o)
.SECONDARY: $(BPF_OBJS)
BPF_SKELS := $(BPF_SRCS:.bpf.c=.skel.h)

LOADER_SRC := bpf_lsm_policy_loader.c
LOADER_BIN := bpf_lsm_policy_loader
SERVICE_FILE := bpf-lsm-policy-loader.service

DESTDIR ?=
BINDIR ?= /usr/local/sbin
UNITDIR ?= /etc/systemd/system

CFLAGS := -g -O2 -Wall
LIBS := -lbpf

CLANG_BPF_SYS_INCLUDES := $(shell $(CC) -v -E - </dev/null 2>&1 \
    | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')


BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__x86_64__ $(CLANG_BPF_SYS_INCLUDES)

.PHONY: all clean install uninstall load

all: $(LOADER_BIN)

%.bpf.o: %.bpf.c kernel_types.bpf.h bpf_lsm_policy.h
	@echo "Compiling BPF object: $@"
	$(BPFCC) $(BPF_CFLAGS) -I. -c $< -o $@

%.skel.h: %.bpf.o
	@echo "Generating skeleton: $@"
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER_BIN): $(LOADER_SRC) $(BPF_SKELS)
	@echo "Compiling loader..."
	$(CC) $(CFLAGS) -I. $(LOADER_SRC) -o $(LOADER_BIN) $(LIBS)

clean:
	rm -f $(BPF_OBJS) $(BPF_SKELS) $(LOADER_BIN)

install: $(LOADER_BIN)
	@echo "Installing binary to $(DESTDIR)$(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(LOADER_BIN) $(DESTDIR)$(BINDIR)/$(LOADER_BIN)
	@echo "Installing service to $(DESTDIR)$(UNITDIR)..."
	install -d $(DESTDIR)$(UNITDIR)
	sed 's|@BINDIR@|$(BINDIR)|g' $(SERVICE_FILE).in > $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)
	chmod 644 $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)

load: install
	@echo "Reloading systemd and starting service..."
	systemctl daemon-reload
	systemctl enable $(SERVICE_FILE)
	systemctl restart $(SERVICE_FILE)
	systemctl status $(SERVICE_FILE) --no-pager

uninstall:
	systemctl stop $(SERVICE_FILE) || true
	systemctl disable $(SERVICE_FILE) || true
	rm -f $(DESTDIR)$(BINDIR)/$(LOADER_BIN)
	rm -f $(DESTDIR)$(UNITDIR)/$(SERVICE_FILE)
	systemctl daemon-reload