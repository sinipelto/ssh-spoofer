CFLAGS := -Wall -Wextra -Wpedantic

binr := spoofer
bind := $(binr)_debug

srcd := ./src
bdir := ./build
ddir := ./bin

srcs := $(srcd)/main.c
objs := $(bdir)/main.o

.PHONY: all
.PHONY: debug
.PHONY: release
.PHONY: clean

all: release

debug: CFLAGS += -g3 -DDEBUG
debug: $(ddir)/$(bind)

release: CFLAGS += -O3
release: $(ddir)/$(binr)

$(ddir)/$(bind): $(objs)
	echo "Building DEBUG.."
	$(CC) -o $@ $(CFLAGS) $<

$(ddir)/$(binr): $(objs)
	echo "Building RELEASE.."
	$(CC) -o $@ $(CFLAGS) $<

$(objs): $(srcs)
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	echo "Cleaning up.."
	rm -rf $(ddir)/*
	rm -rf $(bdir)/*
