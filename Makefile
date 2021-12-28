BIN=pipe_rw
SRCS=corellium.s hexdump.c pipe_rw.c

.PHONY: clean

all: $(BIN)

$(BIN): $(SRCS)
	clang -arch arm64 -arch arm64e -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=11.0 -Wall -O0 -o $@ $+
	codesign -fs - $@

clean:
	rm -f $(BIN)
