UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
    LIB_PATH = -Wl,-rpath,../../target/release
else ifeq ($(UNAME_S),Linux)
    LIB_EXT = so
    LIB_PATH = -Wl,-rpath,../../target/release
else
    LIB_EXT = dll
    LIB_PATH =
endif

# Paths
RUST_LIB = ../../target/release/libcipher312.$(LIB_EXT)
OUT = test_runner

.PHONY: all clean run build-rust

all: run

build-rust:
	cd ../.. && cargo build --release

$(OUT): test.c $(RUST_LIB)
	$(CC) -o $(OUT) test.c -L../../target/release -lcipher312 $(LIB_PATH)

run: build-rust $(OUT)
	./$(OUT)

clean:
	rm -f $(OUT)
