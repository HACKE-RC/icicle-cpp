# Icicle

[Icicle](https://github.com/icicle-emu/icicle-emu) is an experimental fuzzing-specific, multi-architecture emulation framework.

## C/C++ Bindings

This project provides C/C++ bindings for the icicle emulator as a static library with a single-header C API (`icicle.h`).

## Building

### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs))
- NASM (for assembling the test program)
- The ghidra submodule (required for SLEIGH processor definitions)

```sh
git clone --recurse-submodules https://github.com/HACKE-RC/icicle-cpp
cd icicle-cpp
cd src
cargo build --release
```

The static library will be at `src/target/release/libicicle.a`.

### Convenience script

```sh
./build_and_test.sh
```

This builds the Rust library and runs all C test binaries (`tests-debug`, `hook-tests-debug`, `snapshot-tests-debug`, `serialization-test-debug`, `compression-test-debug`, `features-debug`).

## Running Tests

```sh
cd tests
make          # builds all test binaries
make run      # runs the debug suite
```

Each test binary can also be run standalone:
```sh
./tests-debug              # core functionality (registers, memory, disassembly, etc.)
./hook-tests-debug         # violation, syscall, execution, mem read/write hooks
./snapshot-tests-debug     # CPU/VM snapshot and restore
./serialization-test-debug # state serialization + zstd compression
./features-debug           # environment variable debug instrumentation
```

## Linking

The library is a standard C static library. Link with `-licicle` and include `icicle.h`:

```cmake
# CMake example
target_link_libraries(your_target PRIVATE icicle)
target_include_directories(your_target PRIVATE path/to/icicle-cpp)
```

```makefile
# Makefile example
LDFLAGS += -L/path/to/icicle-cpp/src/target/release -licicle
CFLAGS  += -I/path/to/icicle-cpp
```

## Hook API

The following hook types are supported:

| Hook type | Registration | Removal |
|-----------|-------------|---------|
| Memory violation | `icicle_add_violation_hook` | `icicle_remove_hook` |
| Syscall interception | `icicle_add_syscall_hook` | `icicle_remove_hook` |
| Block execution | `icicle_add_execution_hook` | `icicle_remove_execution_hook` |
| Memory read (range) | `icicle_add_mem_read_hook` | `icicle_remove_mem_read_hook` |
| Memory write (range) | `icicle_add_mem_write_hook` | `icicle_remove_mem_write_hook` |
| Debug write logging | `icicle_debug_log_write` | `icicle_remove_mem_write_hook` |
| Debug register logging | `icicle_debug_log_regs` | `icicle_remove_execution_hook` |
| Coverage instrumentation | `icicle_set_coverage_mode` | — (reconfigure to disable) |

See `icicle.h` for full function signatures and documentation.
