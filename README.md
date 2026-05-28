# Icicle

[Icicle](https://github.com/icicle-emu/icicle-emu) is an experimental fuzzing-specific, multi-architecture emulation framework.

## C/C++ Bindings

This project provides C/C++ FFI bindings to the icicle emulator as a static Rust library with a single-header C API (`icicle.h`).

## Building

```sh
git clone --recurse-submodules https://github.com/HACKE-RC/icicle-cpp
cd icicle-cpp/src
cargo build --release
```

The static library will be at `src/target/release/libicicle.a`. For a full build-and-test cycle:

```sh
./build_and_test.sh
```

## Implementation

The wrapper is a Rust `staticlib` crate exposing `#[no_mangle] pub extern "C"` functions for every operation in `icicle.h`.

**Module layout** (`src/`):

| File | Purpose |
|------|---------|
| `types.rs` | FFI callback type aliases, `#[repr(C)]` structs (`SyscallArgs`, `CpuSnapshot`, `MemRegionInfo`), enums (`MemoryProtection`, `RunStatus`, `CoverageMode`), and permission mapping helpers |
| `vm.rs` | `Icicle` struct (wrapping `icicle_vm::Vm`), all core VM methods (`new`, `run`, `mem_map`, `reg_read`, etc.), `reg_find`, and `vm_exit_to_run_status` |
| `lib.rs` | ~60 `#[no_mangle]` FFI entry points — hooks, snapshots, coverage instrumentation, debug instrumentation, serialization, breakpoints, and memory region listing |

**Key design decisions**:

- **Hook lifecycle**: Violation (ID 1) and syscall (ID 2) hooks are singletons stored in `Option` fields on the `Icicle` struct. Execution hooks and memory hooks use `HashMap<u32, Box<dyn ...>>` tracking maps with a monotonically incrementing ID counter (starting at 1 or 3 respectively, leaving 0 as the failure sentinel). Hook removal from the core VM is a known limitation — the upstream API does not expose `remove_hook`, so dropping the tracked closure makes the hook a no-op but does not de-register it from the VM.

- **Exception handling in `run()`**: The `run()` method loops on `VmExit::UnhandledException`, dispatching to the violation or syscall callback if registered. The violation path handles the common x86-64 "write to NULL" pattern by advancing PC past the faulting instruction. The syscall path reads x86-64 calling-convention registers (RAX, RDI, RSI, RDX, R10, R8, R9) and advances PC by 2 bytes (the length of `syscall` on x86-64). Non-x86 architectures are guarded and propagate the exception unhandled.

- **Serialization**: `SerializableVmState` captures register state as a raw byte image of the `Regs` struct (via `bincode`), plus shadow stack entries, exception state, icount, and optionally all mapped memory regions. `zstd` compression is supported. The CPU-only path skips the memory scan entirely.

- **Coverage**: Four modes (Blocks, Edges, BlockCounts, EdgeCounts) are implemented as `FnMut` closures holding a raw `*mut Vec<u8>` into `Icicle.coverage_map`. Mode switches resize the map in-place to avoid invalidating the pointer held by still-registered hooks.

- **Snapshot/restore**: `CpuSnapshot` and `VmSnapshot` are `#[repr(C)]` structs with opaque heap-allocated fields. Save allocates, restore copies back into the live CPU/VM, and free drops each allocation.

## Linking

Link with `-licicle` and include `icicle.h`:

```cmake
target_link_libraries(your_target PRIVATE icicle)
target_include_directories(your_target PRIVATE path/to/icicle-cpp)
```

See `icicle.h` for the full API surface.
