#ifndef ICICLE_FFI_H
#define ICICLE_FFI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NoAccess = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ExecuteOnly = 3,
    ExecuteRead = 4,
    ExecuteReadWrite = 5
} MemoryProtection;

typedef enum {
    Running = 0,
    InstructionLimit = 1,
    Breakpoint = 2,
    Interrupted = 3,
    Halt = 4,
    Killed = 5,
    Deadlock = 6,
    OutOfMemory = 7,
    Unimplemented = 8,
    UnhandledException = 9
} RunStatus;

typedef struct Icicle Icicle;
typedef struct RawEnvironment RawEnvironment;

// Hook Callback Types
typedef int (*ViolationFunction)(void* data, uint64_t address, uint8_t permission, int unmapped);
typedef void (*RawFunction)(void* data);
typedef void (*PtrFunction)(void* data, uint64_t address);

// Syscall Arguments Structure (for x86_64 Linux convention)
typedef struct {
    uint64_t arg0; // RDI
    uint64_t arg1; // RSI
    uint64_t arg2; // RDX
    uint64_t arg3; // R10
    uint64_t arg4; // R8
    uint64_t arg5; // R9
} SyscallArgs;

// Updated Syscall Hook Callback Type with Context
// Return value semantics: 0=Continue after syscall, 1=Skip syscall, -1=Propagate Exception
typedef int (*SyscallHookFunction)(void* data, uint64_t syscall_nr, const SyscallArgs* args);

typedef struct Cpu Cpu;
struct Cpu;

typedef struct {
    char* name;
    uint32_t offset;
    uint8_t size;
} RegInfo;

// New Memory Hook Callback Types
typedef void (*MemReadHookFunction)(void* data, uint64_t address, uint8_t size, const uint8_t* value_read);
typedef void (*MemWriteHookFunction)(void* data, uint64_t address, uint8_t size, uint64_t value_written);

// CPU Snapshot structure
typedef struct {
    void* regs;  // Opaque pointer to Regs
    __uint128_t args[8];  // Using compiler-specific 128-bit type
    void* shadow_stack;  // Opaque pointer to ShadowStack
    uint32_t exception_code;
    uint64_t exception_value;
    void* pending_exception;  // Optional<Exception>
    uint64_t icount;
    uint64_t block_id;
    uint64_t block_offset;
} CpuSnapshot;

// Full VM snapshot structure
typedef struct {
    CpuSnapshot* cpu;
    void* mem;  // Opaque pointer to memory snapshot
    void* env;  // Opaque pointer to environment snapshot
} VmSnapshot;

// Snapshot and restore functions
CpuSnapshot* icicle_cpu_snapshot(Icicle* vm);
int icicle_cpu_restore(Icicle* vm, const CpuSnapshot* snapshot);
void icicle_cpu_snapshot_free(CpuSnapshot* snapshot);

// Full VM snapshot functions
VmSnapshot* icicle_vm_snapshot(Icicle* vm);
int icicle_vm_restore(Icicle* vm, const VmSnapshot* snapshot);
void icicle_vm_snapshot_free(VmSnapshot* snapshot);

Icicle* icicle_new(const char *architecture,
                   int jit,
                   int jit_mem,
                   int shadow_stack,
                   int recompilation,
                   int track_uninitialized,
                   int optimize_instructions,
                   int optimize_block,
                   int tracing);
void icicle_free(Icicle* ptr);
uint64_t icicle_get_icount(const Icicle* ptr);
void icicle_set_icount(Icicle* ptr, uint64_t count);
uint64_t icicle_get_pc(const Icicle* ptr);
void icicle_set_pc(Icicle* ptr, uint64_t addr);
void icicle_reset(Icicle* ptr);
RunStatus icicle_run(Icicle* ptr);
RunStatus icicle_step(Icicle* ptr, uint64_t count);
int icicle_mem_map(Icicle* ptr, uint64_t address, uint64_t size, MemoryProtection protection);
int icicle_mem_unmap(Icicle* ptr, uint64_t address, uint64_t size);
int icicle_mem_protect(Icicle* ptr, uint64_t address, size_t size, MemoryProtection protection);
unsigned char* icicle_mem_read(Icicle* ptr, uint64_t address, size_t size, size_t* out_size);
int icicle_mem_write(Icicle* ptr, uint64_t address, const unsigned char* data, size_t size);
void icicle_free_buffer(unsigned char* buffer, size_t size);

// Utility functions.
uint64_t icicle_get_sp(Icicle* ptr);
void icicle_set_sp(Icicle* ptr, uint64_t addr);
RegInfo* icicle_reg_list(Icicle* ptr, size_t* out_count);
void icicle_reg_list_free(RegInfo* regs, size_t count);
int icicle_reg_size(Icicle* ptr, const char* reg_name);
int icicle_reg_read(Icicle* ptr, const char* reg_name, uint64_t* out_value);
int icicle_reg_write(Icicle* ptr, const char* reg_name, uint64_t value);
size_t icicle_get_mem_capacity(Icicle* ptr);
int icicle_set_mem_capacity(Icicle* ptr, size_t capacity);
bool icicle_add_breakpoint(Icicle* ptr, uint64_t address);
bool icicle_remove_breakpoint(Icicle* ptr, uint64_t address);
int icicle_run_until(Icicle* ptr, uint64_t address);
RawEnvironment* icicle_rawenv_new();
void icicle_rawenv_free(RawEnvironment* env);
int icicle_rawenv_load(RawEnvironment* env, void* cpu, const unsigned char* code, size_t size);
Cpu* icicle_get_cpu_ptr(Icicle* ptr);
uint32_t icicle_add_violation_hook(Icicle* ptr, ViolationFunction callback, void* data);

// Update add_syscall_hook to use the new callback type
uint32_t icicle_add_syscall_hook(Icicle* ptr, SyscallHookFunction callback, void* data);
uint32_t icicle_add_execution_hook(Icicle* ptr, PtrFunction callback, void* data);
int icicle_remove_hook(Icicle* ptr, uint32_t id);

// Add declarations for memory hooks
// Note: Using u32 for hook IDs, although MMU might return Option<u32>
// We will handle potential None in Rust and return 0 for failure.
// We'll expose ReadAfter and Write hooks.
uint32_t icicle_add_mem_read_hook(
    Icicle* ptr, 
    MemReadHookFunction callback, 
    void* data, 
    uint64_t start_addr, 
    uint64_t end_addr);
    
uint32_t icicle_add_mem_write_hook(
    Icicle* ptr, 
    MemWriteHookFunction callback, 
    void* data, 
    uint64_t start_addr, 
    uint64_t end_addr);

// Declarations for removing hooks by type
int icicle_remove_hook(Icicle* ptr, uint32_t hook_id); // ONLY for Violation (1) and Syscall (2)
int icicle_remove_execution_hook(Icicle* ptr, uint32_t hook_id);
int icicle_remove_mem_read_hook(Icicle* ptr, uint32_t hook_id);
int icicle_remove_mem_write_hook(Icicle* ptr, uint32_t hook_id);

#ifdef __cplusplus
}
#endif

#endif // ICICLE_FFI_H
