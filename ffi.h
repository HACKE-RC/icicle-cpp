#ifndef ICICLE_FFI_H
#define ICICLE_FFI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// C-friendly enums for memory protection and run status.
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

// Opaque type representing the Icicle VM.
typedef struct Icicle Icicle;
typedef struct RawEnvironment RawEnvironment;
// Forward-declare Cpu so we can refer to it.
struct Cpu;
typedef struct Cpu Cpu;

// Retrieve the pointer to the CPU from the VM.
Cpu* icicle_get_cpu_ptr(Icicle* ptr);


// Opaque structure for register information.
typedef struct {
    char* name;   // allocated C string (free with icicle_reg_list_free)
    uint32_t offset;
    uint8_t size;
} RegInfo;

// FFI functions provided by the library.
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

#ifdef __cplusplus
}
#endif

#endif // ICICLE_FFI_H

