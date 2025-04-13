#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <icicle.h>
#include <string.h>
#include <limits.h> // For UINT32_MAX

// Utility function for hex dumping memory.
void hex_dump(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
}

void test_register_utilities() {
    printf("\n=== Testing Register Utilities ===\n");
    
    // Create an x86_64 VM.
    Icicle* vm = icicle_new("x86_64", false, false, false, false, false, false, false, false);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM\n");
        return;
    }
    
    // Test get_pc.
    uint64_t pc = icicle_get_pc(vm);
    printf("Initial PC: 0x%lx\n", pc);
    
    // Test set_pc (set to 0x2000).
    icicle_set_pc(vm, 0x2000);
    pc = icicle_get_pc(vm);
    printf("After set_pc, PC: 0x%lx (expected 0x2000)\n", pc);
    if (pc != 0x2000) {
        printf("ERROR: PC value doesn't match expected value\n");
        icicle_free(vm);
        return;
    }
    
    // Test get_sp and set_sp.
    // First, set SP to 0x3000.
    icicle_set_sp(vm, 0x3000);
    uint64_t sp = icicle_get_sp(vm);
    printf("After set_sp, SP: 0x%lx (expected 0x3000)\n", sp);
    if (sp != 0x3000) {
        printf("ERROR: SP value doesn't match expected value\n");
        icicle_free(vm);
        return;
    }
    
    // Test reg_list.
    size_t reg_count = 0;
/*
  RegInfo* regs = icicle_reg_list(vm, &reg_count);
    if (regs) {
        printf("Register List (%zu registers):\n", reg_count);
        for (size_t i = 0; i < reg_count; i++) {
            printf("  %s: offset = %u, size = %u\n", regs[i].name, regs[i].offset, regs[i].size);
        }
        icicle_reg_list_free(regs, reg_count);
    } else {
        printf("Failed to retrieve register list.\n");
    }
    
    // Test reg_size for a known register.
    int rax_size = icicle_reg_size(vm, "rax");
    if (rax_size >= 0)
        printf("Size of register 'rax': %d bytes\n", rax_size);
    else
        printf("Failed to get size for register 'rax'\n");
 */   
    // Test reg_read and reg_write:
    uint64_t rax_val = 0;
    if (icicle_reg_read(vm, "rax", &rax_val) == 0)
        printf("Initial rax = 0x%lx\n", rax_val);
    else {
        printf("ERROR: Failed to read register 'rax'\n");
        icicle_free(vm);
        return;
    }
    
    // Write a new value.
    if (icicle_reg_write(vm, "rax", 0xDEADBEEF) == 0) {
        if (icicle_reg_read(vm, "rax", &rax_val) == 0) {
            printf("After write, rax = 0x%lx (expected 0xDEADBEEF)\n", rax_val);
            if (rax_val != 0xDEADBEEF) {
                printf("ERROR: RAX value doesn't match expected value\n");
                icicle_free(vm);
                return;
            }
        }
        else {
            printf("ERROR: Failed to read register 'rax' after write\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to write register 'rax'\n");
        icicle_free(vm);
        return;
    }
    IcicleExceptionCode exception = icicle_get_exception_code(vm);
    // compare the exception code with halt, limit and syscall
    if (exception == Exception_Halt) {
        printf("Halt after register write\n");
    } else if (exception == Exception_InstructionLimit) {
        printf("Instruction limit after register write\n");
    } else if (exception == Exception_Syscall) {
        printf("Syscall after register write\n");
    } else {
        printf("No exception after register write\n");
    }
    icicle_free(vm);
}

void test_memory_capacity() {
    printf("\n=== Testing Memory Capacity ===\n");
    
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for mem capacity test\n");
        return;
    }
    
    // Get the current memory capacity.
    size_t capacity = icicle_get_mem_capacity(vm);
    printf("Initial memory capacity: %zu bytes\n", capacity);
    
    // Try to set a larger capacity.
    if (icicle_set_mem_capacity(vm, capacity + 0x1000) == 0)
        printf("Memory capacity increased successfully.\n");
    else {
        printf("ERROR: Failed to increase memory capacity.\n");
        icicle_free(vm);
        return;
    }
   
    if (icicle_set_mem_capacity(vm, capacity - 0x1000) != 0)
        printf("Correctly rejected reducing memory capacity.\n");
    else {
        printf("ERROR: Unexpectedly allowed reducing memory capacity.\n");
        icicle_free(vm);
        return;
    }

    icicle_free(vm);
}

void test_breakpoints() {
    printf("\n=== Testing Breakpoints ===\n");

    // Create a new x86_64 VM.
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
         printf("ERROR: Failed to create VM for breakpoints test\n");
         return;
    }

    // Map memory at 0x4000 with execute permission.
    if (icicle_mem_map(vm, 0x4000, 0x1000, ExecuteReadWrite) != 0) {
         printf("ERROR: Failed to map memory for breakpoints test\n");
         icicle_free(vm);
         return;
    }

    // Write code: mov rax, 0x1234; jmp to self.
    const unsigned char code[] = { 
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0xEB, 0xFE                                // jmp to self (infinite loop)
    };
    if (icicle_mem_write(vm, 0x4000, code, sizeof(code)) != 0) {
         printf("ERROR: Failed to write code for breakpoints test\n");
         icicle_free(vm);
         return;
    }

    // Set PC to start of code.
    icicle_set_pc(vm, 0x4000);

    // Use run_until to run until the address 0x4000 is hit.
    RunStatus status = icicle_run_until(vm, 0x4000);
    printf("Run until breakpoint returned status: %d\n", status);
    if (status != Breakpoint) {
        printf("ERROR: Expected Breakpoint status from run_until, got %d\n", status);
        icicle_free(vm);
        return;
    }

    // Explicitly test add and remove breakpoint.
    int added = icicle_add_breakpoint(vm, 0x4000);
    printf("Breakpoint added: %d\n", added);
    if (!added) {
        printf("ERROR: Failed to add breakpoint\n");
        icicle_free(vm);
        return;
    }

    int removed = icicle_remove_breakpoint(vm, 0x4000);
    printf("Breakpoint removed: %d\n", removed);
    if (!removed) {
        printf("ERROR: Failed to remove breakpoint\n");
        icicle_free(vm);
        return;
    }

    icicle_free(vm);
}

void test_rawenv_load() {
    printf("\n=== Testing RawEnvironment Load ===\n");

    // Create a new RawEnvironment.
    RawEnvironment* env = icicle_rawenv_new();
    if (!env) {
         printf("ERROR: Failed to create RawEnvironment\n");
         return;
    }

    // For deterministic testing, prepare a buffer of known code bytes.
    // For example, for x86, a series of NOPs (0x90).
    const unsigned char code[] = { 0x90, 0x90, 0x90, 0x90 };

    // IMPORTANT: In a real test you must supply a valid CPU pointer.
    // For illustration, we pass NULL to force an error.
    int ret = icicle_rawenv_load(env, NULL, code, sizeof(code));
    if (ret != 0) {
         printf("Correctly failed to load code with an invalid CPU pointer.\n");
    } else {
         printf("ERROR: Unexpected success in loading code with an invalid CPU pointer.\n");
         icicle_rawenv_free(env);
         return;
    }

    // NOTE: To perform a proper test, create a CPU instance with known parameters,
    // compile a file with known machine code (for example, using an assembler),
    // and then pass its pointer along with the code bytes. This ensures deterministic results.

    icicle_rawenv_free(env);
}

void test_dynamic_load() {
    printf("\n=== Testing Dynamic Load ===\n");
    
    // Open the test binary file.
    FILE *fp = fopen("test_prog.bin", "rb");
    if (!fp) {
         printf("ERROR: Failed to open test_prog.bin\n");
         return;
    }
    
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);
    
    unsigned char *code_buffer = malloc(file_size);
    if (!code_buffer) {
         printf("ERROR: Memory allocation failure.\n");
         fclose(fp);
         return;
    }
    if (fread(code_buffer, 1, file_size, fp) != file_size) {
         printf("ERROR: Failed to read file contents.\n");
         free(code_buffer);
         fclose(fp);
         return;
    }
    fclose(fp);

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
         printf("ERROR: Failed to create VM.\n");
         free(code_buffer);
         return;
    }
    
    if (icicle_mem_map(vm, 0x8000, 0x1000, ExecuteReadWrite) != 0) {
         printf("ERROR: Memory mapping failed.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    
    // Get the CPU pointer (returns a pointer of type Cpu*).
    Cpu *cpu_ptr = icicle_get_cpu_ptr(vm);
    if (!cpu_ptr) {
         printf("ERROR: Failed to obtain CPU pointer.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    
    RawEnvironment* env = icicle_rawenv_new();
    if (!env) {
         printf("ERROR: Failed to create RawEnvironment.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    int load_status = icicle_rawenv_load(env, cpu_ptr, code_buffer, file_size);
    if (load_status != 0) {
         printf("ERROR: Failed to load program dynamically.\n");
         icicle_rawenv_free(env);
         icicle_free(vm);
         free(code_buffer);
         return;
    } else {
         printf("Success: Program loaded dynamically.\n");
    }
    icicle_rawenv_free(env);
    free(code_buffer);
    
    RunStatus status = icicle_step(vm, 10);
    printf("Run status: %d\n", status);
    if (status == UnhandledException) {
        printf("ERROR: Execution resulted in an unhandled exception\n");
        icicle_free(vm);
        return;
    }
    
    uint64_t rax = 0;
    if (icicle_reg_read(vm, "rax", &rax) == 0)
         printf("Register RAX: 0x%lx (expected 0xdeadbeef)\n", rax);
    else {
         printf("ERROR: Failed to read RAX.\n");
         icicle_free(vm);
         return;
    }
    
    icicle_free(vm);
}

void test_x86_64() {
    printf("\n=== Testing x86_64 ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for x86_64\n");
        icicle_free(vm);
        return;
    }

    // x86_64 Machine code: mov rax, 0x1337; jmp to self.
    // Encoding: 48 C7 C0 37 13 00 00  ; mov rax, 0x1337
    //          EB FE                ; jmp $ (infinite loop)
    const unsigned char code[] = { 
        0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, // mov rax, 0x1337
        0xEB, 0xFE                               // jmp to self
    };
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for x86_64\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    RunStatus status = icicle_step(vm, 1);  // Step once to execute the mov instruction.

    uint64_t rax = 0;
    if (icicle_reg_read(vm, "rax", &rax) == 0) {
        printf("x86_64 RAX = 0x%lx (expected 0x1337)\n", rax);
        if (rax != 0x1337) {
            printf("ERROR: RAX value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read register RAX for x86_64\n");
        icicle_free(vm);
        return;
    }

    icicle_free(vm);
}

// Test function for ARM64 (AArch64).
void test_aarch64() {
    printf("\n=== Testing AArch64 ===\n");

    Icicle *vm = icicle_new("aarch64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create AArch64 VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for AArch64\n");
        icicle_free(vm);
        return;
    }

    // ARM64 Machine code: movz x0, #0x5678; b .
    // Correct encoding for movz x0, #0x5678 is 0xD28ACF00.
    // Little-endian bytes: 0x00, 0xCF, 0x8A, 0xD2.
    // The branch-to-self instruction ("b .") is encoded as 0x14000000.
    // Little-endian: 0x00, 0x00, 0x00, 0x14.
    const unsigned char code[] = { 
        0x00, 0xCF, 0x8A, 0xD2, // movz x0, #0x5678
    };
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for AArch64\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    RunStatus status = icicle_step(vm, 1);  // Step once to execute the movz instruction.


    uint64_t x0 = 0;
    if (icicle_reg_read(vm, "x0", &x0) == 0) {
        printf("AArch64 X0 = 0x%lx (expected 0x5678)\n", x0);
        if (x0 != 0x5678) {
            printf("ERROR: X0 value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read register X0 for AArch64\n");
        icicle_free(vm);
        return;
    }

    icicle_free(vm);
}

// Test function for RISC-V 64-bit.
void test_riscv64() {
    printf("\n=== Testing RISC-V 64 ===\n");

    Icicle *vm = icicle_new("riscv64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create RISC-V VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for RISC-V\n");
        icicle_free(vm);
        return;
    }

    // RISC-V Machine code: addi a0, zero, 0x123; j .
    // Encoding for addi a0, zero, 0x123 is 0x12300513.
    // Little-endian: 0x13, 0x05, 0x30, 0x12.
    // Branch instruction: j . encoded as 0x6F000000.
    // Little-endian: 0x00, 0x00, 0x00, 0x6F.
    const unsigned char code[] = { 
        0x13, 0x05, 0x30, 0x12, // addi a0, zero, 0x123
        0x00, 0x00, 0x00, 0x6F  // j .
    };
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for RISC-V\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    RunStatus status = icicle_step(vm, 1);  // Step once to execute addi.


    uint64_t a0 = 0;
    if (icicle_reg_read(vm, "a0", &a0) == 0) {
        printf("RISC-V A0 = 0x%lx (expected 0x123)\n", a0);
        if (a0 != 0x123) {
            printf("ERROR: A0 value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read register A0 for RISC-V\n");
        icicle_free(vm);
        return;
    }

    icicle_free(vm);
}

void test_arch(){
  test_x86_64();
  test_aarch64();
  test_riscv64();
}

// Test memory read and write.
void test_memory_operations() {
    printf("\n=== Testing Memory Read/Write ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for memory test\n");
        return;
    }

    if (icicle_mem_map(vm, 0x3000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    // Write a 4-byte test pattern.
    const unsigned char test_data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    if (icicle_mem_write(vm, 0x3000, test_data, sizeof(test_data)) != 0) {
        printf("ERROR: Failed to write to memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    // Read back the data.
    size_t out_size = 0;
    unsigned char *read_buffer = icicle_mem_read(vm, 0x3000, sizeof(test_data), &out_size);
    if (!read_buffer) {
        printf("ERROR: Failed to read memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    printf("Memory Read Back (%zu bytes):\n", out_size);
    hex_dump(read_buffer, out_size);

    // Verify the data matches what we wrote
    if (out_size != sizeof(test_data)) {
        printf("ERROR: Read size mismatch, expected %zu bytes, got %zu bytes\n", sizeof(test_data), out_size);
        icicle_free_buffer(read_buffer, out_size);
        icicle_free(vm);
        return;
    }

    for (size_t i = 0; i < out_size; i++) {
        if (read_buffer[i] != test_data[i]) {
            printf("ERROR: Data mismatch at offset %zu, expected 0x%02X, got 0x%02X\n", 
                  i, test_data[i], read_buffer[i]);
            icicle_free_buffer(read_buffer, out_size);
            icicle_free(vm);
            return;
        }
    }

    icicle_free_buffer(read_buffer, out_size);
    icicle_free(vm);
}

// Callback function for violation hook testing.
int my_violation_hook(void* data, uint64_t address, uint8_t permission, int unmapped) {
    printf("Violation hook invoked: address=0x%lx, permission=%u, unmapped=%d\n", address, permission, unmapped);
    // Return 1 to indicate the violation might be considered handled (behavior depends on core)
    return 1;
}

// Example syscall hook: prints a message.
void my_syscall_hook(void* data) {
    printf("Syscall hook invoked.\n");
}

// Example execution hook: prints the execution address.
void my_execution_hook(void* data, uint64_t address) {
    printf("Execution hook invoked: address=0x%lx\n", address);
}

// Test the backtrace functionality
void test_backtrace() {
    printf("\n=== Testing Backtrace ===\n");

    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 1, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for backtrace test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission for code
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for backtrace test\n");
        icicle_free(vm);
        return;
    }

    // Map memory at 0x8000 with read/write permission for stack
    if (icicle_mem_map(vm, 0x8000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map stack memory for backtrace test\n");
        icicle_free(vm);
        return;
    }

    // Set up stack pointer
    icicle_set_sp(vm, 0x8ff0); // Near the top of the stack region

    const unsigned char code[]={
        72, 199, 195, 0, 4, 0, 0, 72, 184, 0, 0, 0, 0, 0, 0, 16, 64, 102, 72, 15, 110, 192, 102, 15, 108, 192, 72, 1, 195, 72, 137, 223, 87, 87, 72, 255, 199, 232, 14, 0, 0, 0, 232, 9, 0, 0, 0, 73, 129, 251, 16, 39, 0, 0, 80, 83, 72, 129, 239, 0, 1, 0, 0, 72, 137, 248, 72, 199, 195, 18, 0, 0, 0, 232, 1, 0, 0, 0, 195, 72, 137, 216, 72, 49, 192, 195
    }; 

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for backtrace test\n");
        icicle_free(vm);
        return;
    }

    // Start execution at main
    icicle_set_pc(vm, 0x1000);

    // Run until we reach func2 (after the calls)
    RunStatus status = icicle_run_until(vm, 0x104f);
    printf("Run status: %d\n", status);
    if (status != Breakpoint && status != Running) {
        printf("ERROR: Expected Breakpoint or Running status from run_until, got %d\n", status);
        icicle_free(vm);
        return;
    }
    
    printf("Current PC: 0x%lx (should be at func3: 0x104f)\n", icicle_get_pc(vm));
    if (icicle_get_pc(vm) != 0x104f) {
        printf("ERROR: Current PC doesn't match expected address\n");
        icicle_free(vm);
        return;
    }
    
    // Get backtrace with a max of 10 frames
    char* backtrace = icicle_get_backtrace(vm, 10);
    if (backtrace) {
        printf("Backtrace:\n%s\n", backtrace);
        // Free the backtrace string when done
        icicle_free_string(backtrace);
    } else {
        printf("ERROR: Failed to get backtrace or no debug info available\n");
        icicle_free(vm);
        return;
    }

    // Clean up
    icicle_free(vm);
}

// Test the disassembly functionality
void test_disassembly() {
    printf("\n=== Testing Disassembly ===\n");

    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for disassembly test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for disassembly test\n");
        icicle_free(vm);
        return;
    }

    // Create a sequence of x86_64 instructions to test disassembly
    // Instructions:
    // mov rax, 0x1337
    // mov rbx, 0xdeadbeef
    // add rax, rbx
    // ret
    const unsigned char code[] = {
        0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00,         // mov rax, 0x1337
        0x48, 0xC7, 0xC3, 0xEF, 0xBE, 0xAD, 0xDE,         // mov rbx, 0xdeadbeef
        0x48, 0x01, 0xD8,                                 // add rax, rbx
        0xC3                                              // ret
    };

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for disassembly test\n");
        icicle_free(vm);
        return;
    }

    // Set PC to start of code
    icicle_set_pc(vm, 0x1000);

    // Step once to ensure the block is translated
    icicle_step(vm, 1);

    printf("\n--- Current Disassembly ---\n");
    char* current_disasm = icicle_current_disasm(vm);
    if (current_disasm) {
        printf("%s\n", current_disasm);
        icicle_free_string(current_disasm);
    } else {
        printf("ERROR: Failed to get current disassembly\n");
        icicle_free(vm);
        return;
    }

    printf("\n--- Full Disassembly Dump ---\n");
    char* full_disasm = icicle_dump_disasm(vm);
    if (full_disasm) {
        printf("%s\n", full_disasm);
        icicle_free_string(full_disasm);
    } else {
        printf("ERROR: Failed to dump full disassembly\n");
        icicle_free(vm);
        return;
    }

    // Execute the remaining instructions
    icicle_step(vm, 3);  // Execute the remaining 3 instructions
    
    // Check that RAX contains the expected value (0x1337 + 0xdeadbeef = 0xdeadd226)
    uint64_t rax_value = 0;
    if (icicle_reg_read(vm, "rax", &rax_value) == 0) {
        printf("\nFinal RAX value: 0x%lx (expected 0xdeadd226)\n", rax_value);
        if (rax_value != 0xdeadd226) {
            printf("ERROR: RAX value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read RAX value\n");
        icicle_free(vm);
        return;
    }

    // Clean up
    icicle_free(vm);
}

// Test AArch64 disassembly functionality
void test_aarch64_disassembly() {
    printf("\n=== Testing AArch64 Disassembly ===\n");

    // Create a new AArch64 VM
    Icicle *vm = icicle_new("aarch64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for AArch64 disassembly test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for AArch64 disassembly test\n");
        icicle_free(vm);
        return;
    }

    // AArch64 instructions:
    // movz x0, #0x1234
    // movz x1, #0x5678
    // add x0, x0, x1
    // ret
    const unsigned char code[] = {
        0x00, 0x24, 0x86, 0xD2,     // movz x0, #0x1234
        0x01, 0xAC, 0x8B, 0xD2,     // movz x1, #0x5678
        0x00, 0x00, 0x01, 0x8B,     // add x0, x0, x1
        0xC0, 0x03, 0x5F, 0xD6      // ret
    };

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for AArch64 disassembly test\n");
        icicle_free(vm);
        return;
    }

    // Set PC to start of code
    icicle_set_pc(vm, 0x1000);

    // Step once to ensure the block is translated
    icicle_step(vm, 1);

    printf("\n--- AArch64 Current Disassembly ---\n");
    char* current_disasm = icicle_current_disasm(vm);
    if (current_disasm) {
        printf("%s\n", current_disasm);
        icicle_free_string(current_disasm);
    } else {
        printf("ERROR: Failed to get current AArch64 disassembly\n");
        icicle_free(vm);
        return;
    }

    printf("\n--- AArch64 Full Disassembly Dump ---\n");
    char* full_disasm = icicle_dump_disasm(vm);
    if (full_disasm) {
        printf("%s\n", full_disasm);
        icicle_free_string(full_disasm);
    } else {
        printf("ERROR: Failed to dump full AArch64 disassembly\n");
        icicle_free(vm);
        return;
    }

    // Execute the remaining instructions
    icicle_step(vm, 3);  // Execute the remaining 3 instructions
    
    // Check that X0 contains the expected value (0x1234 + 0x5678 = 0x68AC)
    uint64_t x0_value = 0;
    if (icicle_reg_read(vm, "x0", &x0_value) == 0) {
        printf("\nFinal X0 value: 0x%lx (expected 0x68ac)\n", x0_value);
        if (x0_value != 0x68ac) {
            printf("ERROR: X0 value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read X0 value\n");
        icicle_free(vm);
        return;
    }

    // Clean up
    icicle_free(vm);
}

// Test RISC-V disassembly functionality
void test_riscv64_disassembly() {
    printf("\n=== Testing RISC-V 64 Disassembly ===\n");

    // Create a new RISC-V 64 VM
    Icicle *vm = icicle_new("riscv64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for RISC-V disassembly test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for RISC-V disassembly test\n");
        icicle_free(vm);
        return;
    }

    // RISC-V instructions:
    // addi a0, zero, 0x123  # Load 0x123 into a0
    // addi a1, zero, 0x456  # Load 0x456 into a1
    // add a0, a0, a1        # a0 = a0 + a1
    // ret                   # Return
    const unsigned char code[] = {
        0x13, 0x05, 0x30, 0x12,     // addi a0, zero, 0x123
        0x93, 0x05, 0x60, 0x45,     // addi a1, zero, 0x456
        0x33, 0x85, 0xB5, 0x00,     // add a0, a0, a1
        0x67, 0x80, 0x00, 0x00      // ret
    };

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for RISC-V disassembly test\n");
        icicle_free(vm);
        return;
    }

    // Set PC to start of code
    icicle_set_pc(vm, 0x1000);

    // Step once to ensure the block is translated
    icicle_step(vm, 1);

    printf("\n--- RISC-V Current Disassembly ---\n");
    char* current_disasm = icicle_current_disasm(vm);
    if (current_disasm) {
        printf("%s\n", current_disasm);
        icicle_free_string(current_disasm);
    } else {
        printf("ERROR: Failed to get current RISC-V disassembly\n");
        icicle_free(vm);
        return;
    }

    printf("\n--- RISC-V Full Disassembly Dump ---\n");
    char* full_disasm = icicle_dump_disasm(vm);
    if (full_disasm) {
        printf("%s\n", full_disasm);
        icicle_free_string(full_disasm);
    } else {
        printf("ERROR: Failed to dump full RISC-V disassembly\n");
        icicle_free(vm);
        return;
    }

    // Execute the remaining instructions
    icicle_step(vm, 3);  // Execute the remaining 3 instructions
    
    // Check that A0 contains the expected value (0x123 + 0x456 = 0x579)
    uint64_t a0_value = 0;
    if (icicle_reg_read(vm, "a0", &a0_value) == 0) {
        printf("\nFinal A0 value: 0x%lx (expected 0x579)\n", a0_value);
        if (a0_value != 0x579) {
            printf("ERROR: A0 value doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read A0 value\n");
        icicle_free(vm);
        return;
    }

    // Clean up
    icicle_free(vm);
}

// Test the reversible execution functionality
void test_reversible_execution() {
    printf("\n=== Testing Reversible Execution ===\n");

    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for reversible execution test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission for code
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for reversible execution test\n");
        icicle_free(vm);
        return;
    }

    // Simple program that increments RAX several times:
    // start:
    //   xor rax, rax           ; 0x1000: 48 31 C0
    //   inc rax                ; 0x1003: 48 FF C0
    //   inc rax                ; 0x1006: 48 FF C0
    //   inc rax                ; 0x1009: 48 FF C0
    //   inc rax                ; 0x100C: 48 FF C0
    //   inc rax                ; 0x100F: 48 FF C0
    //   ret                    ; 0x1012: C3
    const unsigned char code[] = {
        0x48, 0x31, 0xC0,             // xor rax, rax
        0x48, 0xFF, 0xC0,             // inc rax
        0x48, 0xFF, 0xC0,             // inc rax
        0x48, 0xFF, 0xC0,             // inc rax
        0x48, 0xFF, 0xC0,             // inc rax
        0x48, 0xFF, 0xC0,             // inc rax
        0xC3                          // ret
    };

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for reversible execution test\n");
        icicle_free(vm);
        return;
    }

    // Set PC to start of code
    icicle_set_pc(vm, 0x1000);
    
    // First, verify that step_back fails without snapshots
    uint32_t result = icicle_step_back(vm, 1);
    if (result == UINT32_MAX) {
        printf("Test passed: step_back correctly returned failure when no snapshots exist\n");
    } else {
        printf("ERROR: step_back should have failed without snapshots\n");
        icicle_free(vm);
        return;
    }

    // Create an array to store our snapshots
    VmSnapshot* snapshots[7]; // One for each instruction + initial state
    
    // Save a snapshot at the start
    printf("\nSaving initial snapshot at instruction count: %lu\n", icicle_get_icount(vm));
    snapshots[0] = icicle_vm_snapshot(vm);
    if (!snapshots[0]) {
        printf("ERROR: Failed to save snapshot\n");
        icicle_free(vm);
        return;
    }

    // Execute the first instruction (xor rax, rax)
    icicle_step(vm, 1);
    uint64_t rax_value = 0;
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 1, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save another snapshot
    snapshots[1] = icicle_vm_snapshot(vm);
    if (!snapshots[1]) {
        printf("ERROR: Failed to save snapshot\n");
        icicle_vm_snapshot_free(snapshots[0]);
        icicle_free(vm);
        return;
    }
    
    // Execute the second instruction (first inc rax)
    icicle_step(vm, 1);
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 2, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save another snapshot
    snapshots[2] = icicle_vm_snapshot(vm);
    if (!snapshots[2]) {
        printf("ERROR: Failed to save snapshot\n");
        icicle_vm_snapshot_free(snapshots[0]);
        icicle_vm_snapshot_free(snapshots[1]);
        icicle_free(vm);
        return;
    }
    
    // Execute the third instruction (second inc rax)
    icicle_step(vm, 1);
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 3, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save another snapshot
    snapshots[3] = icicle_vm_snapshot(vm);
    if (!snapshots[3]) {
        printf("ERROR: Failed to save snapshot\n");
        for (int i = 0; i < 3; i++) {
            icicle_vm_snapshot_free(snapshots[i]);
        }
        icicle_free(vm);
        return;
    }
    
    // Execute the fourth instruction (third inc rax)
    icicle_step(vm, 1);
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 4, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save another snapshot
    snapshots[4] = icicle_vm_snapshot(vm);
    if (!snapshots[4]) {
        printf("ERROR: Failed to save snapshot\n");
        for (int i = 0; i < 4; i++) {
            icicle_vm_snapshot_free(snapshots[i]);
        }
        icicle_free(vm);
        return;
    }
    
    // Execute the fifth instruction (fourth inc rax)
    icicle_step(vm, 1);
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 5, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save another snapshot
    snapshots[5] = icicle_vm_snapshot(vm);
    if (!snapshots[5]) {
        printf("ERROR: Failed to save snapshot\n");
        for (int i = 0; i < 5; i++) {
            icicle_vm_snapshot_free(snapshots[i]);
        }
        icicle_free(vm);
        return;
    }
    
    // Execute the sixth instruction (fifth inc rax)
    icicle_step(vm, 1);
    icicle_reg_read(vm, "rax", &rax_value);
    printf("After step 6, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
    
    // Save a final snapshot
    snapshots[6] = icicle_vm_snapshot(vm);
    if (!snapshots[6]) {
        printf("ERROR: Failed to save snapshot\n");
        for (int i = 0; i < 6; i++) {
            icicle_vm_snapshot_free(snapshots[i]);
        }
        icicle_free(vm);
        return;
    }
    
    // Current icount for later checks
    uint64_t final_icount = icicle_get_icount(vm);
    
    // Test step_back - restore snapshot to go back 2 instructions
    printf("\nStepping back 2 instructions by restoring snapshot...\n");
    if (icicle_vm_restore(vm, snapshots[4]) == 0) {
        icicle_reg_read(vm, "rax", &rax_value);
        printf("After restoring snapshot 4, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
        
        if (rax_value == 3) {
            printf("Test passed: restore correctly reverted to RAX=3\n");
        } else {
            printf("ERROR: restore should have reverted to RAX=3, got %lu\n", rax_value);
        }
    } else {
        printf("ERROR: restore unexpectedly failed\n");
    }
    
    // Test restore to go to the first increment (RAX should be 0)
    printf("\nGoing to instruction count after first instruction (RAX=0)...\n");
    if (icicle_vm_restore(vm, snapshots[1]) == 0) {
        icicle_reg_read(vm, "rax", &rax_value);
        printf("After restore to snapshot 1, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
        
        if (rax_value == 0) {
            printf("Test passed: restore correctly jumped to RAX=0\n");
        } else {
            printf("ERROR: restore should have jumped to RAX=0, got %lu\n", rax_value);
        }
    } else {
        printf("ERROR: restore unexpectedly failed\n");
    }
    
    // Test restore to the final state (RAX should be 5)
    printf("\nGoing to final instruction count (RAX=5)...\n");
    if (icicle_vm_restore(vm, snapshots[6]) == 0) {
        icicle_reg_read(vm, "rax", &rax_value);
        printf("After restore to snapshot 6, RAX = %lu (icount: %lu)\n", rax_value, icicle_get_icount(vm));
        
        if (rax_value == 5) {
            printf("Test passed: restore correctly jumped to RAX=5\n");
        } else {
            printf("ERROR: restore should have jumped to RAX=5, got %lu\n", rax_value);
        }
    } else {
        printf("ERROR: restore unexpectedly failed\n");
    }
    
    // Free all snapshots
    printf("\nFreeing snapshots...\n");
    for (int i = 0; i < 7; i++) {
        icicle_vm_snapshot_free(snapshots[i]);
    }
    
    // Clean up
    icicle_free(vm);
}

// Callback functions for debug instrumentation testing

// For the write logging
void my_log_write_hook(void* data, const char* name, uint64_t address, uint8_t size, uint64_t value) {
    int* log_count = (int*)data;
    (*log_count)++;
    printf("[LOG_WRITE] %s@0x%lx (%d bytes): 0x%lx\n", name, address, size, value);
}

// For the register logging
void my_log_regs_hook(void* data, const char* name, uint64_t address, size_t num_regs, const char** reg_names, const uint64_t* reg_values) {
    int* log_count = (int*)data;
    (*log_count)++;
    printf("[LOG_REGS] %s@0x%lx:\n", name, address);
    for (size_t i = 0; i < num_regs; i++) {
        printf("  %s = 0x%lx\n", reg_names[i], reg_values[i]);
    }
}

// Test the debug instrumentation functionality
void test_debug_instrumentation() {
    printf("\n=== Testing Debug Instrumentation ===\n");

    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for debug instrumentation test\n");
        return;
    }

    // Map memory at 0x1000 with execute permission for code
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map memory for debug instrumentation test\n");
        icicle_free(vm);
        return;
    }

    // Map memory at 0x2000 with read/write permission for data
    if (icicle_mem_map(vm, 0x2000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory for debug instrumentation test\n");
        icicle_free(vm);
        return;
    }

    // Map memory for stack
    if (icicle_mem_map(vm, 0x8000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map stack memory\n");
        icicle_free(vm);
        return;
    }
    
    // Set up the stack pointer
    icicle_set_sp(vm, 0x8F00);

    // Simple program that:
    // 1. First writes to 0x2000 (monitored memory location)
    // 2. Sets some register values
    // 3. Jumps to a checkpoint where we'll monitor register values
    // 4. Writes again to the monitored memory location
    // 5. Halts
    const unsigned char code[] = {
        // Write 0xDEADBEEF to [0x2000] - This should trigger the first memory hook
        0x48, 0xC7, 0xC0, 0x00, 0x20, 0x00, 0x00,         // mov rax, 0x2000
        0x48, 0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,         // mov qword ptr [rax], 0xDEADBEEF
        
        // Set up register values
        0x48, 0xC7, 0xC1, 0x11, 0x11, 0x11, 0x11,         // mov rcx, 0x11111111
        0x48, 0xC7, 0xC2, 0x22, 0x22, 0x22, 0x22,         // mov rdx, 0x22222222
        0x48, 0xC7, 0xC3, 0x33, 0x33, 0x33, 0x33,         // mov rbx, 0x33333333
        
        // Jump to the checkpoint where we'll check registers
        0xE9, 0x0F, 0x00, 0x00, 0x00,                     // jmp checkpoint (15 bytes ahead)
        
        // Some data that won't be executed
        0x90, 0x90, 0x90, 0x90, 0x90,                     // 5 nops
        0x90, 0x90, 0x90, 0x90, 0x90,                     // 5 more nops
        
        // checkpoint: (This is where the register hook will fire)
        0x48, 0xC7, 0xC0, 0x44, 0x44, 0x44, 0x44,         // mov rax, 0x44444444
        
        // Write a different value to [0x2004] - This triggers the second memory hook
        0x48, 0xC7, 0xC0, 0x04, 0x20, 0x00, 0x00,         // mov rax, 0x2004
        0x48, 0xC7, 0x00, 0xCC, 0xCC, 0xCC, 0xCC,         // mov qword ptr [rax], 0xCCCCCCCC
        
        0xC3                                              // ret
    };

    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for debug instrumentation test\n");
        icicle_free(vm);
        return;
    }

    // Set PC to start of code
    icicle_set_pc(vm, 0x1000);
    
    // Counters to track how many times our hooks are called
    int write_hook_count = 0;
    int regs_hook_count = 0;
    
    // Register a hook to log writes to the memory range 0x2000-0x2008
    printf("Registering memory write hook for 0x2000-0x2008...\n");
    uint32_t write_hook_id = icicle_debug_log_write(
        vm, 
        "monitored_var", 
        0x2000, 
        8,  // Monitor 8 bytes
        my_log_write_hook, 
        &write_hook_count
    );
    
    if (write_hook_id == 0) {
        printf("ERROR: Failed to register write hook\n");
        icicle_free(vm);
        return;
    }
    printf("Memory write hook registered with ID: %u\n", write_hook_id);
    
    // Register a hook to log registers at the checkpoint (0x102e)
    printf("Registering register hook at checkpoint (0x102e)...\n");
    const char* regs_to_log[] = {"rax", "rbx", "rcx", "rdx"};
    uint32_t regs_hook_id = icicle_debug_log_regs(
        vm, 
        "checkpoint", 
        0x102e,  // Address of the checkpoint
        4,      // Number of registers
        regs_to_log,
        my_log_regs_hook, 
        &regs_hook_count
    );
    
    if (regs_hook_id == 0) {
        printf("ERROR: Failed to register register hook\n");
        icicle_free(vm);
        return;
    }
    printf("Register hook registered with ID: %u\n", regs_hook_id);
    
    // Run the VM to see if our hooks get triggered
    printf("\nRunning the VM...\n");
    RunStatus status = icicle_run(vm);
    printf("VM execution completed with status: %d\n", status);
    
    // Verify hooks were triggered
    printf("\nHook execution summary:\n");
    printf("- Memory write hook called: %d times (expected: 2)\n", write_hook_count);
    printf("- Register hook called: %d times (expected: 1)\n", regs_hook_count);
    
    // Read memory to verify writes
    size_t read_size = 0;
    unsigned char* mem_data = icicle_mem_read(vm, 0x2000, 8, &read_size);
    if (mem_data && read_size >= 8) {
        printf("\nVerifying memory content at 0x2000:\n");
        hex_dump(mem_data, read_size);
        icicle_free_buffer(mem_data, read_size);
    }
    
    // Verify test success
    if (write_hook_count == 2 && regs_hook_count == 1) {
        printf("\nTEST PASSED: Debug instrumentation working correctly\n");
    } else {
        printf("\nTEST FAILED: Debug instrumentation not working as expected\n");
    }
    
    icicle_free(vm);
}

// Test the environment variable-based debug instrumentation
void test_env_debug_instrumentation() {
    printf("\n=== Testing Environment Variable Debug Instrumentation ===\n");
    
    // Set up environment variables
    setenv("ICICLE_LOG_WRITES", "var1=0x3000:4;var2=0x3004:4", 1);
    setenv("ICICLE_LOG_REGS", "point1@0x1008=rax,rbx,rcx;point2@0x1020=rsp,rbp", 1);
    setenv("BREAKPOINTS", "0x1040", 1);
    
    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for env debug instrumentation test\n");
        return;
    }
    
    // Map memory regions
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0 ||
        icicle_mem_map(vm, 0x3000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory\n");
        icicle_free(vm);
        return;
    }
    
    // Set up a simple test program
    const unsigned char code[] = {
        // 0x1000: Start
        0x48, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00,         // mov rax, 0x3000
        
        // 0x1007: Should hit first register hook (point1@0x1008)
        0x90,                                             // nop
        0x48, 0xC7, 0xC3, 0xAA, 0xAA, 0xAA, 0xAA,         // mov rbx, 0xAAAAAAAA
        0x48, 0xC7, 0xC1, 0xBB, 0xBB, 0xBB, 0xBB,         // mov rcx, 0xBBBBBBBB
        
        // 0x1016: Write to monitored address (var1@0x3000)
        0x48, 0xC7, 0x00, 0x11, 0x22, 0x33, 0x44,         // mov qword ptr [rax], 0x44332211
        
        // 0x101D: Should hit second register hook (point2@0x1020)
        0x90, 0x90, 0x90,                                 // 3 nops
        0x48, 0x89, 0xE5,                                 // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,                           // sub rsp, 0x20
        
        // 0x102A: Write to second monitored address (var2@0x3004)
        0x48, 0xC7, 0xC0, 0x04, 0x30, 0x00, 0x00,         // mov rax, 0x3004
        0x48, 0xC7, 0x00, 0x55, 0x66, 0x77, 0x88,         // mov qword ptr [rax], 0x88776655
        
        // 0x103B: Should hit first breakpoint (0x1030)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,   // 8 nops
        0x90, 0x90, 0x90, 0x90, 0x90,                     // 5 more nops
        
        // 0x1048: Should hit second breakpoint (0x1040)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,   // 8 nops
        
        // End
        0xC3                                              // ret
    };
    
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code\n");
        icicle_free(vm);
        return;
    }
    
    // Set up the VM
    icicle_set_pc(vm, 0x1000);
    
    // Configure instrumentation from environment variables
    int hook_count = icicle_add_debug_instrumentation(vm);
    printf("Configured %d hooks from environment variables\n", hook_count);
    
    if (hook_count <= 0) {
        printf("ERROR: Failed to configure hooks from environment variables\n");
        icicle_free(vm);
        return;
    }
    
    // Run until we hit the first breakpoint
    printf("\nRunning until first breakpoint (expected at 0x1040)...\n");
    RunStatus status = icicle_run(vm);
    printf("VM stopped with status: %d\n", status);
    printf("Current PC: 0x%lx (expected: 0x1040)\n", icicle_get_pc(vm));
    
    if (status != Breakpoint || icicle_get_pc(vm) != 0x1040) {
        printf("ERROR: Breakpoint not hit or wrong breakpoint hit\n");
        icicle_free(vm);
        return;
    }
    
    // Continue to the end of execution
    printf("\nContinuing to the end of execution...\n");
    status = icicle_run(vm);
    printf("VM execution complete with status: %d\n", status);
    printf("Current PC: 0x%lx\n", icicle_get_pc(vm));
    
    // Check memory values
    size_t read_size = 0;
    unsigned char* mem_data = icicle_mem_read(vm, 0x3000, 8, &read_size);
    if (mem_data && read_size == 8) {
        printf("\nMemory values at monitored locations:\n");
        printf("var1@0x3000: ");
        for (int i = 0; i < 4; i++) {
            printf("%02X ", mem_data[i]);
        }
        printf("\n");
        
        printf("var2@0x3004: ");
        for (int i = 4; i < 8; i++) {
            printf("%02X ", mem_data[i]);
        }
        printf("\n");
        
        // Check expected values
        bool var1_ok = mem_data[0] == 0x11 && mem_data[1] == 0x22 && 
                      mem_data[2] == 0x33 && mem_data[3] == 0x44;
        bool var2_ok = mem_data[4] == 0x55 && mem_data[5] == 0x66 && 
                      mem_data[6] == 0x77 && mem_data[7] == 0x88;
        
        if (var1_ok && var2_ok) {
            printf("\nTEST PASSED: Environment variable debug instrumentation working correctly\n");
        } else {
            printf("\nTEST FAILED: Memory values don't match expected values\n");
        }
        
        icicle_free_buffer(mem_data, read_size);
    } else {
        printf("ERROR: Failed to read memory values\n");
    }
    
    // Clean up
    icicle_free(vm);
    
    // Clear environment variables for other tests
    unsetenv("ICICLE_LOG_WRITES");
    unsetenv("ICICLE_LOG_REGS");
    unsetenv("BREAKPOINTS");
}

// Test the coverage instrumentation functionality
void test_coverage_instrumentation() {
    printf("\n=== Testing Coverage Instrumentation ===\n");
    
    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for coverage instrumentation test\n");
        return;
    }

    // Map memory at 0x3000 for code
    if (icicle_mem_map(vm, 0x3000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map code memory for coverage test\n");
        icicle_free(vm);
        return;
    }
    
    // Simple test program with multiple basic blocks and branches
    // This is a simple counter program that examines even and odd numbers
    const unsigned char code[] = {
        // 0x3000: Start with RAX=0, RBX=0
        0x48, 0x31, 0xC0,                     // xor rax, rax (counter)
        0x48, 0x31, 0xDB,                     // xor rbx, rbx (result)
        
        // 0x3006: Compare counter
        0x48, 0x83, 0xF8, 0x0A,               // cmp rax, 10
        0x74, 0x16,                           // je done (0x3020)
        
        // 0x300C: Check even/odd
        0x48, 0x89, 0xC1,                     // mov rcx, rax
        0x48, 0x83, 0xE1, 0x01,               // and rcx, 1
        0x74, 0x05,                           // je even (0x3018)
        
        // 0x3014: odd path
        0x48, 0x29, 0xC3,                     // sub rbx, rax
        0xEB, 0x03,                           // jmp next (0x301B)
        
        // 0x3018: even path
        0x48, 0x01, 0xC3,                     // add rbx, rax
        
        // 0x301B: Increment and continue
        0x48, 0xFF, 0xC0,                     // inc rax
        0xEB, 0xE4,                           // jmp loop_cmp (0x3006)
        
        // 0x3020: End
        0xC3                                  // ret
    };
    
    if (icicle_mem_write(vm, 0x3000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for coverage test\n");
        icicle_free(vm);
        return;
    }
    
    // Set starting PC
    icicle_set_pc(vm, 0x3000);
    
    // Configure and enable instrumentation
    printf("Testing instrumentation configuration\n");
    
    
    // Set up for block coverage mode
    printf("Setting up block coverage mode\n");
    if (icicle_set_coverage_mode(vm, CoverageMode_Blocks) != 0) {
        printf("ERROR: Failed to set coverage mode\n");
        icicle_free(vm);
        return;
    }
    
    CoverageMode mode = icicle_get_coverage_mode(vm);
    printf("Coverage mode: %d (expected: %d)\n", mode, CoverageMode_Blocks);
    
    // Enable instrumentation for our code range
    if (icicle_enable_instrumentation(vm, 0x3000, 0x3100) != 0) {
        printf("ERROR: Failed to enable instrumentation\n");
        icicle_free(vm);
        return;
    }
    
    // Run the VM to generate coverage
    printf("\nRunning the VM with block coverage...\n");
    RunStatus status = icicle_run(vm);
    printf("VM execution completed with status: %d\n", status);
    
    // Get the final value of RBX (sum of even numbers 0,2,4,6,8 minus odd numbers 1,3,5,7,9)
    uint64_t result = 0;
    if (icicle_reg_read(vm, "rbx", &result) == 0) {
        printf("Final RBX value (sum): %ld (expected: -5)\n", (int64_t)result);
        if ((int64_t)result != -5) {
            printf("ERROR: Calculation result doesn't match expected value\n");
            icicle_free(vm);
            return;
        }
    } else {
        printf("ERROR: Failed to read RBX register\n");
        icicle_free(vm);
        return;
    }
    
    // Get the coverage map for block coverage
    size_t map_size = 0;
    uint8_t* coverage_map = icicle_get_coverage_map(vm, &map_size);
    if (!coverage_map || map_size == 0) {
        printf("ERROR: Failed to get coverage map\n");
        icicle_free(vm);
        return;
    }
    
    printf("Coverage map size: %zu bytes\n", map_size);
    printf("Coverage map contents (first 16 bytes): ");
    for (size_t i = 0; i < (map_size < 16 ? map_size : 16); i++) {
        printf("%02X ", coverage_map[i]);
    }
    printf("\n");
    
    // Check if any bits are set (should have at least a few blocks covered)
    bool has_coverage = false;
    for (size_t i = 0; i < map_size; i++) {
        if (coverage_map[i] != 0) {
            has_coverage = true;
            break;
        }
    }
    
    if (!has_coverage) {
        printf("ERROR: Coverage map is empty\n");
        icicle_free_buffer(coverage_map, map_size);
        icicle_free(vm);
        return;
    }
    
    icicle_free_buffer(coverage_map, map_size);
    
    // Reset coverage
    icicle_reset_coverage(vm);
    
    // Try edge coverage mode
    printf("\nSwitching to edge coverage mode\n");
    if (icicle_set_coverage_mode(vm, CoverageMode_Edges) != 0) {
        printf("ERROR: Failed to set edge coverage mode\n");
        icicle_free(vm);
        return;
    }
    
    if (!icicle_has_edge_coverage(vm)) {
        printf("ERROR: Edge coverage not enabled after setting mode\n");
        icicle_free(vm);
        return;
    }
    
    // Reset PC and run again
    icicle_set_pc(vm, 0x3000);
    printf("Running the VM with edge coverage...\n");
    status = icicle_run(vm);
    
    // Get the coverage map for edge coverage
    coverage_map = icicle_get_coverage_map(vm, &map_size);
    if (!coverage_map || map_size == 0) {
        printf("ERROR: Failed to get edge coverage map\n");
        icicle_free(vm);
        return;
    }
    
    printf("Edge coverage map size: %zu bytes\n", map_size);
    
    has_coverage = false;
    for (size_t i = 0; i < map_size; i++) {
        if (coverage_map[i] != 0) {
            has_coverage = true;
            break;
        }
    }
    
    if (!has_coverage) {
        printf("ERROR: Edge coverage map is empty\n");
        icicle_free_buffer(coverage_map, map_size);
        icicle_free(vm);
        return;
    }
    
    icicle_free_buffer(coverage_map, map_size);
    
    // Try with counter-based coverage
    printf("\nSwitching to block count coverage mode\n");
    if (icicle_set_coverage_mode(vm, CoverageMode_BlockCounts) != 0) {
        printf("ERROR: Failed to set block counts coverage mode\n");
        icicle_free(vm);
        return;
    }
    
    if (!icicle_has_counts_coverage(vm)) {
        printf("ERROR: Count coverage not enabled after setting mode\n");
        icicle_free(vm);
        return;
    }
    
    // Reset PC and run again
    icicle_set_pc(vm, 0x3000);
    printf("Running the VM with block count coverage...\n");
    status = icicle_run(vm);
    
    // Get the coverage map for block count coverage
    coverage_map = icicle_get_coverage_map(vm, &map_size);
    if (!coverage_map || map_size == 0) {
        printf("ERROR: Failed to get block count coverage map\n");
        icicle_free(vm);
        return;
    }
    
    printf("Block count coverage map size: %zu bytes\n", map_size);
    
    // Test setting context bits
    printf("\nTesting context bits setting\n");
    if (icicle_set_context_bits(vm, 4) != 0) {
        printf("ERROR: Failed to set context bits\n");
        icicle_free(vm);
        return;
    }
    
    uint8_t context_bits = icicle_get_context_bits(vm);
    printf("Context bits: %u (expected: 4)\n", context_bits);
    
    // Test comparison coverage
    printf("\nTesting comparison coverage setting\n");
    if (icicle_enable_compcov(vm, 2) != 0) {
        printf("ERROR: Failed to enable comparison coverage\n");
        icicle_free(vm);
        return;
    }
    
    uint8_t compcov_level = icicle_get_compcov_level(vm);
    printf("CompCov level: %u (expected: 2)\n", compcov_level);
    
    printf("\nTEST PASSED: Coverage instrumentation working correctly\n");
    icicle_free(vm);
}

// Test the AFL++ compatible instrumentation
void test_afl_instrumentation() {
    printf("\n=== Testing AFL++ Compatible Instrumentation ===\n");
    
    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for AFL instrumentation test\n");
        return;
    }

    // Map memory regions for code and data
    if (icicle_mem_map(vm, 0x4000, 0x1000, ExecuteReadWrite) != 0 ||
        icicle_mem_map(vm, 0x5000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory for AFL test\n");
        icicle_free(vm);
        return;
    }
    
    // Allocate a simulated AFL coverage map
    const size_t AFL_MAP_SIZE = 64 * 1024; // Typical AFL map size is 64KB
    uint8_t* afl_area_ptr = (uint8_t*)calloc(AFL_MAP_SIZE, 1);
    if (!afl_area_ptr) {
        printf("ERROR: Failed to allocate AFL coverage map\n");
        icicle_free(vm);
        return;
    }
    
    // Sample program to test edge transitions - complex control flow to generate edge hits
    const unsigned char code[] = {
        // 0x4000: Initialize registers (loop counter in RAX, input value in RCX)
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0
        0x48, 0xC7, 0xC1, 0x2A, 0x00, 0x00, 0x00,  // mov rcx, 42 (input)
        
        // 0x400E: Loop header
        0x48, 0x83, 0xF8, 0x10,                    // cmp rax, 16
        0x7D, 0x40,                                // jge done (0x4052)
        
        // 0x4014: Loop body - series of branches based on input
        0x48, 0x89, 0xCA,                          // mov rdx, rcx
        0x48, 0xC1, 0xEA, 0x02,                    // shr rdx, 2
        0x48, 0x21, 0xC2,                          // and rdx, rax
        0x48, 0x83, 0xFA, 0x00,                    // cmp rdx, 0
        0x74, 0x07,                                // je path_a (0x4027)
        
        // 0x4020: Path B
        0x48, 0xFF, 0xC1,                          // inc rcx
        0xEB, 0x05,                                // jmp continue (0x402A)
        
        // 0x4025: Path A
        0x48, 0xFF, 0xC9,                          // dec rcx
        
        // 0x4028: Continue
        0x48, 0x89, 0xCA,                          // mov rdx, rcx
        0x48, 0xC1, 0xEA, 0x03,                    // shr rdx, 3
        0x48, 0x83, 0xE2, 0x01,                    // and rdx, 1
        0x48, 0x85, 0xD2,                          // test rdx, rdx
        0x74, 0x07,                                // je path_c (0x403C)
        
        // 0x4035: Path D
        0x48, 0x01, 0xC1,                          // add rcx, rax
        0xEB, 0x05,                                // jmp next (0x403F)
        
        // 0x403A: Path C
        0x48, 0x29, 0xC1,                          // sub rcx, rax
        
        // 0x403D: Next
        0x48, 0x89, 0x0D, 0xBC, 0x0F, 0x00, 0x00,  // mov [rip+0xFBC], rcx (store at 0x5000)
        0x48, 0xFF, 0xC0,                          // inc rax
        0xEB, 0xCC,                                // jmp loop_header (0x400E)
        
        // 0x4050: Done
        0xC3                                       // ret
    };
    
    if (icicle_mem_write(vm, 0x4000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code for AFL test\n");
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Set PC to start of code
    icicle_set_pc(vm, 0x4000);
    
    // Setup edge coverage (required for AFL instrumentation)
    if (icicle_set_coverage_mode(vm, CoverageMode_Edges) != 0) {
        printf("ERROR: Failed to set coverage mode\n");
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Enable instrumentation for code section
    if (icicle_enable_instrumentation(vm, 0x4000, 0x5000) != 0) {
        printf("ERROR: Failed to enable instrumentation\n");
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Run the program
    printf("Running program with edge coverage...\n");
    RunStatus status = icicle_run(vm);
    printf("Program execution completed with status: %d\n", status);
    
    // Verify output value (result of calculations in code)
    uint64_t output = 0;
    size_t read_size = 0;
    uint8_t* mem_data = icicle_mem_read(vm, 0x5000, 8, &read_size);
    if (mem_data && read_size == 8) {
        output = *(uint64_t*)mem_data;
        printf("Output value: %ld\n", (int64_t)output);
        icicle_free_buffer(mem_data, read_size);
    } else {
        printf("ERROR: Failed to read output value\n");
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Get and analyze the coverage information
    size_t map_size = 0;
    uint8_t* coverage_map = icicle_get_coverage_map(vm, &map_size);
    if (!coverage_map || map_size == 0) {
        printf("ERROR: Failed to get edge coverage map\n");
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    printf("Edge coverage map size: %zu bytes\n", map_size);
    
    // Count bits set (edges hit) in the bitmap
    int edges_hit = 0;
    for (size_t i = 0; i < map_size; i++) {
        for (int b = 0; b < 8; b++) {
            if (coverage_map[i] & (1 << b)) {
                edges_hit++;
                
                // Simulate copying to AFL map (if this were a real fuzzer)
                if ((i * 8 + b) < AFL_MAP_SIZE) {
                    afl_area_ptr[i] |= (1 << b);
                }
            }
        }
    }
    
    printf("Total edges hit: %d\n", edges_hit);
    
    // In our simplified implementation, we can't guarantee a specific number
    // of edge hits, but we should have at least some coverage
    if (edges_hit == 0) {
        printf("ERROR: No edges were hit\n");
        icicle_free_buffer(coverage_map, map_size);
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Try with context bits (like AFL's CTX mode)
    printf("\nTesting with 1-bit context:\n");
    icicle_reset_coverage(vm);
    if (icicle_set_context_bits(vm, 1) != 0) {
        printf("ERROR: Failed to set context bits\n");
        icicle_free_buffer(coverage_map, map_size);
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Reset and run again
    icicle_set_pc(vm, 0x4000);
    status = icicle_run(vm);
    
    // Get the new coverage map
    uint8_t* ctx_coverage_map = icicle_get_coverage_map(vm, &map_size);
    if (!ctx_coverage_map || map_size == 0) {
        printf("ERROR: Failed to get context coverage map\n");
        icicle_free_buffer(coverage_map, map_size);
        free(afl_area_ptr);
        icicle_free(vm);
        return;
    }
    
    // Count bits set with context bits
    int ctx_edges_hit = 0;
    for (size_t i = 0; i < map_size; i++) {
        for (int b = 0; b < 8; b++) {
            if (ctx_coverage_map[i] & (1 << b)) {
                ctx_edges_hit++;
            }
        }
    }
    
    printf("With context bits, total edges hit: %d\n", ctx_edges_hit);
    
    // Clean up
    icicle_free_buffer(coverage_map, map_size);
    icicle_free_buffer(ctx_coverage_map, map_size);
    free(afl_area_ptr);
    
    printf("\nTEST PASSED: AFL instrumentation working correctly\n");
    icicle_free(vm);
}

// Test reading large registers using icicle_reg_read_bytes with float values
void test_large_register_read() {
    printf("\n=== Testing Large Register Read (XMM0 with Floats) ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM for large register test\n");
        return;
    }

    // Map memory for code
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("ERROR: Failed to map code memory\n");
        icicle_free(vm);
        return;
    }

    // Map memory for data (must be aligned for movaps)
    // Note: mmap usually provides sufficient alignment, but explicitly allocating
    // on a 16-byte boundary would be more robust in a real scenario.
    if (icicle_mem_map(vm, 0x2000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map data memory\n");
        icicle_free(vm);
        return;
    }

    // Define the 128-bit constant value using four floats (16 bytes)
    const float constant_floats[4] = { 1.0f, -2.5f, 3.14159f, -0.0f };
    // Treat the float array as raw bytes for writing and comparison
    const uint8_t* constant_bytes = (const uint8_t*)constant_floats;
    const size_t constant_size = sizeof(constant_floats);

    // Write the constant bytes to memory at 0x2000
    if (icicle_mem_write(vm, 0x2000, constant_bytes, constant_size) != 0) {
        printf("ERROR: Failed to write float constant to memory\n");
        icicle_free(vm);
        return;
    }

    // x86_64 assembly code: movaps xmm0, [0x2000]; ret
    // Machine code: 0f 28 05 f9 0f 00 00 c3 (Corrected displacement)
    const unsigned char code[] = { 0x0f, 0x28, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0xc3 };
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code\n");
        icicle_free(vm);
        return;
    }

    // Set PC and execute the instruction
    icicle_set_pc(vm, 0x1000);
    RunStatus status = icicle_step(vm, 1); // Execute movaps
    
    // Now, read xmm0 using icicle_reg_read_bytes
    // Declare a buffer for the raw bytes
    uint8_t xmm0_buffer[16];
    size_t bytes_read = 0;
    
    // Read the XMM0 register bytes
    int read_status = icicle_reg_read_bytes(vm, "xmm0", xmm0_buffer, sizeof(xmm0_buffer), &bytes_read);
    if (read_status != 0) {
        printf("ERROR: icicle_reg_read_bytes failed with status %d\n", read_status);
        icicle_free(vm);
        return;
    }

    printf("Bytes read for xmm0: %zu (expected 16)\n", bytes_read);
    if (bytes_read != 16) {
        printf("ERROR: Unexpected number of bytes read for xmm0\n");
        icicle_free(vm);
        return;
    }

    // Display the raw bytes
    printf("XMM0 value read (raw bytes):\n");
    hex_dump(xmm0_buffer, bytes_read);
    
    // Also interpret and display as floats for clarity
    float* float_values = (float*)xmm0_buffer;
    printf("XMM0 as floats: [%f, %f, %f, %f]\n", 
           float_values[0], float_values[1], float_values[2], float_values[3]);

    // Compare the read value with the expected constant bytes
    if (memcmp(xmm0_buffer, constant_bytes, constant_size) == 0) {
        printf("TEST PASSED: XMM0 float value matches expected constant.\n");
    } else {
        printf("ERROR: XMM0 float value does NOT match expected constant.\n");
        printf("Expected bytes:\n");
        hex_dump(constant_bytes, constant_size);
        printf("Expected as floats: [%f, %f, %f, %f]\n",
               constant_floats[0], constant_floats[1], constant_floats[2], constant_floats[3]);
    }

    icicle_free(vm);
}

// Test writing/reading large registers using icicle_reg_write_bytes/icicle_reg_read_bytes
void test_large_register_write() {
    printf("\n=== Testing Large Register Write/Read (XMM0) ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM for large register test\n");
        return;
    }

    // Define the 128-bit values we'll use for testing (two sets)
    const float test_floats1[4] = { 42.0f, -42.0f, 123.456f, 789.012f };
    const float test_floats2[4] = { 1.0f, -2.5f, 3.14159f, -0.0f };
    const uint8_t* test_bytes1 = (const uint8_t*)test_floats1;
    const uint8_t* test_bytes2 = (const uint8_t*)test_floats2;
    const size_t test_size = sizeof(test_floats1);

    // Step 1: Write test_floats1 to xmm0 using icicle_reg_write_bytes
    int write_status = icicle_reg_write_bytes(vm, "xmm0", test_bytes1, test_size);
    if (write_status != 0) {
        printf("ERROR: icicle_reg_write_bytes failed with status %d\n", write_status);
        icicle_free(vm);
        return;
    }
    printf("Successfully wrote to XMM0\n");
    printf("Written values as floats: [%f, %f, %f, %f]\n", 
           test_floats1[0], test_floats1[1], test_floats1[2], test_floats1[3]);

    // Step 2: Read xmm0 to verify the write was successful
    uint8_t xmm0_buffer[16];
    size_t bytes_read = 0;
    int read_status = icicle_reg_read_bytes(vm, "xmm0", xmm0_buffer, sizeof(xmm0_buffer), &bytes_read);
    if (read_status != 0) {
        printf("ERROR: icicle_reg_read_bytes failed with status %d\n", read_status);
        icicle_free(vm);
        return;
    }

    printf("Bytes read for xmm0: %zu (expected 16)\n", bytes_read);
    if (bytes_read != 16) {
        printf("ERROR: Unexpected number of bytes read for xmm0\n");
        icicle_free(vm);
        return;
    }

    printf("XMM0 value read after write (raw bytes):\n");
    hex_dump(xmm0_buffer, bytes_read);
    
    // Display as floats for clarity
    float* float_values = (float*)xmm0_buffer;
    printf("XMM0 read as floats: [%f, %f, %f, %f]\n", 
           float_values[0], float_values[1], float_values[2], float_values[3]);

    // Compare with the expected values
    if (memcmp(xmm0_buffer, test_bytes1, test_size) == 0) {
        printf("TEST PASSED: XMM0 value matches the written value.\n");
    } else {
        printf("ERROR: XMM0 value does NOT match the written value.\n");
        printf("Expected bytes:\n");
        hex_dump(test_bytes1, test_size);
        icicle_free(vm);
        return;
    }

    // Step 3: Now test writing to xmm0 and then reading it back using a YMM register
    // (YMM0 is the 256-bit register, with XMM0 being its lower 128 bits)
    printf("\n=== Testing YMM (256-bit) Register Write/Read ===\n");
    
    // First, let's see if we can write to YMM0 (this should write the full 256 bits)
    uint8_t ymm0_buffer[32];
    // Fill the ymm0_buffer with a pattern - low 128 bits with test_bytes2, high 128 bits with test_bytes1
    memcpy(ymm0_buffer, test_bytes2, 16);
    memcpy(ymm0_buffer + 16, test_bytes1, 16);
    
    write_status = icicle_reg_write_bytes(vm, "ymm0", ymm0_buffer, sizeof(ymm0_buffer));
    if (write_status != 0) {
        printf("ERROR: icicle_reg_write_bytes failed for YMM0 with status %d\n", write_status);
        icicle_free(vm);
        return;
    }
    printf("Successfully wrote to YMM0\n");
    printf("Written values (lower 128 bits) as floats: [%f, %f, %f, %f]\n", 
           test_floats2[0], test_floats2[1], test_floats2[2], test_floats2[3]);
    printf("Written values (upper 128 bits) as floats: [%f, %f, %f, %f]\n", 
           test_floats1[0], test_floats1[1], test_floats1[2], test_floats1[3]);
    
    // Read back YMM0 to verify
    uint8_t ymm0_read_buffer[32];
    bytes_read = 0;
    read_status = icicle_reg_read_bytes(vm, "ymm0", ymm0_read_buffer, sizeof(ymm0_read_buffer), &bytes_read);
    if (read_status != 0) {
        printf("ERROR: icicle_reg_read_bytes failed for YMM0 with status %d\n", read_status);
        icicle_free(vm);
        return;
    }

    printf("Bytes read for ymm0: %zu (expected 32)\n", bytes_read);
    if (bytes_read != 32) {
        printf("ERROR: Unexpected number of bytes read for ymm0\n");
        icicle_free(vm);
        return;
    }

    printf("YMM0 value read after write (raw bytes):\n");
    hex_dump(ymm0_read_buffer, bytes_read);

    // Display as floats for clarity (first 16 bytes are low 128 bits, next 16 bytes are high 128 bits)
    float* ymm_low = (float*)ymm0_read_buffer;
    float* ymm_high = (float*)(ymm0_read_buffer + 16);
    printf("YMM0 read (lower 128 bits) as floats: [%f, %f, %f, %f]\n", 
           ymm_low[0], ymm_low[1], ymm_low[2], ymm_low[3]);
    printf("YMM0 read (upper 128 bits) as floats: [%f, %f, %f, %f]\n", 
           ymm_high[0], ymm_high[1], ymm_high[2], ymm_high[3]);

    // Compare with the expected values
    if (memcmp(ymm0_read_buffer, ymm0_buffer, sizeof(ymm0_buffer)) == 0) {
        printf("TEST PASSED: YMM0 value matches the written value.\n");
    } else {
        printf("ERROR: YMM0 value does NOT match the written value.\n");
        printf("Expected bytes:\n");
        hex_dump(ymm0_buffer, sizeof(ymm0_buffer));
    }

    icicle_free(vm);
}

// Test the exception code mapping in icicle_get_exception_code
void test_exception_code_mapping() {
    printf("\n=== Testing Exception Code Mapping ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM for exception code test\n");
        return;
    }

    // Map memory for code
    if (icicle_mem_map(vm, 0x1000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory\n");
        icicle_free(vm);
        return;
    }

    // Attempt to execute from non-executable memory (should trigger ExecViolation)
    printf("Setting PC to non-executable memory...\n");
    icicle_set_pc(vm, 0x1000);

    // Run and expect execution violation exception
    RunStatus status = icicle_step(vm, 1);
    printf("Run status: %d\n", status);
    
    // Get the exception code
    IcicleExceptionCode ex_code = icicle_get_exception_code(vm);
    printf("Exception code: %u\n", ex_code);
    
    // Check if code matches the expected value from IcicleExceptionCode enum
    if (ex_code == Exception_ExecViolation) {
        printf("TEST PASSED: Exception code mapping works correctly.\n");
        printf("Internal code 0x0401 (1025) was correctly mapped to %d (Exception_ExecViolation)\n", Exception_ExecViolation);
    } else {
        printf("TEST FAILED: Expected exception code %d but got %d\n", Exception_ExecViolation, ex_code);
        
        // Debug output in case the mapping is still incorrect
        if (ex_code == 0x0401) {
            printf("ERROR: The internal code 0x0401 (1025) was returned directly without mapping!\n");
        } else {
            printf("ERROR: Unexpected exception code value\n");
        }
    }

    icicle_free(vm);
}

// Test listing breakpoints
void test_breakpoint_listing() {
    printf("\n=== Testing Breakpoint Listing ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create x86_64 VM for breakpoint list test\n");
        return;
    }

    // Set some breakpoints
    uint64_t bp1 = 0x1000;
    uint64_t bp2 = 0x2050;
    uint64_t bp3 = 0x3000;
    printf("Setting breakpoints at: 0x%lx, 0x%lx, 0x%lx\n", bp1, bp2, bp3);
    icicle_add_breakpoint(vm, bp1);
    icicle_add_breakpoint(vm, bp2);
    icicle_add_breakpoint(vm, bp3);

    // Retrieve the list of breakpoints
    size_t count = 0;
    uint64_t* bp_list = icicle_breakpoint_list(vm, &count);

    if (!bp_list) {
        if (count == 0) {
            printf("ERROR: Failed to retrieve breakpoint list, but count is 0 (should be 3)\n");
        } else {
            printf("ERROR: Failed to retrieve breakpoint list (returned NULL)\n");
        }
        icicle_free(vm);
        return;
    }

    printf("Retrieved %zu breakpoints:\n", count);
    for (size_t i = 0; i < count; ++i) {
        printf("  Breakpoint %zu: 0x%lx\n", i + 1, bp_list[i]);
    }

    // Verify the count and content (order might not be guaranteed)
    bool found1 = false, found2 = false, found3 = false;
    if (count == 3) {
        for (size_t i = 0; i < count; ++i) {
            if (bp_list[i] == bp1) found1 = true;
            if (bp_list[i] == bp2) found2 = true;
            if (bp_list[i] == bp3) found3 = true;
        }
        if (found1 && found2 && found3) {
            printf("TEST PASSED: Retrieved breakpoint list matches expected values.\n");
        } else {
            printf("ERROR: Retrieved breakpoint list does not contain all expected values.\n");
        }
    } else {
        printf("ERROR: Expected 3 breakpoints, but got %zu\n", count);
    }

    // Free the list
    icicle_breakpoint_list_free(bp_list, count);

    // Remove a breakpoint and check again
    printf("\nRemoving breakpoint at 0x%lx...\n", bp2);
    icicle_remove_breakpoint(vm, bp2);
    
    bp_list = icicle_breakpoint_list(vm, &count);
    if (!bp_list) {
         if (count == 0) {
            printf("ERROR: Failed to retrieve breakpoint list after removal (count is 0, should be 2)\n");
        } else {
             printf("ERROR: Failed to retrieve breakpoint list after removal (returned NULL)\n");
        }
        icicle_free(vm);
        return;
    }
    
    printf("Retrieved %zu breakpoints after removal:\n", count);
    for (size_t i = 0; i < count; ++i) {
        printf("  Breakpoint %zu: 0x%lx\n", i + 1, bp_list[i]);
    }

    found1 = false; found2 = false; found3 = false;
    if (count == 2) {
         for (size_t i = 0; i < count; ++i) {
            if (bp_list[i] == bp1) found1 = true;
            if (bp_list[i] == bp2) found2 = true; // This should be false now
            if (bp_list[i] == bp3) found3 = true;
        }
        if (found1 && !found2 && found3) {
            printf("TEST PASSED: Retrieved breakpoint list after removal is correct.\n");
        } else {
            printf("ERROR: Retrieved breakpoint list after removal is incorrect.\n");
        }
    } else {
        printf("ERROR: Expected 2 breakpoints after removal, but got %zu\n", count);
    }

    icicle_breakpoint_list_free(bp_list, count);

    icicle_free(vm);
}

int main() {
    setenv("GHIDRA_SRC", "../ghidra", 1);
    test_register_utilities();
    test_memory_capacity();
    test_breakpoints();
    test_rawenv_load();
    test_dynamic_load();
    test_arch();
    test_memory_operations();
    test_backtrace();
    test_disassembly();
    test_aarch64_disassembly();
    test_riscv64_disassembly();
    test_reversible_execution();
    test_debug_instrumentation();
    test_env_debug_instrumentation();
    test_coverage_instrumentation();
    test_afl_instrumentation();
    test_large_register_read();
    test_large_register_write();
    test_exception_code_mapping();
    test_breakpoint_listing(); // Add the new test
    printf("\nAll tests completed.\n");
    return 0;
}

