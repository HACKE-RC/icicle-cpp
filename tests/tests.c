#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ffi.h>

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
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create x86_64 VM\n");
        return;
    }
    
    // Test get_pc.
    uint64_t pc = icicle_get_pc(vm);
    printf("Initial PC: 0x%lx\n", pc);
    
    // Test set_pc (set to 0x2000).
    icicle_set_pc(vm, 0x2000);
    pc = icicle_get_pc(vm);
    printf("After set_pc, PC: 0x%lx (expected 0x2000)\n", pc);
    
    // Test get_sp and set_sp.
    // First, set SP to 0x3000.
    icicle_set_sp(vm, 0x3000);
    uint64_t sp = icicle_get_sp(vm);
    printf("After set_sp, SP: 0x%lx (expected 0x3000)\n", sp);
    
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
    else
        printf("Failed to read register 'rax'\n");
    
    // Write a new value.
    if (icicle_reg_write(vm, "rax", 0xDEADBEEF) == 0) {
        if (icicle_reg_read(vm, "rax", &rax_val) == 0)
            printf("After write, rax = 0x%lx (expected 0xDEADBEEF)\n", rax_val);
        else
            printf("Failed to read register 'rax' after write\n");
    } else {
        printf("Failed to write register 'rax'\n");
    }
    
    icicle_free(vm);
}

void test_memory_capacity() {
    printf("\n=== Testing Memory Capacity ===\n");
    
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create VM for mem capacity test\n");
        return;
    }
    
    // Get the current memory capacity.
    size_t capacity = icicle_get_mem_capacity(vm);
    printf("Initial memory capacity: %zu bytes\n", capacity);
    
    // Try to set a larger capacity.
    if (icicle_set_mem_capacity(vm, capacity + 0x1000) == 0)
        printf("Memory capacity increased successfully.\n");
    else
        printf("Failed to increase memory capacity.\n");
   
    if (icicle_set_mem_capacity(vm, capacity - 0x1000) != 0)
        printf("Correctly rejected reducing memory capacity.\n");
    else
        printf("ERROR: Unexpectedly allowed reducing memory capacity.\n");

    icicle_free(vm);
}
void test_breakpoints() {
    printf("\n=== Testing Breakpoints ===\n");

    // Create a new x86_64 VM.
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
         printf("Failed to create VM for breakpoints test\n");
         return;
    }

    // Map memory at 0x4000 with execute permission.
    if (icicle_mem_map(vm, 0x4000, 0x1000, ExecuteReadWrite) != 0) {
         printf("Failed to map memory for breakpoints test\n");
         icicle_free(vm);
         return;
    }

    // Write code: mov rax, 0x1234; jmp to self.
    const unsigned char code[] = { 
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
        0xEB, 0xFE                                // jmp to self (infinite loop)
    };
    if (icicle_mem_write(vm, 0x4000, code, sizeof(code)) != 0) {
         printf("Failed to write code for breakpoints test\n");
         icicle_free(vm);
         return;
    }

    // Set PC to start of code.
    icicle_set_pc(vm, 0x4000);

    // Use run_until to run until the address 0x4000 is hit.
    RunStatus status = icicle_run_until(vm, 0x4000);
    printf("Run until breakpoint returned status: %d\n", status);

    // Explicitly test add and remove breakpoint.
    int added = icicle_add_breakpoint(vm, 0x4000);
    printf("Breakpoint added: %d\n", added);
    int removed = icicle_remove_breakpoint(vm, 0x4000);
    printf("Breakpoint removed: %d\n", removed);

    icicle_free(vm);
}

void test_rawenv_load() {
    printf("\n=== Testing RawEnvironment Load ===\n");

    // Create a new RawEnvironment.
    RawEnvironment* env = icicle_rawenv_new();
    if (!env) {
         printf("Failed to create RawEnvironment\n");
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
         printf("Error: Failed to open test_prog.bin\n");
         return;
    }
    
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);
    
    unsigned char *code_buffer = malloc(file_size);
    if (!code_buffer) {
         printf("Error: Memory allocation failure.\n");
         fclose(fp);
         return;
    }
    if (fread(code_buffer, 1, file_size, fp) != file_size) {
         printf("Error: Failed to read file contents.\n");
         free(code_buffer);
         fclose(fp);
         return;
    }
    fclose(fp);

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
         printf("Error: Failed to create VM.\n");
         free(code_buffer);
         return;
    }
    
    if (icicle_mem_map(vm, 0x8000, 0x1000, ExecuteReadWrite) != 0) {
         printf("Error: Memory mapping failed.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    
    // Get the CPU pointer (returns a pointer of type Cpu*).
    Cpu *cpu_ptr = icicle_get_cpu_ptr(vm);
    if (!cpu_ptr) {
         printf("Error: Failed to obtain CPU pointer.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    
    RawEnvironment* env = icicle_rawenv_new();
    if (!env) {
         printf("Error: Failed to create RawEnvironment.\n");
         icicle_free(vm);
         free(code_buffer);
         return;
    }
    int load_status = icicle_rawenv_load(env, cpu_ptr, code_buffer, file_size);
    if (load_status != 0) {
         printf("Error: Failed to load program dynamically.\n");
    } else {
         printf("Success: Program loaded dynamically.\n");
    }
    icicle_rawenv_free(env);
    free(code_buffer);
    
    RunStatus status = icicle_step(vm, 10);
    printf("Run status: %d\n", status);
    
    uint64_t rax = 0;
    if (icicle_reg_read(vm, "rax", &rax) == 0)
         printf("Register RAX: 0x%lx (expected 0xdeadbeef)\n", rax);
    else
         printf("Error: Failed to read RAX.\n");
    
    icicle_free(vm);
}

void test_x86_64() {
    printf("\n=== Testing x86_64 ===\n");

    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create x86_64 VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("Failed to map memory for x86_64\n");
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
        printf("Failed to write code for x86_64\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    icicle_step(vm, 1);  // Step once to execute the mov instruction.

    uint64_t rax = 0;
    if (icicle_reg_read(vm, "rax", &rax) == 0)
        printf("x86_64 RAX = 0x%lx (expected 0x1337)\n", rax);
    else
        printf("Failed to read register RAX for x86_64\n");

    icicle_free(vm);
}

// Test function for ARM64 (AArch64).
void test_aarch64() {
    printf("\n=== Testing AArch64 ===\n");

    Icicle *vm = icicle_new("aarch64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create AArch64 VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("Failed to map memory for AArch64\n");
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
        printf("Failed to write code for AArch64\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    icicle_step(vm, 1);  // Step once to execute the movz instruction.

    uint64_t x0 = 0;
    if (icicle_reg_read(vm, "x0", &x0) == 0)
        printf("AArch64 X0 = 0x%lx (expected 0x5678)\n", x0);
    else
        printf("Failed to read register X0 for AArch64\n");

    icicle_free(vm);
}

// Test function for RISC-V 64-bit.
void test_riscv64() {
    printf("\n=== Testing RISC-V 64 ===\n");

    Icicle *vm = icicle_new("riscv64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create RISC-V VM\n");
        return;
    }

    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0) {
        printf("Failed to map memory for RISC-V\n");
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
        printf("Failed to write code for RISC-V\n");
        icicle_free(vm);
        return;
    }

    icicle_set_pc(vm, 0x1000);
    icicle_step(vm, 1);  // Step once to execute addi.

    uint64_t a0 = 0;
    if (icicle_reg_read(vm, "a0", &a0) == 0)
        printf("RISC-V A0 = 0x%lx (expected 0x123)\n", a0);
    else
        printf("Failed to read register A0 for RISC-V\n");

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
        printf("Failed to create VM for memory test\n");
        return;
    }

    if (icicle_mem_map(vm, 0x3000, 0x1000, ReadWrite) != 0) {
        printf("Failed to map memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    // Write a 4-byte test pattern.
    const unsigned char test_data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    if (icicle_mem_write(vm, 0x3000, test_data, sizeof(test_data)) != 0) {
        printf("Failed to write to memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    // Read back the data.
    size_t out_size = 0;
    unsigned char *read_buffer = icicle_mem_read(vm, 0x3000, sizeof(test_data), &out_size);
    if (!read_buffer) {
        printf("Failed to read memory at 0x3000\n");
        icicle_free(vm);
        return;
    }

    printf("Memory Read Back (%zu bytes):\n", out_size);
    hex_dump(read_buffer, out_size);

    icicle_free_buffer(read_buffer, out_size);
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
    printf("\nAll register utility tests completed.\n");
    return 0;
}

