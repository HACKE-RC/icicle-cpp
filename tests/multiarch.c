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

// Test function for x86_64 architecture.
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


// Main test runner.
int main() {
    test_x86_64();
    test_aarch64();
    test_riscv64();
    test_memory_operations();
    printf("\nAll tests completed.\n");
    return 0;
}

