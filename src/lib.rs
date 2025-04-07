use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use icicle_cpu::mem::{Mapping, perm, Mmu, ReadAfterHook, WriteHook};
use icicle_cpu::{Cpu, ValueSource, VmExit, ExceptionCode, HookHandler, Regs, ShadowStack, Exception};
use icicle_vm::cpu::{Environment, debug_info::{DebugInfo, SourceLocation}};
use icicle_vm;
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;
use icicle_vm::cpu::mem::{AllocLayout};
use crate::icicle_vm::injector;
use icicle_vm::{
    cpu::{BlockGroup, BlockTable},
    CodeInjector, Vm,
};
use pcode::Op;
use icicle_vm::cpu;

pub type ViolationFunction = extern "C" fn(data: *mut c_void, address: u64, permission: u8, unmapped: c_int) -> c_int;
pub type RawFunction = extern "C" fn(data: *mut c_void);
pub type PtrFunction = extern "C" fn(data: *mut c_void, address: u64);
pub type SyscallHookFunction = extern "C" fn(data: *mut c_void, syscall_nr: u64, args: *const SyscallArgs) -> c_int;

// Define Memory Hook callback types matching ffi.h
pub type MemReadHookFunction = extern "C" fn(data: *mut c_void, address: u64, size: u8, value_read: *const u8);
pub type MemWriteHookFunction = extern "C" fn(data: *mut c_void, address: u64, size: u8, value_written: u64);

// Define SyscallArgs struct matching ffi.h (must be repr(C))
#[repr(C)]
pub struct SyscallArgs {
    pub arg0: u64, // RDI
    pub arg1: u64, // RSI
    pub arg2: u64, // RDX
    pub arg3: u64, // R10
    pub arg4: u64, // R8
    pub arg5: u64, // R9
}

// Hook type identifiers for tracking different hook types
#[repr(C)]
pub enum HookType {
    Memory = 0,
    Execution = 1,
    Syscall = 2,
    Violation = 3,
}

/// Adds a hook for memory access violations (read/write/execute violations and unmapped memory)
/// 
/// When a memory violation occurs, the callback is invoked with:
/// - data: User-provided context pointer
/// - address: The address that caused the violation
/// - permission: The permission that was violated (read/write/execute)
/// - unmapped: 1 if the memory was unmapped, 0 if it was a permission violation
/// 
/// If the callback returns non-zero, the violation will be ignored and execution continues.
/// If the callback returns zero, the emulator will stop with an exception.
///
/// Returns a hook ID on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_violation_hook(
    vm_ptr: *mut Icicle,
    callback: ViolationFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Store the callback in the VM's custom data for when we handle exceptions
    vm.violation_callback = Some((callback, data));

    // Return a fixed ID for the violation hook type
    1
}

/// Adds a hook for syscall interception
/// 
/// When a syscall is executed, the callback is invoked with:
/// - data: User-provided context pointer
/// - syscall_nr: The syscall number
/// - args: Pointer to the syscall arguments
///
/// Returns hook ID 2 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_syscall_hook(
    vm_ptr: *mut Icicle,
    callback: SyscallHookFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };
    vm.syscall_callback = Some((callback, data));
    2
}

/// Adds a hook for code execution (basic block hook)
/// 
/// The callback is invoked before each basic block is executed with:
/// - data: User-provided context pointer
/// - address: The address of the basic block about to be executed
///
/// Returns a unique FFI hook ID (>= 3) on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_execution_hook(
    vm_ptr: *mut Icicle,
    callback: PtrFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Create the hook handler that calls the C callback
    let hook_fn = Box::new(move |_cpu: &mut Cpu, pc: u64| {
        (callback)(data, pc);
    });

    // Add the hook to the core VM and get its internal ID
    let internal_id = vm.vm.cpu.add_hook(hook_fn.clone()); // Clone needed for storage
    
    // Register the injector to activate the hook for all basic blocks
    icicle_vm::injector::register_block_hook_injector(&mut vm.vm, 0, u64::MAX, internal_id);

    // Generate and store the FFI-level hook
    let ffi_hook_id = vm.next_execution_hook_id;
    vm.execution_hooks.insert(ffi_hook_id, hook_fn);
    vm.next_execution_hook_id += 1;

    ffi_hook_id
}

/// Removes a previously registered execution hook using its FFI ID.
/// Note: Due to limitations in the core library, this only removes the hook
/// from FFI tracking; the underlying VM hook might still exist but become inactive
/// if the associated data/callback is dropped.
#[no_mangle]
pub extern "C" fn icicle_remove_execution_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Check if the hook exists in our tracking (IDs >= 3)
    if hook_id < 3 || !vm.execution_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking map.
    // The actual hook closure will be dropped when removed from the map.
    // We cannot remove it from the core VM's hook list.
    vm.execution_hooks.remove(&hook_id);
    // Maybe clear TLB? Unsure if needed for execution hooks.
    // vm.vm.cpu.mem.tlb.clear(); 

    0 // Return success
}

/// Removes a previously registered hook (Violation or Syscall ONLY)
/// Use type-specific removal functions (e.g., icicle_remove_execution_hook) for other types.
#[no_mangle]
pub extern "C" fn icicle_remove_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let mut removed = false;

    if hook_id == 1 { // Violation hook (Managed internally)
        if vm.violation_callback.is_some() {
            vm.violation_callback = None;
            removed = true;
        }
    } else if hook_id == 2 { // Syscall hook (Managed internally)
        if vm.syscall_callback.is_some() {
            vm.syscall_callback = None;
            removed = true;
        }
    } else {
        // This function only handles Violation (1) and Syscall (2) hooks.
        removed = false;
    }

    if removed {
        0 // Return success
    } else {
        // Return error (hook not found, already removed, or not supported for removal)
        -1
    }
}

/// Legacy function to maintain compatibility with existing code
#[no_mangle]
pub extern "C" fn icicle_remove_syscall_hook(vm_ptr: *mut Icicle, hook_id: u32) -> c_int {
    icicle_remove_hook(vm_ptr, hook_id)
}

#[repr(C)]
pub struct RegInfo {
    pub name: *mut c_char, // allocated C string (to be freed by caller)
    pub offset: u32,
    pub size: u8,
}

// ----- Helper for x86 flags handling -----
struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
}

pub struct RawEnvironment {
    debug_info: DebugInfo,
}

impl RawEnvironment {
    pub fn new() -> Self {
        Self { debug_info: DebugInfo::default() }
    }
}

impl icicle_cpu::RegHandler for X86FlagsRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

// ----- C-friendly enums -----

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MemoryProtection {
    NoAccess = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ExecuteOnly = 3,
    ExecuteRead = 4,
    ExecuteReadWrite = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RunStatus {
    Running = 0,
    InstructionLimit = 1,
    Breakpoint = 2,
    Interrupted = 3,
    Halt = 4,
    Killed = 5,
    Deadlock = 6,
    OutOfMemory = 7,
    Unimplemented = 8,
    UnhandledException = 9,
}

/// Helper function to map our MemoryProtection to the underlying permission bits.
fn convert_protection(protection: MemoryProtection) -> u8 {
    match protection {
        MemoryProtection::NoAccess => perm::NONE,
        MemoryProtection::ReadOnly => perm::READ,
        MemoryProtection::ReadWrite => perm::READ | perm::WRITE,
        MemoryProtection::ExecuteOnly => perm::EXEC,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

// ----- The Icicle VM structure -----
// This structure is treated as opaque in the FFI API.
pub struct Icicle {
    architecture: String,
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
    violation_callback: Option<(ViolationFunction, *mut c_void)>,
    syscall_callback: Option<(SyscallHookFunction, *mut c_void)>,
    // Track memory hooks
    mem_read_hooks: HashMap<u32, Box<dyn ReadAfterHook>>,
    mem_write_hooks: HashMap<u32, Box<dyn WriteHook>>,
    next_mem_hook_id: u32,
    // Track execution hooks
    execution_hooks: HashMap<u32, Box<dyn FnMut(&mut Cpu, u64)>>,
    next_execution_hook_id: u32,
}

impl Icicle {
    /// Create a new Icicle instance.
    pub fn new(
        architecture: &str,
        jit: bool,
        jit_mem: bool,
        shadow_stack: bool,
        recompilation: bool,
        track_uninitialized: bool,
        optimize_instructions: bool,
        optimize_block: bool,
        tracing: bool,
    ) -> Result<Self, String> {
        // Prevent mixing '_' and '-'
        if architecture.split('-').count() != 1 {
            return Err(format!("Bad architecture format: {}", architecture));
        }

        if tracing {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .try_init();
        }

        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{}-none", architecture).as_str(),
        );
        if config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(format!("Unknown architecture: {}", architecture));
        }

        config.enable_jit = jit;
        config.enable_jit_mem = jit_mem;
        config.enable_shadow_stack = shadow_stack;
        config.enable_recompilation = recompilation;
        config.track_uninitialized = track_uninitialized;
        config.optimize_instructions = optimize_instructions;
        config.optimize_block = optimize_block;

        let mut vm = icicle_vm::build(&config)
            .map_err(|e| format!("VM build error: {}", e))?;

        let mut regs = HashMap::new();
        let sleigh = &vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        // Special handling for x86 flags
        match config.triple.architecture {
            Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
                let eflags = sleigh.get_reg("eflags").unwrap().var;
                let reg_handler = X86FlagsRegHandler { eflags };
                vm.cpu.add_reg_handler(eflags.id, Box::new(reg_handler));
            }
            _ => {}
        }

        Ok(Icicle {
            architecture: architecture.to_string(),
            vm,
            regs,
            violation_callback: None,
            syscall_callback: None,
            mem_read_hooks: HashMap::new(),
            mem_write_hooks: HashMap::new(),
            next_mem_hook_id: 0, // Start memory IDs at 0
            execution_hooks: HashMap::new(),
            next_execution_hook_id: 3, // Start execution IDs after Violation(1) and Syscall(2)
        })
    }

    // Methods for icicle functions follow:
    pub fn get_icount_limit(&self) -> u64 {
        self.vm.icount_limit
    }

    pub fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    pub fn get_icount(&self) -> u64 {
        self.vm.cpu.icount
    }

    pub fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    pub fn set_pc(&mut self, address: u64) {
        self.vm.cpu.write_pc(address)
    }

    pub fn get_sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.vm.cpu.arch.reg_sp)
    }

    pub fn set_sp(&mut self, address: u64) {
        self.vm.cpu.write_reg(self.vm.cpu.arch.reg_sp, address)
    }

    pub fn get_mem_capacity(&self) -> usize {
        self.vm.cpu.mem.capacity()
    }

    pub fn set_mem_capacity(&mut self, capacity: usize) -> Result<(), String> {
        if self.vm.cpu.mem.set_capacity(capacity) {
            Ok(())
        } else {
            Err("Reducing memory capacity is not supported".to_string())
        }
    }

    pub fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> Result<(), String> {
        let init_perm = if self.vm.cpu.mem.track_uninitialized { perm::NONE } else { perm::INIT };
        let mapping = Mapping {
            perm: convert_protection(protection) | init_perm,
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(format!("Failed to map memory {:#X}[{:#X}]", address, size))
        }
    }

    pub fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), String> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(format!("Failed to unmap memory {:#X}[{:#X}]", address, size))
        }
    }

    pub fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> Result<(), String> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|e| format!("Failed to protect memory {:#X}[{:#X}]: {:?}", address, size, e))?;
        Ok(())
    }

    /// Reads memory into a newly allocated Vec.
    pub fn mem_read(&mut self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; size];
        self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE)
            .map_err(|e| format!("Failed to read memory {:#X}[{:#X}]: {:?}", address, size, e))?;
        Ok(buffer)
    }

    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), String> {
        let size = data.len();
        self.vm.cpu.mem.write_bytes(address, data, perm::NONE)
            .map_err(|e| format!("Failed to write memory {:#X}[{:#X}]: {:?}", address, size, e))
    }

    pub fn reset(&mut self) {
        self.vm.reset();
    }

    pub fn run(&mut self) -> RunStatus {
        let original_exit = self.vm.run();

        match original_exit {
            VmExit::UnhandledException(_) => {
                let cpu = &mut self.vm.cpu;
                let exception_code_val = cpu.exception.code;
                let exception_value = cpu.exception.value;
                
                let is_syscall = exception_code_val == ExceptionCode::Syscall as u32;
                let is_violation = !is_syscall && (
                       exception_code_val == ExceptionCode::ReadUnmapped as u32 ||
                       exception_code_val == ExceptionCode::WriteUnmapped as u32 ||
                       exception_code_val == ExceptionCode::ReadPerm as u32 ||
                       exception_code_val == ExceptionCode::WritePerm as u32 ||
                       exception_code_val == ExceptionCode::ExecViolation as u32);

                if is_violation && self.violation_callback.is_some() {
                    let (callback, data) = self.violation_callback.as_ref().unwrap(); 
                    let address = exception_value;
                    let unmapped = if exception_code_val == ExceptionCode::ReadUnmapped as u32 ||
                                     exception_code_val == ExceptionCode::WriteUnmapped as u32 { 1 } else { 0 };
                    let permission = match exception_code_val { 
                         code if code == ExceptionCode::ReadPerm as u32 || code == ExceptionCode::ReadUnmapped as u32 => perm::READ,
                         code if code == ExceptionCode::WritePerm as u32 || code == ExceptionCode::WriteUnmapped as u32 => perm::WRITE,
                         code if code == ExceptionCode::ExecViolation as u32 => perm::EXEC,
                         _ => 0 };
                    
                    let result = (callback)(*data, address, permission, unmapped);
                    
                    if result != 0 { 
                        if address == 0 && (exception_code_val == ExceptionCode::WriteUnmapped as u32 ||
                                            exception_code_val == ExceptionCode::WritePerm as u32) {
                            let pc = cpu.read_pc(); 
                            cpu.write_pc(pc + 6);    
                        }
                        cpu.exception.clear(); 
                        return self.run(); 
                    } else {
                        return RunStatus::UnhandledException;
                    }

                } else if is_syscall && self.syscall_callback.is_some() {
                    let (callback, data) = self.syscall_callback.as_ref().unwrap(); 
                    
                    let syscall_nr = match cpu.arch.sleigh.get_reg("RAX") {
                        Some(reg) => cpu.read_reg(reg.var),
                        None => u64::MAX, 
                    };
                    let args = SyscallArgs {
                        arg0: match cpu.arch.sleigh.get_reg("RDI") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg1: match cpu.arch.sleigh.get_reg("RSI") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg2: match cpu.arch.sleigh.get_reg("RDX") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg3: match cpu.arch.sleigh.get_reg("R10") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg4: match cpu.arch.sleigh.get_reg("R8")  { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg5: match cpu.arch.sleigh.get_reg("R9")  { Some(r) => cpu.read_reg(r.var), None => 0 },
                    };
                    
                    let callback_result = (callback)(*data, syscall_nr, &args as *const SyscallArgs);

                    match callback_result {
                        0 => { 
                            if syscall_nr == 0x3C { // sys_exit
                                cpu.exception.clear();
                                return RunStatus::Halt;
                            } else {
                                let pc = cpu.read_pc();
                                cpu.write_pc(pc + 2); 
                                cpu.exception.clear();
                                return self.run(); 
                            }
                        }
                        1 => { 
                            let pc = cpu.read_pc();
                            cpu.write_pc(pc + 2); 
                            cpu.exception.clear();
                            return self.run(); 
                        }
                        _ => { 
                            return RunStatus::UnhandledException;
                        }
                    }
                } else {
                    return RunStatus::UnhandledException;
                }
            }
            // Map other VmExit types
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
        }
    }

    pub fn run_until(&mut self, address: u64) -> RunStatus {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    pub fn step(&mut self, count: u64) -> RunStatus {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    pub fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    pub fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
    }
}

fn reg_find<'a>(i: &'a Icicle, name: &str) -> Result<&'a NamedRegister, String> {
    let sleigh = &i.vm.cpu.arch.sleigh;
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(&name.to_lowercase())
                .ok_or(format!("Register not found: {}", name))
        }
        Some(r) => Ok(r),
    }
}

#[no_mangle]
pub extern "C" fn icicle_new(
    architecture: *const c_char,
    jit: bool,
    jit_mem: bool,
    shadow_stack: bool,
    recompilation: bool,
    track_uninitialized: bool,
    optimize_instructions: bool,
    optimize_block: bool,
    tracing: bool,
) -> *mut Icicle {
    if architecture.is_null() {
        return std::ptr::null_mut();
    }
    let c_str = unsafe { CStr::from_ptr(architecture) };
    let arch_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match Icicle::new(
        arch_str,
        jit,
        jit_mem,
        shadow_stack,
        recompilation,
        track_uninitialized,
        optimize_instructions,
        optimize_block,
        tracing,
    ) {
        Ok(vm) => Box::into_raw(Box::new(vm)),
        Err(err) => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_free(ptr: *mut Icicle) {
    if !ptr.is_null() {
        unsafe { Box::from_raw(ptr); }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_icount(ptr: *const Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_icount() }
}

#[no_mangle]
pub extern "C" fn icicle_set_icount(ptr: *mut Icicle, count: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_icount(count); }
}

#[no_mangle]
pub extern "C" fn icicle_get_pc(ptr: *const Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_pc() }
}

#[no_mangle]
pub extern "C" fn icicle_set_pc(ptr: *mut Icicle, addr: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_pc(addr); }
}

#[no_mangle]
pub extern "C" fn icicle_reset(ptr: *mut Icicle) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).reset(); }
}

#[no_mangle]
pub extern "C" fn icicle_run(ptr: *mut Icicle) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).run() }
}

#[no_mangle]
pub extern "C" fn icicle_step(ptr: *mut Icicle, count: u64) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).step(count) }
}

#[no_mangle]
pub extern "C" fn icicle_mem_map(ptr: *mut Icicle, address: u64, size: u64, protection: MemoryProtection) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_map(address, size, protection) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_unmap(ptr: *mut Icicle, address: u64, size: u64) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_unmap(address, size) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_protect(ptr: *mut Icicle, address: u64, size: usize, protection: MemoryProtection) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_protect(address, size, protection) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_read(ptr: *mut Icicle, address: u64, size: usize, out_size: *mut usize) -> *mut c_uchar {
    if ptr.is_null() || out_size.is_null() {
        return std::ptr::null_mut();
    }
    let res = unsafe { (*ptr).mem_read(address, size) };
    match res {
        Ok(buffer) => {
            let len = buffer.len();
            unsafe { *out_size = len; }
            let mut buf = buffer.into_boxed_slice();
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            ptr
        }
        Err(err) => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_write(ptr: *mut Icicle, address: u64, data: *const c_uchar, size: usize) -> c_int {
    if ptr.is_null() || data.is_null() {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    let res = unsafe { (*ptr).mem_write(address, slice) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_free_buffer(buffer: *mut c_uchar, size: usize) {
    if buffer.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(buffer, size));
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_read(vm_ptr: *mut Icicle, reg_name: *const c_char, out_value: *mut u64) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() || out_value.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => {
            let value = vm.vm.cpu.read_reg(reg.var);
            unsafe { *out_value = value; }
            0
        }
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_write(vm_ptr: *mut Icicle, reg_name: *const c_char, value: u64) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => {
            if reg.var == vm.vm.cpu.arch.reg_pc {
                vm.vm.cpu.write_pc(value);
            } else {
                vm.vm.cpu.write_reg(reg.var, value);
            }
            0
        }
        Err(err) => {
            
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_sp(ptr: *mut Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_sp() }
}

#[no_mangle]
pub extern "C" fn icicle_set_sp(ptr: *mut Icicle, addr: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_sp(addr); }
}

#[no_mangle]
pub extern "C" fn icicle_reg_list(vm_ptr: *mut Icicle, out_count: *mut usize) -> *mut RegInfo {
    if vm_ptr.is_null() || out_count.is_null() {
        return ptr::null_mut();
    }
    let vm = unsafe { &*vm_ptr };
    let sleigh = &vm.vm.cpu.arch.sleigh;
    let mut regs_vec: Vec<RegInfo> = Vec::new();
    for reg in &sleigh.named_registers {
        let name = sleigh.get_str(reg.name);
        let cstring = match CString::new(name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        regs_vec.push(RegInfo {
            name: cstring.into_raw(),
            offset: reg.offset,
            size: reg.var.size,
        });
    }
    unsafe {
        *out_count = regs_vec.len();
    }
    let boxed_slice = regs_vec.into_boxed_slice();
    Box::into_raw(boxed_slice) as *mut RegInfo
}

#[no_mangle]
pub extern "C" fn icicle_reg_list_free(regs: *mut RegInfo, count: usize) {
    if regs.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(regs, count);
        for reg in &mut *slice {
            if !reg.name.is_null() {
                let _ = CString::from_raw(reg.name);
            }
        }
        let _ = Box::from_raw(slice as *mut [RegInfo]);
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_size(vm_ptr: *mut Icicle, reg_name: *const c_char) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() {
        return -1;
    }
    let vm = unsafe { &*vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => reg.var.size as c_int,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_mem_capacity(ptr: *mut Icicle) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_mem_capacity() }
}

#[no_mangle]
pub extern "C" fn icicle_set_mem_capacity(ptr: *mut Icicle, capacity: usize) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *ptr };
    let current_capacity = vm.get_mem_capacity();
    
    if capacity < current_capacity {
        return -1;
    }

    match vm.set_mem_capacity(capacity) {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_add_breakpoint(ptr: *mut Icicle, address: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let added = unsafe { (*ptr).add_breakpoint(address) };
    if added { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn icicle_remove_breakpoint(ptr: *mut Icicle, address: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let removed = unsafe { (*ptr).remove_breakpoint(address) };
    if removed { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn icicle_run_until(ptr: *mut Icicle, address: u64) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).run_until(address) }
}

impl Environment for RawEnvironment {
    fn load(&mut self, cpu: &mut Cpu, code_bytes: &[u8]) -> Result<(), String> {
        let layout = AllocLayout { addr: Some(0x10000), size: 0x1000, align: 0x1000 };

        let base_addr = cpu
            .mem
            .alloc_memory(layout, Mapping { perm: perm::MAP, value: 0xaa })
            .map_err(|e| format!("Failed to allocate memory: {e:?}"))?;

        cpu.mem.update_perm(layout.addr.unwrap(), layout.size, perm::EXEC | perm::READ)
            .map_err(|e| format!("Failed to update perm: {e:?}"))?;

        cpu.mem.write_bytes(base_addr, code_bytes, perm::NONE)
            .map_err(|e| format!("Failed to write memory: {e:?}"))?;

        (cpu.arch.on_boot)(cpu, base_addr);

        Ok(())
    }

    fn handle_exception(&mut self, _: &mut Cpu) -> Option<VmExit> { None }

    fn symbolize_addr(&mut self, _: &mut Cpu, addr: u64) -> Option<SourceLocation> {
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        self.debug_info.symbols.resolve_sym(symbol)
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_new() -> *mut RawEnvironment {
    Box::into_raw(Box::new(RawEnvironment::new()))
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_free(env: *mut RawEnvironment) {
    if !env.is_null() {
        unsafe { Box::from_raw(env); }
    }
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_load(
    env: *mut RawEnvironment,
    cpu: *mut std::os::raw::c_void,
    code: *const c_uchar,
    size: usize,
) -> c_int {
    if env.is_null() || cpu.is_null() || code.is_null() {
        return -1;
    }
    let cpu = unsafe { &mut *(cpu as *mut Cpu) };
    let code_slice = unsafe { std::slice::from_raw_parts(code, size) };
    match unsafe { &mut *env }.load(cpu, code_slice) {
        Ok(()) => 0,
        Err(e) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_cpu_ptr(vm_ptr: *mut Icicle) -> *mut Cpu {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    unsafe { &mut *(*vm_ptr).vm.cpu }
}

// --- FFI Functions for Memory Hooks ---

#[no_mangle]
pub extern "C" fn icicle_add_mem_read_hook(
    vm_ptr: *mut Icicle,
    callback: MemReadHookFunction,
    data: *mut c_void,
    start_addr: u64,
    end_addr: u64,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    let wrapper = ReadHookWrapper {
        callback,
        user_data: data,
    };

    // Generate a new hook ID
    let hook_id = vm.mem_read_hooks.len() as u32;
    
    // Store the wrapper in our tracking map
    vm.mem_read_hooks.insert(hook_id, Box::new(wrapper.clone()));

    // Add the hook to the MMU
    match vm.vm.cpu.mem.add_read_after_hook(start_addr, end_addr, Box::new(wrapper)) {
        Some(_) => {
            hook_id
        }
        None => {
            // Clean up our tracking if MMU addition failed
            vm.mem_read_hooks.remove(&hook_id);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_add_mem_write_hook(
    vm_ptr: *mut Icicle,
    callback: MemWriteHookFunction,
    data: *mut c_void,
    start_addr: u64,
    end_addr: u64,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    let wrapper = WriteHookWrapper {
        callback,
        user_data: data,
    };

    // Generate a new hook ID
    let hook_id = vm.mem_write_hooks.len() as u32;
    
    // Store the wrapper in our tracking map
    vm.mem_write_hooks.insert(hook_id, Box::new(wrapper.clone()));

    // Add the hook to the MMU
    match vm.vm.cpu.mem.add_write_hook(start_addr, end_addr, Box::new(wrapper)) {
        Some(_) => {
            hook_id
        }
        None => {
            // Clean up our tracking if MMU addition failed
            vm.mem_write_hooks.remove(&hook_id);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_remove_mem_read_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Check if the hook exists in our tracking
    if !vm.mem_read_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking
    vm.mem_read_hooks.remove(&hook_id);
    vm.vm.cpu.mem.tlb.clear(); // Clear TLB to ensure changes take effect
    
    0
}

#[no_mangle]
pub extern "C" fn icicle_remove_mem_write_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Check if the hook exists in our tracking
    if !vm.mem_write_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking
    vm.mem_write_hooks.remove(&hook_id);
    vm.vm.cpu.mem.tlb.clear(); // Clear TLB to ensure changes take effect
    
    0
}


// Wrapper for ReadAfterHook
#[derive(Clone)]
struct ReadHookWrapper {
    callback: MemReadHookFunction,
    user_data: *mut c_void,
}

// We need to mark the wrapper as Send + Sync potentially if hooks can be called cross-thread,
// although for this FFI it might not be strictly necessary if called synchronously.
// For safety, let's assume the underlying hook mechanism might require it.
unsafe impl Send for ReadHookWrapper {}
unsafe impl Sync for ReadHookWrapper {}

impl ReadAfterHook for ReadHookWrapper {
    fn read(&mut self, _mmu: &mut Mmu, addr: u64, value: &[u8]) {
        let size = value.len() as u8;
        (self.callback)(self.user_data, addr, size, value.as_ptr());
    }
}

// Wrapper for WriteHook
#[derive(Clone)]
struct WriteHookWrapper {
    callback: MemWriteHookFunction,
    user_data: *mut c_void,
}

unsafe impl Send for WriteHookWrapper {}
unsafe impl Sync for WriteHookWrapper {}

impl WriteHook for WriteHookWrapper {
    fn write(&mut self, _mmu: &mut Mmu, addr: u64, value: &[u8]) {
        let size = value.len() as u8;
        let mut bytes = [0u8; 8];
        let len = size.min(8) as usize;
        bytes[..len].copy_from_slice(&value[..len]);
        let value_u64 = u64::from_le_bytes(bytes);
        (self.callback)(self.user_data, addr, size, value_u64);
    }
}

#[repr(C)]
pub struct CpuSnapshot {
    regs: *mut Regs,
    args: [u128; 8],
    shadow_stack: *mut ShadowStack,
    exception_code: u32,
    exception_value: u64,
    pending_exception: *mut Option<Exception>,
    icount: u64,
    block_id: u64,
    block_offset: u64,
}

#[no_mangle]
pub extern "C" fn icicle_cpu_snapshot(vm: *mut Icicle) -> *mut CpuSnapshot {
    if vm.is_null() {
        return std::ptr::null_mut();
    }

    let vm = unsafe { &*vm };
    let snapshot = vm.vm.cpu.snapshot();
    
    // Convert the snapshot into a C-compatible format
    let c_snapshot = Box::new(CpuSnapshot {
        regs: Box::into_raw(Box::new((*snapshot).regs.clone())),
        args: (*snapshot).args,
        shadow_stack: Box::into_raw(Box::new((*snapshot).shadow_stack.clone())),
        exception_code: (*snapshot).exception.code,
        exception_value: (*snapshot).exception.value,
        pending_exception: Box::into_raw(Box::new((*snapshot).pending_exception.clone())),
        icount: (*snapshot).icount,
        block_id: (*snapshot).block_id,
        block_offset: (*snapshot).block_offset,
    });

    Box::into_raw(c_snapshot)
}

#[no_mangle]
pub extern "C" fn icicle_cpu_restore(vm: *mut Icicle, snapshot: *const CpuSnapshot) -> i32 {
    if vm.is_null() || snapshot.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *vm };
    let snapshot = unsafe { &*snapshot };

    // Create a new CPU snapshot with the correct types
    let rust_snapshot = Box::new(icicle_cpu::CpuSnapshot {
        regs: unsafe { (*snapshot.regs).clone() },
        args: snapshot.args,
        shadow_stack: unsafe { (*snapshot.shadow_stack).clone() },
        exception: Exception {
            code: snapshot.exception_code,
            value: snapshot.exception_value,
        },
        pending_exception: unsafe { (*snapshot.pending_exception).clone() },
        icount: snapshot.icount,
        block_id: snapshot.block_id,
        block_offset: snapshot.block_offset,
    });

    vm.vm.cpu.restore(&*rust_snapshot);
    0
}

#[no_mangle]
pub extern "C" fn icicle_cpu_snapshot_free(snapshot: *mut CpuSnapshot) {
    if !snapshot.is_null() {
        unsafe {
            let snapshot = Box::from_raw(snapshot);
            Box::from_raw(snapshot.regs);
            Box::from_raw(snapshot.shadow_stack);
            Box::from_raw(snapshot.pending_exception);
        }
    }
}

#[repr(C)]
pub struct VmSnapshot {
    cpu: *mut CpuSnapshot,
    mem: *mut icicle_vm::Snapshot,
    env: *mut Box<dyn std::any::Any>,
}

#[no_mangle]
pub extern "C" fn icicle_vm_snapshot(vm: *mut Icicle) -> *mut VmSnapshot {
    if vm.is_null() {
        return std::ptr::null_mut();
    }

    let vm = unsafe { &mut *vm };
    let snapshot = vm.vm.snapshot();

    // Convert the snapshot into a C-compatible format
    let c_snapshot = Box::new(VmSnapshot {
        cpu: Box::into_raw(Box::new(CpuSnapshot {
            regs: Box::into_raw(Box::new((*snapshot.cpu).regs.clone())),
            args: (*snapshot.cpu).args,
            shadow_stack: Box::into_raw(Box::new((*snapshot.cpu).shadow_stack.clone())),
            exception_code: (*snapshot.cpu).exception.code,
            exception_value: (*snapshot.cpu).exception.value,
            pending_exception: Box::into_raw(Box::new((*snapshot.cpu).pending_exception.clone())),
            icount: (*snapshot.cpu).icount,
            block_id: (*snapshot.cpu).block_id,
            block_offset: (*snapshot.cpu).block_offset,
        })),
        mem: Box::into_raw(Box::new(snapshot)),
        env: Box::into_raw(Box::new(Box::new(()))), // Empty environment for now
    });

    Box::into_raw(c_snapshot)
}

#[no_mangle]
pub extern "C" fn icicle_vm_restore(vm: *mut Icicle, snapshot: *const VmSnapshot) -> i32 {
    if vm.is_null() || snapshot.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *vm };
    let snapshot = unsafe { &*snapshot };
    let snapshot = unsafe { &*snapshot.mem };

    vm.vm.restore(snapshot);
    0
}

#[no_mangle]
pub extern "C" fn icicle_vm_snapshot_free(snapshot: *mut VmSnapshot) {
    if !snapshot.is_null() {
        unsafe {
            let snapshot = Box::from_raw(snapshot);
            icicle_cpu_snapshot_free(snapshot.cpu);
            Box::from_raw(snapshot.mem);
            Box::from_raw(snapshot.env);
        }
    }
}
