use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use icicle_cpu::mem::{Mapping, perm};
use icicle_cpu::{Cpu, ValueSource, VmExit};
use icicle_vm::cpu::{Environment, debug_info::{DebugInfo, SourceLocation}};
use icicle_vm;
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;
use icicle_vm::cpu::mem::{AllocLayout};

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
        match self.vm.run() {
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
            VmExit::UnhandledException(_) => RunStatus::UnhandledException,
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

// ----- New: Register Read/Write Support -----

// Convert the register name lookup to a standard Result.
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

// ----- FFI Interface -----

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
            eprintln!("icicle_new error: {}", err);
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
            eprintln!("icicle_mem_map error: {}", err);
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
            eprintln!("icicle_mem_unmap error: {}", err);
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
            eprintln!("icicle_mem_protect error: {}", err);
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
            eprintln!("icicle_mem_read error: {}", err);
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
            eprintln!("icicle_mem_write error: {}", err);
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

// ----- New: FFI for Register Read/Write -----

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
            eprintln!("icicle_reg_read error: {}", err);
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
            // If writing to the PC register, use set_pc.
            if reg.var == vm.vm.cpu.arch.reg_pc {
                vm.vm.cpu.write_pc(value);
            } else {
                vm.vm.cpu.write_reg(reg.var, value);
            }
            0
        }
        Err(err) => {
            eprintln!("icicle_reg_write error: {}", err);
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

// FFI function: Set the stack pointer.
#[no_mangle]
pub extern "C" fn icicle_set_sp(ptr: *mut Icicle, addr: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_sp(addr); }
}

// FFI function: Return a list of registers.
// On success, out_count is set to the number of registers and a pointer to an array of RegInfo is returned.
// The caller must free the array by calling icicle_reg_list_free.
#[no_mangle]
pub extern "C" fn icicle_reg_list(vm_ptr: *mut Icicle, out_count: *mut usize) -> *mut RegInfo {
    if vm_ptr.is_null() || out_count.is_null() {
        return ptr::null_mut();
    }
    let vm = unsafe { &*vm_ptr };
    let sleigh = &vm.vm.cpu.arch.sleigh;
    // Build a vector of RegInfo.
    let mut regs_vec: Vec<RegInfo> = Vec::new();
    for reg in &sleigh.named_registers {
        let name = sleigh.get_str(reg.name);
        // Allocate a C string for the register name.
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
    // Set out_count.
    unsafe {
        *out_count = regs_vec.len();
    }
    // Convert vector into a heap-allocated array.
    let boxed_slice = regs_vec.into_boxed_slice();
    Box::into_raw(boxed_slice) as *mut RegInfo
}

// FFI function: Free the register list returned by icicle_reg_list.
#[no_mangle]
pub extern "C" fn icicle_reg_list_free(regs: *mut RegInfo, count: usize) {
    if regs.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(regs, count);
        // Free each register name.
        for reg in &mut *slice {
            if !reg.name.is_null() {
                // Reconstruct CString to free memory.
                let _ = CString::from_raw(reg.name);
            }
        }
        // Then free the slice itself.
        let _ = Box::from_raw(slice as *mut [RegInfo]);
    }
}

// FFI function: Return the size of the register specified by name.
// Returns the size (in bytes) if found, otherwise returns -1.
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
    
    // Prevent reducing memory capacity
    if capacity < current_capacity {
        eprintln!("Attempted to reduce memory capacity: Not allowed.");
        return -1; // Indicate failure
    }

    match vm.set_mem_capacity(capacity) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("icicle_set_mem_capacity error: {}", err);
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

// FFI: Remove a breakpoint at the given address.
// Returns 1 if removed successfully, 0 otherwise.
#[no_mangle]
pub extern "C" fn icicle_remove_breakpoint(ptr: *mut Icicle, address: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let removed = unsafe { (*ptr).remove_breakpoint(address) };
    if removed { 1 } else { 0 }
}

// FFI: Run until the given address is reached (using a breakpoint).
// Returns the RunStatus.
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

        // Without READ we cannot translate the code.
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

// FFI functions for RawEnvironment:
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

/// Loads code into a CPU using the provided RawEnvironment.
/// The CPU pointer is assumed to be of type *mut icicle_vm::cpu::Cpu.
/// Returns 0 on success, -1 on error.
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
    // Cast cpu pointer.
    let cpu = unsafe { &mut *(cpu as *mut Cpu) };
    let code_slice = unsafe { std::slice::from_raw_parts(code, size) };
    match unsafe { &mut *env }.load(cpu, code_slice) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("icicle_rawenv_load error: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_cpu_ptr(vm_ptr: *mut Icicle) -> *mut Cpu {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        // Assuming vm.cpu is a Box<Cpu>, use as_mut() to get a mutable reference to the inner Cpu.
        (*vm_ptr).vm.cpu.as_mut() as *mut Cpu
    }
}
