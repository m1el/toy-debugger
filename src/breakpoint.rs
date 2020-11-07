use nix::unistd::Pid;
use nix::sys::ptrace;
use crate::errors::LazyResult;

pub struct Breakpoint {
    pid: Pid,
    pub address: usize,
    enabled: bool,
    original_byte: u8,
}

const INT3: u8 = 0xcc;
impl Breakpoint {
    pub fn new(pid: Pid, address: usize) -> Self {
        Self {
            pid, address,
            enabled: false,
            original_byte: 0,
        }
    }

    pub fn enable(&mut self) -> LazyResult<()> {
        if self.enabled {
            return Ok(())
        }
        let address = self.address as *mut std::ffi::c_void;
        let mut memory = ptrace::read(self.pid, address)?.to_ne_bytes();
        self.original_byte = memory[0];
        memory[0] = INT3;
        let word = usize::from_ne_bytes(memory);
        unsafe {
            ptrace::write(self.pid, address, word as *mut std::ffi::c_void)?;
        }
        self.enabled = true;
        Ok(())
    }

    pub fn disable(&mut self) -> LazyResult<()> {
        if !self.enabled {
            return Ok(())
        }
        let address = self.address as *mut std::ffi::c_void;
        let mut memory = ptrace::read(self.pid, address)?.to_ne_bytes();
        println!("disabling bp, original={}", self.original_byte);
        memory[0] = self.original_byte;
        let word = usize::from_ne_bytes(memory);
        unsafe {
            ptrace::write(self.pid, address, word as *mut std::ffi::c_void)?;
        }
        self.enabled = false;
        Ok(())
    }
}
