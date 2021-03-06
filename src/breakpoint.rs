use nix::unistd::Pid;
use nix::sys::ptrace;
use crate::errors::LazyResult;

pub struct Breakpoint {
    pub name: String,
    pid: Pid,
    pub address: usize,
    enabled: bool,
    original_byte: u8,
}

const INT3: u8 = 0xcc;
impl Breakpoint {
    pub fn new(name: String, pid: Pid, address: usize) -> Self {
        Self {
            name,
            pid, address,
            enabled: false,
            original_byte: 0,
        }
    }

    pub fn enable_in_thread(&mut self, pid: Pid) -> LazyResult<()> {
        if self.enabled {
            return Ok(())
        }
        let address = self.address as *mut std::ffi::c_void;
        let mut memory = ptrace::read(pid, address)?.to_ne_bytes();
        self.original_byte = memory[0];
        memory[0] = INT3;
        let word = usize::from_ne_bytes(memory);
        unsafe {
            // Bug: ptrace::write asks for a pointer, but it uses it as a word!
            ptrace::write(pid, address, word as *mut std::ffi::c_void)?;
        }
        self.enabled = true;
        Ok(())
    }

    pub fn enable(&mut self) -> LazyResult<()> {
        self.enable_in_thread(self.pid)
    }

    //pub fn step_over(current_rip: usize) -> LazyResult<()> {
    //}

    pub fn disable_in_thread(&mut self, pid: Pid) -> LazyResult<()> {
        if !self.enabled {
            return Ok(())
        }
        let address = self.address as *mut std::ffi::c_void;
        let mut memory = ptrace::read(pid, address)?.to_ne_bytes();
        memory[0] = self.original_byte;
        let word = usize::from_ne_bytes(memory);
        unsafe {
            ptrace::write(pid, address, word as *mut std::ffi::c_void)?;
        }
        self.enabled = false;
        Ok(())
    }

    pub fn disable(&mut self) -> LazyResult<()> {
        self.disable_in_thread(self.pid)
    }
}
