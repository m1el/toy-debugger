use std::ffi::CStr;
use nix::unistd::{execvp, fork, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace;

mod syscalls;
use syscalls::SYSCALL_NAMES_X86_64;

type LazyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn child_fn() -> LazyResult<()> {
    let program = "ls\0";
    unsafe {
        let progname_ptr = CStr::from_ptr(program.as_ptr() as *const i8);
        ptrace::traceme()?;
        execvp(progname_ptr, &[progname_ptr])?;
    }
    // here we need to start the debuggee
    Ok(())
}

struct Breakpoint {
    pid: Pid,
    address: usize,
    enabled: bool,
    original_byte: u8,
}

const INT3: u8 = 0xcc;
impl Breakpoint {
    fn new(pid: Pid, address: usize) -> Self {
        Self {
            pid, address,
            enabled: false,
            original_byte: 0,
        }
    }

    fn enable(&mut self) -> LazyResult<()> {
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

    fn disable(&mut self) -> LazyResult<()> {
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


#[derive(Debug)]
struct AddressRange {
    start: usize,
    end: usize,
}
struct MemoryPermissions(u8);
impl MemoryPermissions {
    fn new(read: bool, write: bool, execute: bool, private: bool) -> Self {
        let mut perms = 0;
        perms |= (read as u8) << 0;
        perms |= (write as u8) << 1;
        perms |= (execute as u8) << 2;
        perms |= (private as u8) << 3;
        Self(perms)
    }
    fn read(&self) -> bool {
        (self.0 & (1 << 0)) != 0
    }
    fn write(&self) -> bool {
        (self.0 & (1 << 1)) != 0
    }
    fn execute(&self) -> bool {
        (self.0 & (1 << 2)) != 0
    }
    fn private(&self) -> bool {
        (self.0 & (1 << 3)) != 0
    }
}

impl std::fmt::Debug for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let read = if self.read() { 'r' } else { '-' };
        let write = if self.write() { 'w' } else { '-' };
        let execute = if self.execute() { 'x' } else { '-' };
        let private = if self.private() { 'p' } else { '-' };
        write!(f, "{}{}{}{}", read, write, execute, private)
    }
}

impl std::str::FromStr for MemoryPermissions {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 4 {
            Err("invalid memory permissions string!")?;
        }
        let s = s.as_bytes();
        Ok(Self::new(
                s[0] == b'r', s[1] == b'w',
                s[2] == b'x', s[3] == b'p'))
    }
}

#[derive(Debug)]
struct Device(u8, u8);

impl std::str::FromStr for Device {
    type Err = Box<dyn std::error::Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 5 || &s[2..3] != ":" {
            Err("invalid maps file: cannot read device")?;
        }
        let high = u8::from_str_radix(&s[..2], 16)?;
        let low = u8::from_str_radix(&s[3..], 16)?;
        Ok(Device(high, low))
    }
}

#[derive(Debug)]
struct MemoryRegion {
    address_range: AddressRange,
    permissions: MemoryPermissions,
    offset: usize,
    device: Device,
    inode: u64,
    filename: Option<String>, // OSstring?
}

impl std::str::FromStr for MemoryRegion {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut indicies = Vec::new();
        let mut start = 0;
        let max_elements = 6;
        for (ii, chr) in s.char_indices() {
            if chr == ' ' {
                if start != ii {
                    if indicies.len() < max_elements {
                        indicies.push((start, ii));
                    }
                }
                start = ii + 1;
            } else if indicies.len() + 1 == max_elements {
                indicies.push((start, s.len()));
            }
        }

        let words = indicies.iter()
            .map(|&(start, end)| &s[start..end])
            .collect::<Vec<&str>>();

        if words.len() < 5 {
            Err("invalid maps file, too few space-separated columns")?;
        }

        let mut range_it = words[0].split('-');
        let start_str = range_it.next().ok_or("cannot find range start")?;
        let start = usize::from_str_radix(start_str, 16)?;
        let end_str = range_it.next().ok_or("cannot find range end")?;
        let end = usize::from_str_radix(end_str, 16)?;
        let permissions = words[1].parse::<MemoryPermissions>()?;
        let offset = usize::from_str_radix(words[2], 16)?;
        let device = words[3].parse::<Device>()?;
        let inode = words[4].parse::<u64>()?;
        let filename = words.get(5).map(|s| s.to_string());


        Ok(MemoryRegion {
            address_range: AddressRange { start, end },
            permissions,
            offset,
            device,
            inode,
            filename,
        })
    }
}

fn read_memory_maps(pid: Pid) -> LazyResult<Vec<MemoryRegion>> {
    let path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(path)?;

    let mut result = Vec::new();
    for line in content.lines() {
        result.push(line.parse()?);
    }
    Ok(result)
}

// We want to translate a known memory address in the module
// to an address in process's virtual memory
fn translate_address(
    maps: &[MemoryRegion], module: &str, address: usize
) -> Option<usize>
{
    for region in maps {
        // skip memory regions which don't correspond to needle module
        if region.filename.as_ref().map_or(true, |x| x != module) {
            continue;
        }
        let AddressRange { start, end } = region.address_range;
        let size = end - start;
        let offset = region.offset;
        if address > offset && address - offset < size {
            return Some(start + (address - offset))
        }
    }
    // We have failed to find a region, return None
    None
}

fn parent_fn(child: Pid) -> LazyResult<()> {
    // After this call, our child is unpaused
    let _ = waitpid(child, None)?;
    // let's inspect memory maps
    let maps = read_memory_maps(child)?;
    println!("setting up breakpoint at binary entry point...");
    let entry_point = 0x6130;
    let translated_entry = translate_address(&maps, "/bin/ls", entry_point)
        .ok_or("failed to translate entry point!")?;
    let mut breakpoint = Breakpoint::new(child, translated_entry);
    breakpoint.enable()?;
    println!("successfully enabled a breakpoint at entry point.");
    // Set ptrace options
    let mut ptrace_options = ptrace::Options::empty();
    // Distinguish between regular traps and syscall traps
    ptrace_options |= ptrace::Options::PTRACE_O_TRACESYSGOOD;
    ptrace::setoptions(child, ptrace_options)?;
    let mut current_syscall = None;

    let pause_on_syscalls = true;

    loop {
        if pause_on_syscalls {
            // Run the child until it hits a breakpoint or a syscal
            ptrace::syscall(child, None)?;
        } else {
            ptrace::cont(child, None)?;
        }

        // Wait for the child to hit a trap
        match waitpid(child, None) {
            Err(error) => {
                println!("cannot waitpid, the child may have died. error: {:?}", error);
            }
            Ok(WaitStatus::Exited(pid, exit_code)) => {
                // The child has exited, we can break
                // Note: doesn't work for mutliple children
                println!("the child has exited, pid={} exit_status={}", pid, exit_code);
                break;
            }
            Ok(WaitStatus::Stopped(pid, signal)) => {
                // We have hit a regular trap
                println!("the child has stopped, pid={} signal={}", pid, signal);
                let mut regs = ptrace::getregs(pid)?;
                println!("rip: {}, addr: {}", regs.rip, breakpoint.address);
                // Test if we just executed a breakpoint
                if regs.rip == breakpoint.address as u64 + 1 {
                    println!("disabling breakpoint");
                    // rewind rip to the location of breakpoint
                    regs.rip -= 1;
                    // disable breakpoint
                    breakpoint.disable()?;
                    ptrace::setregs(child, regs)?;
                }
            }
            Ok(WaitStatus::PtraceSyscall(pid)) => {
                let regs = ptrace::getregs(pid)?;
                let syscall_name;
                let exited;
                if let Some(current_syscall) = current_syscall.take() {
                    // we have exited a syscall
                    exited = true;
                    syscall_name =
                        SYSCALL_NAMES_X86_64.get(current_syscall as usize)
                            .unwrap_or(&"invalid_syscall");
                } else {
                    exited = false;
                    syscall_name =
                        SYSCALL_NAMES_X86_64.get(regs.orig_rax as usize)
                            .unwrap_or(&"invalid_syscall");
                    // we entered a syscall, store its number
                    current_syscall = Some(regs.orig_rax);
                }
                if !exited {
                    println!("syscall={} exited={}", syscall_name, exited);
                }
            }
            Ok(event) => {
                println!("unhandled ptrace event: {:?}", event)
            }
        }
    }
    // here we need to start the debugger
    Ok(())
}

fn main() -> LazyResult<()> {
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            parent_fn(child)?;
        }
        ForkResult::Child => {
            child_fn()?;
        }
    }
    Ok(())
}
