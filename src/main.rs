use std::ffi::CStr;
use std::io::{Seek, SeekFrom};
use std::fs::File;
use std::collections::BTreeMap;
use libc::user_regs_struct;
use nix::unistd::{execv, fork, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace;

mod breakpoint;
mod errors;
mod elf;
mod memory_maps;
mod syscalls;
pub mod auxv;

use auxv::{AuxilliaryVector, read_auxv};
use breakpoint::Breakpoint;
use elf::{Elf64, Elf64ProgramHeader, parse_elf_info, parse_program_headers};
use errors::LazyResult;
use memory_maps::{MemoryMap};
use syscalls::SYSCALL_NAMES_X86_64;

/// Request system to trace our process and exec the target program with arguments
fn spawn_traceable_child(prog: &str, argv: &[&str]) -> LazyResult<()> {
    // This string will hold all of the necessary zero-terminated values
    // starting from program name, and followed by arguments.
    let mut arena = String::new();
    arena.push_str(prog);
    arena.push('\0');
    for arg in argv {
        arena.push_str(arg);
        arena.push('\0');
    }

    let program_ptr = arena.as_ptr();
    unsafe {
        let program_cstr = CStr::from_ptr(program_ptr as *const i8);
        let mut argv_ptr = Vec::new();
        // Keep track of current position in arena
        let mut pos = prog.len() + 1;
        for arg in argv {
            let cstr = CStr::from_ptr(program_ptr.offset(pos as isize) as *const i8);
            argv_ptr.push(cstr);
            pos += arg.len() + 1;
        }
        ptrace::traceme()?;
        execv(program_cstr, &argv_ptr)?;
    }

    Ok(())
}


struct Debugger {
    mem: File,
    maps: MemoryMap,
    main_path: String,
    elfs: BTreeMap<String, Elf64>,
    auxv: AuxilliaryVector,
    current_syscall: Option<u64>,
    entry_point: usize,
    current_child: Pid,
    breakpoints: BTreeMap<(Pid, usize), Breakpoint>,
    pending_breakpoint_addr: Option<usize>,
}

impl Debugger {
    fn init_with(child: Pid) -> LazyResult<Self> {
        let _ = waitpid(child, None)?;

        let maps = MemoryMap::from_pid(child)
            .map_err(|_| "could not read memory map!")?;
        let mem_path = format!("/proc/{}/mem", child);
        let mem = File::open(mem_path)?;

        let mut elfs = BTreeMap::new();

        let auxv = read_auxv(child)?;
        let entry_point = auxv.get_value(auxv::AT_ENTRY)
            .ok_or("Failed to read entry point from auxilliary vector")?;
        let main_path = maps.find_module(entry_point)
            .ok_or("cannot find memory mapped executable at entry point")?
            .to_string();

        let mut main_file = File::open(&main_path)?;
        let main_elf = parse_elf_info(&mut main_file)?;
        elfs.insert(main_path.clone(), main_elf);

        let mut breakpoints = BTreeMap::new();

        if let Some(interp) = auxv.get_value(auxv::AT_BASE) {
            let ld_so_path = maps.find_module(interp)
                .ok_or("cannot find interpreter module?")?
                .to_string();
            let mut ld_so_file = File::open(&ld_so_path)?;
            let ld_so_elf = parse_elf_info(&mut ld_so_file)?;

            if let Some(export) = ld_so_elf.lookup_export("_dl_debug_state") {
                // TODO: need to bound-check this?
                let addr = interp + export.vaddr;
                println!("dl_debug_state breakpoint {:x?} {:x}", export.vaddr, addr);
                //println!("maps: {:x?}", &maps);
                let mut breakpoint = Breakpoint::new("dl_debug".into(), child, addr);
                breakpoint.enable()?;
                breakpoints.insert((child, addr), breakpoint);
            }
            elfs.insert(ld_so_path.clone(), ld_so_elf);
        }

        println!("elfs loaded: {:?}", elfs.keys().collect::<Vec<&String>>());

        let mut breakpoint = Breakpoint::new("_start".into(), child, entry_point);
        breakpoint.enable()?;
        println!("successfully enabled a breakpoint at entry point.");

        breakpoints.insert((child, entry_point), breakpoint);

        // Set ptrace options
        let mut ptrace_options = ptrace::Options::empty();
        // Distinguish between regular traps and syscall traps
        ptrace_options |= ptrace::Options::PTRACE_O_TRACESYSGOOD;
        ptrace::setoptions(child, ptrace_options)?;

        Ok(Self {
            mem,
            maps,
            main_path,
            elfs,
            auxv,
            entry_point,
            current_syscall: None,
            current_child: child,
            breakpoints,
            pending_breakpoint_addr: None,
        })
    }

    fn update_memory_map(&mut self) -> LazyResult<()> {
        self.maps = MemoryMap::from_pid(self.current_child)
            .map_err(|_| "could not read memory map!")?;
        Ok(())
    }

    fn load_elf(&mut self, path: &str) -> LazyResult<bool> {
        use std::collections::btree_map::Entry;
        match self.elfs.entry(path.into()) {
            Entry::Vacant(entry) => {
                let mut file = File::open(path)?;
                entry.insert(parse_elf_info(&mut file)?);
                Ok(true)
            },
            _ => Ok(false)
        }
    }

    fn handle_startup(&mut self) -> LazyResult<()> {
        self.update_memory_map()?;
        let modules = self.maps.list_modules();
        for module in modules {
            let filename = &module.filename;
            match self.load_elf(filename) {
                Ok(loaded) => if loaded {
                    println!("loaded {}", filename);
                }
                Err(err) => {
                    println!("failed to load module {} {:?}",
                             filename, err);
                }
            }
        }
        Ok(())
    }

    fn handle_breakpoint(&mut self, mut regs: user_regs_struct, pid: Pid)
        -> LazyResult<()>
    {
        let prev_addr = regs.rip.wrapping_sub(1);
        // Test if we just executed a breakpoint
        if let Some(breakpoint) = self.breakpoints.get_mut(&(pid, prev_addr as usize)) {
            println!("hit breakpoint '{}' at {:x}", breakpoint.name, prev_addr);
            regs.rip = prev_addr;
            breakpoint.disable()?;
            ptrace::setregs(pid, regs)?;
            self.pending_breakpoint_addr = Some(prev_addr as usize);
            if breakpoint.address == self.entry_point {
                self.handle_startup()?;
            }
        }

        Ok(())
    }

    fn run_loop(&mut self, pause_on_syscalls: bool) -> LazyResult<()> {
        loop {
            let enable_breakpoint = self.pending_breakpoint_addr.take();
            if enable_breakpoint.is_some() {
                ptrace::step(self.current_child, None)?;
            } else if pause_on_syscalls {
                // Run the child until it hits a breakpoint or a syscal
                ptrace::syscall(self.current_child, None)?;
            } else {
                ptrace::cont(self.current_child, None)?;
            }

            // Wait for the child to hit a trap
            match waitpid(None, None) {
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
                    // if we just resumed from a previous breakpoint, enable it again.
                    if let Some(addr) = enable_breakpoint {
                        if let Some(breakpoint) = self.breakpoints.get_mut(&(pid, addr)) {
                            println!("re-enabling breakpoint at {:x}", addr);
                            breakpoint.enable()?;
                            continue;
                        }
                    }
                    // We have hit a regular trap
                    println!("the child has stopped, pid={} signal={}", pid, signal);
                    let mut regs = ptrace::getregs(pid)?;
                    self.handle_breakpoint(regs, pid)?;
                }
                Ok(WaitStatus::PtraceSyscall(pid)) => {
                    let regs = ptrace::getregs(pid)?;
                    let syscall_name;
                    let exited;
                    if let Some(current_syscall) = self.current_syscall.take() {
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
                        self.current_syscall = Some(regs.orig_rax);
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

        Ok(())
    }
}

fn main() -> LazyResult<()> {
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            // The parent will be the debugger and should know its child pid
            let mut debugger = Debugger::init_with(child)?;
            debugger.run_loop(false)?;
        }
        ForkResult::Child => {
            // The child will be the debuggee and spawn target program
            spawn_traceable_child("/bin/ls", &["/bin/ls"])?;
        }
    }
    Ok(())
}
