use std::ffi::CStr;
use std::io::{Seek, SeekFrom};
use std::fs::File;
use std::collections::BTreeMap;
use libc::user_regs_struct;
use nix::unistd::{execvp, fork, ForkResult, Pid};
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

fn child_fn() -> LazyResult<()> {
    let program = "ls\0";
    // path: &str, argv: &[&str]
    // make this accept program and argv
    unsafe {
        let progname_ptr = CStr::from_ptr(program.as_ptr() as *const i8);
        ptrace::traceme()?;
        execvp(progname_ptr, &[progname_ptr])?;
    }
    // here we need to start the debuggee
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
}

impl Debugger {
    fn init_with(child: Pid) -> LazyResult<Self> {
        let _ = waitpid(child, None)?;

        let maps = MemoryMap::from_pid(child)?;
        let mem_path = format!("/proc/{}/mem", child);
        let mem = File::open(mem_path)?;
        let auxv = read_auxv(child)?;
        let entry_point = auxv.get_value(auxv::AT_ENTRY)
            .ok_or("Failed to read entry point from auxilliary vector")?;
        let main_path = maps.find_module(entry_point)
            .ok_or("cannot find memory mapped executable at entry point")?
            .to_string();

        let mut main_file = File::open(&main_path)?;
        let main_elf = parse_elf_info(&mut main_file)?;
        let mut elfs = BTreeMap::new();
        elfs.insert(main_path.clone(), main_elf);

        let mut breakpoints = BTreeMap::new();

        let mut breakpoint = Breakpoint::new(child, entry_point);
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
        })
    }

    fn handle_breakpoint(&mut self, mut regs: user_regs_struct, pid: Pid)
        -> LazyResult<()>
    {
        let prev_addr = regs.rip.wrapping_sub(1);
        // Test if we just executed a breakpoint
        if let Some(breakpoint) = self.breakpoints.get_mut(&(pid, prev_addr as usize)) {
            regs.rip = prev_addr;
            println!("disabling the breakpoint we hit.");
            // TODO: need to enable after single step!
            breakpoint.disable()?;
            ptrace::setregs(pid, regs)?;
        }
        Ok(())
    }

    fn run_loop(&mut self, pause_on_syscalls: bool) -> LazyResult<()> {
        loop {
            if pause_on_syscalls {
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
        // here we need to start the debugger
        Ok(())
    }
}

fn main() -> LazyResult<()> {
    let mut file = std::fs::File::open("/bin/ls")?;
    let info = parse_elf_info(&mut file)?;
    println!("elf info: {:#x?}", info);
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            let mut debugger = Debugger::init_with(child)?;
            debugger.run_loop(true)?;
        }
        ForkResult::Child => {
            child_fn()?;
        }
    }
    Ok(())
}
