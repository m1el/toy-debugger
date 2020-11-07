use std::ffi::CStr;
use nix::unistd::{execvp, fork, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::ptrace;

mod breakpoint;
mod errors;
mod memory_maps;
mod syscalls;

use breakpoint::Breakpoint;
use errors::LazyResult;
use memory_maps::{translate_address, read_memory_maps};
use syscalls::SYSCALL_NAMES_X86_64;

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
