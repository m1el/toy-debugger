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

fn parent_fn(child: Pid) -> LazyResult<()> {
    let _ = waitpid(child, None)?;
    // Set ptrace options
    let mut ptrace_options = ptrace::Options::empty();
    // Distinguish between regular traps and syscall traps
    ptrace_options |= ptrace::Options::PTRACE_O_TRACESYSGOOD;
    ptrace::setoptions(child, ptrace_options)?;
    let mut current_syscall = None;

    loop {
        // Run the child until it hits a breakpoint or a syscal
        ptrace::syscall(child, None)?;

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
                println!("syscall={} exited={}", syscall_name, exited);
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
