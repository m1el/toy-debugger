use std::ffi::CStr;
use std::fs::File;
use std::collections::BTreeMap;
use libc::user_regs_struct;
use nix::unistd::{execv, fork, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::{Signal};
use nix::sys::ptrace;

mod breakpoint;
mod errors;
mod elf;
mod memory_maps;
mod syscalls;
pub mod auxv;

use auxv::{AuxilliaryVector, read_auxv};
use breakpoint::Breakpoint;
use elf::{Elf64, parse_elf_info};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ThreadState {
    PtraceStop,
    Running,
}

impl ThreadState {
    fn running(&self) -> bool {
        self == &ThreadState::Running
    }
}

struct Thread {
    current_syscall: Option<usize>,
    step_addr: Option<usize>,
    state: ThreadState
}

struct Process {
    pid: Pid,
    threads: BTreeMap<Pid, Thread>,
}

enum SyscallDir {
    Enter(usize),
    Exit(usize),
}

impl Process {
    fn new(pid: Pid) -> Self {
        let mut threads = BTreeMap::new();
        threads.insert(pid, Thread {
            step_addr: None,
            current_syscall: None,
            state: ThreadState::PtraceStop,
        });

        Self {
            pid,
            threads,
        }
    }

    fn process_syscall(&mut self, tid: Pid, regs: &user_regs_struct)
        -> Option<SyscallDir>
    {
        let thread = self.threads.get_mut(&tid)?;
        thread.state = ThreadState::PtraceStop;
        if let Some(id) = thread.current_syscall {
            thread.current_syscall = None;
            SyscallDir::Exit(id)
        } else {
            let id = regs.orig_rax as usize;
            thread.current_syscall = Some(id);
            SyscallDir::Enter(id)
        }.into()
    }

    fn stop_main(&mut self) {
        if let Some(main) = self.threads.get_mut(&self.pid) {
            main.state = ThreadState::PtraceStop;
        }
    }

    fn add_thread(&mut self, pid: Pid) {
        self.threads.insert(pid, Thread {
            current_syscall: None,
            step_addr: None,
            state: ThreadState::PtraceStop,
        });
    }

    fn exit_pid(&mut self, pid: Pid, _status: i32) -> bool {
        if self.pid == pid {
            self.threads.clear();
            true
        } else {
            self.threads.remove(&pid);
            false
        }
    }
}

struct Debugger {
    // mem: File,
    maps: MemoryMap,
    main_path: String,
    elfs: BTreeMap<String, Elf64>,
    auxv: AuxilliaryVector,
    entry_point: usize,
    process: Process,
    breakpoints: BTreeMap<usize, Breakpoint>,
}

impl Debugger {
    fn init_with(child: Pid) -> LazyResult<Self> {
        let _ = waitpid(child, None)?;

        let maps = MemoryMap::from_pid(child)?;
            //.map_err(|_| "could not read memory map!")?;
        //let mem_path = format!("/proc/{}/mem", child);
        //let mem = File::open(mem_path)?;

        let mut elfs = BTreeMap::new();

        let auxv = read_auxv(child)?;
        let entry_point = auxv.get_value(auxv::AT_ENTRY)
            .ok_or("Failed to read entry point from auxilliary vector")?;
        let (main_path, _addr) = maps.find_module(entry_point)
            .ok_or("cannot find memory mapped executable at entry point")?;
        let main_path = main_path.to_string();

        let mut main_file = File::open(&main_path)?;
        let main_elf = parse_elf_info(&mut main_file)?;
        elfs.insert(main_path.clone(), main_elf);

        let mut breakpoints = BTreeMap::new();

        if let Some(interp) = auxv.get_value(auxv::AT_BASE) {
            let (ld_so_path, _addr) = maps.find_module(interp)
                .ok_or("cannot find interpreter module?")?;
            let ld_so_path = ld_so_path.to_string();
            let mut ld_so_file = File::open(&ld_so_path)?;
            let ld_so_elf = parse_elf_info(&mut ld_so_file)?;

            if let Some(export) = ld_so_elf.lookup_export("_dl_debug_state") {
                // TODO: need to bound-check this?
                let addr = interp + export.vaddr;
                println!("dl_debug_state breakpoint {:x?} {:x}", export.vaddr, addr);
                println!("maps: {:x?}", &maps);
                let mut breakpoint = Breakpoint::new("dl_debug".into(), child, addr);
                breakpoint.enable()?;
                breakpoints.insert(addr, breakpoint);
            }
            elfs.insert(ld_so_path.clone(), ld_so_elf);
        }

        println!("elfs loaded: {:?}", elfs.keys().collect::<Vec<&String>>());

        let mut breakpoint = Breakpoint::new("_start".into(), child, entry_point);
        breakpoint.enable()?;
        println!("successfully enabled a breakpoint at entry point.");

        breakpoints.insert(entry_point, breakpoint);

        // Set ptrace options
        let mut ptrace_options = ptrace::Options::empty();
        // Distinguish between regular traps and syscall stops
        ptrace_options |= ptrace::Options::PTRACE_O_TRACESYSGOOD;
        ptrace_options |= ptrace::Options::PTRACE_O_TRACECLONE;
        ptrace::setoptions(child, ptrace_options)?;

        Ok(Self {
            //mem,
            maps,
            main_path,
            elfs,
            auxv,
            entry_point,
            process: Process::new(child),
            breakpoints,
        })
    }

    fn update_memory_map(&mut self) -> LazyResult<()> {
        self.maps = MemoryMap::from_pid(self.process.pid)
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
                    println!("loaded {} {:x}", filename, module.base_addr);
                }
                Err(err) => {
                    println!("failed to load module {} {:?}",
                             filename, err);
                }
            }
        }
        self.breakpoint_all_the_things()?;
        Ok(())
    }

    fn maybe_breakpoint(
        breakpoints: &mut BTreeMap<usize, Breakpoint>,
        pid: Pid, addr: usize, name: String,
    ) -> LazyResult<bool>
    {
        use std::collections::btree_map::Entry;
        match breakpoints.entry(addr) {
            Entry::Vacant(entry) => {
                let mut breakpoint = Breakpoint::new(name, pid, addr);
                breakpoint.enable()?;
                entry.insert(breakpoint);
                Ok(true)
            }
            _ => Ok(false)
        }
    }

    fn breakpoint_all_the_things(&mut self) -> LazyResult<()> {
        for (path, elf) in self.elfs.iter() {
            let module_base =
                if let Some(addr) = self.maps.module_base(path) {
                    addr
                } else {
                    continue;
                };

            for symbol in &elf.exports {
                if symbol.value == 0 { continue; }
                if !symbol.is_function() { continue; }
                let address = module_base + symbol.value as usize;
                let result = Self::maybe_breakpoint(
                    &mut self.breakpoints,
                    self.process.pid,
                    address, symbol.name.clone());
                match result {
                    Ok(added) => if added {
                        println!("added breakpoint {} at {:x?}",
                                 symbol.name, address);
                    }
                    Err(err) => {
                        println!("failed to add breakpoint at {:x?}, err={:?}",
                                 address, err);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_breakpoint(&mut self, mut regs: user_regs_struct, pid: Pid)
        -> LazyResult<()>
    {
        let thread = if let Some(thread) = self.process.threads.get_mut(&pid) {
            thread
        } else {
            println!("bastard thread pid={:?}", pid);
            return Ok(());
        };
        let prev_addr = regs.rip.wrapping_sub(1);
        // Test if we just executed a breakpoint
        if let Some(breakpoint) = self.breakpoints.get_mut(&(prev_addr as usize)) {
            println!("hit breakpoint '{}' at {:x}", breakpoint.name, prev_addr);
            regs.rip = prev_addr;
            breakpoint.disable_in_thread(pid)?;
            ptrace::setregs(pid, regs)?;
            thread.step_addr = Some(prev_addr as usize);
            let startup = breakpoint.address == self.entry_point;
            let dl_debug = breakpoint.name == "dl_debug";
            if startup {
                self.handle_startup()?;
            }
            if dl_debug {
                self.update_memory_map()?;
            }
        }

        Ok(())
    }

    fn run_loop(&mut self, pause_on_syscalls: bool) -> LazyResult<usize> {
        let mut event_counter = 0;
        loop {
            event_counter += 1;
            for (&pid, thread) in self.process.threads.iter_mut() {
                if thread.state.running() { continue }
                // if we just resumed from a previous breakpoint, enable it again.
                if let Some(pending) = thread.step_addr.take() {
                    println!("single stepping: pid={}", pid);
                    //kill(self.process.pid, Signal::SIGSTOP)?;
                    ptrace::step(pid, None)?;
                    if let Some(breakpoint) = self.breakpoints.get_mut(&pending) {
                        println!("re-enabling breakpoint at {:x} pid={}",
                                 pending, pid);
                        waitpid(pid, None)?;
                        breakpoint.enable_in_thread(pid)?;
                    }
                }
                if pause_on_syscalls {
                    // Run the child until it hits a breakpoint or a syscal
                    ptrace::syscall(pid, None)?;
                    thread.state = ThreadState::Running;
                } else {
                    ptrace::cont(pid, None)?;
                    thread.state = ThreadState::Running;
                }
            }

            // Wait for the child to hit a trap
            match waitpid(None, None) {
                Err(error) => {
                    println!("cannot waitpid, the child may have died. error: {:?}", error);
                }
                Ok(WaitStatus::Exited(pid, exit_code)) => {
                    if self.process.exit_pid(pid, exit_code) {
                        println!("the child has exited pid={} status={}",
                                 pid, exit_code);
                        break;
                    } else {
                        println!("a thread has exited pid={} status={}",
                                 pid, exit_code);
                    }
                }
                Ok(WaitStatus::Stopped(pid, signal)) => {
                    if let Some(thread) = self.process.threads.get_mut(&pid) {
                        thread.state = ThreadState::PtraceStop;
                    } else {
                        println!("bastard child pid={}", pid);
                    }
                    let regs = ptrace::getregs(pid)?;
                    let module_info = self.maps.find_module(regs.rip as usize);
                    let symbol = module_info.and_then(|(module, addr)| {
                        let elf = self.elfs.get(module)?;
                        elf.addr_to_symbol(addr)
                    });
                    println!("the child has stopped, pid={} signal={} rip={:x} module={:?} symbol={:?}",
                             pid, signal, regs.rip, module_info, symbol);
                    // We have hit a regular trap
                    if signal == Signal::SIGSEGV {
                        println!("we have hit segmentation fault!");
                        println!("{:#x?}", self.maps);
                        break;
                    }
                    //let code = ptrace::read(pid, (regs.rip - 4) as _)?
                    //    .to_ne_bytes();
                    self.handle_breakpoint(regs, pid)?;
                }
                Ok(WaitStatus::PtraceSyscall(pid)) => {
                    let regs = ptrace::getregs(pid)?;
                    let new_state = self.process.process_syscall(pid, &regs);
                    let (direction, id) = match new_state {
                        Some(SyscallDir::Enter(id)) => ("enter", id),
                        Some(SyscallDir::Exit(id)) => ("exit", id),
                        None => {
                            println!("got a syscall on a bastard child pid={}",
                                     pid);
                            continue
                        }
                    };
                    let name =
                        SYSCALL_NAMES_X86_64.get(id)
                            .unwrap_or(&"invalid_syscall");
                    println!("syscall {} {} pid={}", direction, name, pid);
                }
                Ok(WaitStatus::Signaled(pid, signal, core_dumped)) => {
                    println!("Signaled! pid={}, signal={:?} core_dumped={:?}",
                             pid, signal, core_dumped);
                    break;
                }
                Ok(WaitStatus::PtraceEvent(pid, signal, data)) => {
                    if signal == Signal::SIGTRAP
                        && data == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
                        self.process.stop_main();
                        let tid = Pid::from_raw(ptrace::getevent(pid)? as i32);
                        self.process.add_thread(tid);
                        println!("added thread pid={:?} tid={:?} signal={:?}",
                                 pid, tid, signal);
                    }
                }
                Ok(event) => {
                    println!("unhandled ptrace event: {:?}", event)
                }
            }
        }

        Ok(event_counter)
    }
}

fn main() -> LazyResult<()> {
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            // The parent will be the debugger and should know its child pid
            let mut debugger = Debugger::init_with(child)?;
            println!("main path: {}", debugger.main_path);
            println!("auxv: {:?}", debugger.auxv);
            let start = std::time::Instant::now();
            let events = debugger.run_loop(true)?;
            let elapsed = start.elapsed();
            println!("duration: {:?}, events: {}, events/s: {}",
                     elapsed, events,
                     (events as f32) / elapsed.as_secs_f32());
        }
        ForkResult::Child => {
            // The child will be the debuggee and spawn target program
            spawn_traceable_child("/bin/ls", &["/bin/ls"])?;
            /*
            spawn_traceable_child(
                "/usr/bin/curl",
                &[
                    "/usr/bin/curl",
                    "-qsocurl-output.txt",
                    "https://www.google.com",
                ])?;
                */
        }
    }
    Ok(())
}
