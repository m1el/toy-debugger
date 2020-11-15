use nix::unistd::Pid;
use crate::errors::LazyResult;
use std::convert::TryInto;

pub const AT_NULL   : usize = 0; /* end of vector */
pub const AT_IGNORE : usize = 1; /* entry should be ignored */
pub const AT_EXECFD : usize = 2; /* file descriptor of program */
pub const AT_PHDR   : usize = 3; /* program headers for program */
pub const AT_PHENT  : usize = 4; /* size of program header entry */
pub const AT_PHNUM  : usize = 5; /* number of program headers */
pub const AT_PAGESZ : usize = 6; /* system page size */
pub const AT_BASE   : usize = 7; /* base address of interpreter */
pub const AT_FLAGS  : usize = 8; /* flags */
pub const AT_ENTRY  : usize = 9; /* entry point of program */
pub const AT_NOTELF : usize = 10; /* program is not ELF */
pub const AT_UID    : usize = 11; /* real uid */
pub const AT_EUID   : usize = 12; /* effective uid */
pub const AT_GID    : usize = 13; /* real gid */
pub const AT_EGID   : usize = 14; /* effective gid */
pub const AT_PLATFORM: usize = 15;  /* string identifying CPU for optimizations */
pub const AT_HWCAP  : usize = 16;    /* arch dependent hints at CPU capabilities */
pub const AT_CLKTCK : usize = 17; /* frequency at which times() increments */
pub const AT_SECURE : usize = 23;   /* secure mode boolean */
pub const AT_BASE_PLATFORM : usize = 24; /* string identifying real platform, may */
pub const AT_RANDOM : usize = 25; /* address of 16 random bytes */
pub const AT_HWCAP2 : usize = 26; /* extension of AT_HWCAP */
pub const AT_EXECFN : usize = 31; /* filename of program */

#[derive(Debug)]
pub struct AuxilliaryEntry {
    tag: usize,
    value: usize,
}

#[derive(Debug)]
pub struct AuxilliaryVector {
    data: Vec<AuxilliaryEntry>,
}

impl AuxilliaryVector {
    pub fn get_value(&self, tag: usize) -> Option<usize> {
        self.data.iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }
}

pub fn read_auxv(pid: Pid) -> LazyResult<AuxilliaryVector> {
    let path = format!("/proc/{}/auxv", pid);
    let auxv_content = std::fs::read(path)?;
    let mut data = Vec::new();
    let size = std::mem::size_of::<usize>();
    for chunk in auxv_content.chunks(size * 2) {
        let tag = usize::from_ne_bytes(chunk[..size].try_into()?);
        let value = usize::from_ne_bytes(chunk[size..].try_into()?);
        data.push(AuxilliaryEntry { tag, value });
    }
    Ok(AuxilliaryVector { data })
}
