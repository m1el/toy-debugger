use nix::unistd::{Pid};
use crate::errors::LazyResult;

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
pub struct AddressRange {
    start: usize,
    end: usize,
}

#[derive(Debug)]
pub struct MemoryRegion {
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

#[derive(Debug)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
}

#[derive(Debug)]
pub struct LoadedModule {
    pub base_addr: usize,
    pub filename: String,
}

impl MemoryMap {
    pub fn from_pid(pid: Pid) -> LazyResult<Self> {
        let path = format!("/proc/{}/maps", pid);
        let content = std::fs::read_to_string(path)?;

        let mut regions = Vec::new();
        for line in content.lines() {
            regions.push(line.parse()?);
        }

        Ok(Self { regions })
    }

    pub fn module_base(&self, name: &str) -> Option<usize> {
        self.regions.iter()
            .find(|region| region.offset == 0 &&
                  region.filename.as_ref().map(|s| s.as_str()) == Some(name))
            .map(|region| region.address_range.start)
    }

    pub fn find_module(&self, address: usize) -> Option<&str> {
        self.regions.iter()
            .find(|region| {
                let AddressRange { start, end } = region.address_range;
                start <= address && end > address
            })
            .and_then(|region| region.filename.as_ref().map(|s| s.as_str()))
    }

    // We want to translate a known memory address in the module
    // to an address in process's virtual memory
    pub fn translate_address(&self, module: &str, address: usize)
        -> Option<usize>
    {
        for region in &self.regions {
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

    pub fn list_modules(&self) -> Vec<LoadedModule> {
        let mut modules = Vec::new();
        for region in &self.regions {
            let filename = if let Some(name) = &region.filename {
                name
            } else {
                continue;
            };

            // skip non-file and non-start sections
            if region.inode == 0 || region.offset != 0 { continue; }
            modules.push(LoadedModule {
                base_addr: region.address_range.start,
                filename: filename.clone(),
            })
        }
        modules
    }
}
