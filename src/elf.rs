use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::convert::TryInto;
use crate::errors::LazyResult;


const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
enum ElfType {
    None   = 0x00,
    Rel    = 0x01,
    Exec   = 0x02,
    Dyn    = 0x03,
    Core   = 0x04,
    Loos   = 0xFE00,
    Hios   = 0xFEFF,
    LoProc = 0xFF00,
    HiProc = 0xFFFF,
}

impl ElfType {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x00	=> ElfType::None,
            0x01	=> ElfType::Rel,
            0x02	=> ElfType::Exec,
            0x03	=> ElfType::Dyn,
            0x04	=> ElfType::Core,
            0xFE00	=> ElfType::Loos,
            0xFEFF	=> ElfType::Hios,
            0xFF00	=> ElfType::LoProc,
            0xFFFF	=> ElfType::HiProc,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub struct Elf64ProgramHeader {
    htype: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
}

#[derive(Debug)]
pub struct Elf64 {
    file_type: ElfType,
    machine_type: u16,
    version: u32,
    entry_point: u64,
    headers: Vec<Elf64ProgramHeader>,
    sections: Vec<Elf64Section>,
    flags: u32,
    exports: Vec<ExportSymbol>,
    /*
unsigned char e_ident[16]; /* ELF identification */
Elf64_Half e_type; /* Object file type */
Elf64_Half e_machine; /* Machine type */
Elf64_Word e_version; /* Object file version */
Elf64_Addr e_entry; /* Entry point address */
Elf64_Off e_phoff; /* Program header offset */
Elf64_Off e_shoff; /* Section header offset */
Elf64_Word e_flags; /* Processor-specific flags */
Elf64_Half e_ehsize; /* ELF header size */
Elf64_Half e_phentsize; /* Size of program header entry */
Elf64_Half e_phnum; /* Number of program header entries */
Elf64_Half e_shentsize; /* Size of section header entry */
Elf64_Half e_shnum; /* Number of section header entries */
Elf64_Half e_shstrndx; /* Section name string table index */
*/
}

#[derive(Debug)]
pub struct ExportLocation {
    pub vaddr: usize,
    pub faddr: usize,
    pub size: usize,
}

impl Elf64 {
    pub fn lookup_export(&self, symbol: &str) -> Option<ExportLocation> {
        let export = self.exports.iter().find(|e| e.name == symbol)?;
        Some(ExportLocation {
            vaddr: export.value as usize,
            faddr: export.value as usize,
            size: export.size as usize,
        })
    }
}

const CLASS_32BIT: u8 = 1;
const CLASS_64BIT: u8 = 2;
const ENDIANNESS_LITTLE: u8 = 1;
const ENDIANNESS_BIG: u8 = 2;
const ELF_VERSION: u8 = 1;
const IDENT_SYSV: u8 = 0;
const IDENT_LINUX: u8 = 3;

pub fn parse_program_headers(file: &mut File, count: usize, size: usize)
    -> LazyResult<Vec<Elf64ProgramHeader>>
{
    let mut headers = Vec::new();
    let elf64_header_size = 0x38;
    if size != elf64_header_size { Err("invalid program headers size, expect 0x38")? }
    let mut buf = vec![0_u8; count * size];
    file.read_exact(&mut buf)?;
    for chunk in buf.chunks_exact(elf64_header_size) {
        let htype = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
        let offset = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let vaddr = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        let paddr = u64::from_le_bytes(chunk[24..32].try_into().unwrap());
        let file_size = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        let memory_size = u64::from_le_bytes(chunk[40..48].try_into().unwrap());
        let align = u64::from_le_bytes(chunk[48..56].try_into().unwrap());
        headers.push(Elf64ProgramHeader {
            htype, flags,
            offset, vaddr, paddr,
            file_size, memory_size,
            align,
        });
    }
    Ok(headers)
}

#[derive(Debug)]
pub struct Elf64Section {
    name_index: u32,
    name: Option<String>,
    stype: u32,
    flags: u64,
    vaddr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
}

const ELF64_SECTION_SIZE: usize = 0x40;
// Parse section from a slice of bytes.
// panics when the slice has an invalid size.
fn parse_section(chunk: &[u8]) -> Elf64Section {
    assert_eq!(chunk.len(), ELF64_SECTION_SIZE,
        "invalid chunk size for elf64 section");
    let name_index = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
    let stype = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
    let flags = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
    let vaddr = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
    let offset = u64::from_le_bytes(chunk[24..32].try_into().unwrap());
    let size = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
    let link = u32::from_le_bytes(chunk[40..44].try_into().unwrap());
    let info = u32::from_le_bytes(chunk[44..48].try_into().unwrap());
    let align = u64::from_le_bytes(chunk[48..56].try_into().unwrap());
    let entry_size = u64::from_le_bytes(chunk[56..64].try_into().unwrap());

    Elf64Section {
        name_index,
        name: None,
        stype,
        flags,
        vaddr,
        offset,
        size,
        link,
        info,
        align,
        entry_size,
    }
}

fn parse_sections(
    file: &mut File,
    count: usize, size: usize,
    section_names: usize,
) -> LazyResult<Vec<Elf64Section>> {
    let mut sections = Vec::new();
    let elf64_section_size = 0x40;
    if size != ELF64_SECTION_SIZE { Err("invalid section size, expect 0x40")? }
    let mut buf = vec![0_u8; count * size];
    file.read_exact(&mut buf)?;

    for chunk in buf.chunks_exact(elf64_section_size) {
        sections.push(parse_section(chunk));
    }

    // read section names
    if let Some(name_section) = sections.get(section_names) {
        file.seek(SeekFrom::Start(name_section.offset))?;
        let mut names_buf = vec![0_u8; name_section.size as usize];
        file.read_exact(&mut names_buf)?;
        std::mem::drop(name_section);
        for section in sections.iter_mut() {
            let index = section.name_index as usize;
            let name = &names_buf[index..];
            let end = name.iter().position(|&c| c == b'\0')
                .ok_or("Expect zero-terminated string")?;
            section.name = std::str::from_utf8(&name[..end])
                .ok().map(|s| s.to_string());
        }
    }

    Ok(sections)
}

#[derive(Debug)]
pub struct ExportSymbol {
    name_index: u32,
    name: String,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    size: u64,
}

fn parse_shared_symbols(file: &mut File, sections: &[Elf64Section])
    -> LazyResult<Vec<ExportSymbol>>
{
    const SHT_DYNSYM: u32 = 11;
    const SHT_STRTAB: u32 = 3;
    let mut exports = Vec::new();

    let names =
        // TODO: ensure this is the only .strtab section?
        if let Some(section) = sections.iter().find(|s| s.stype == SHT_STRTAB) {
            // allocate a buffer with section size
            let mut section_content = vec![0_u8; section.size as usize];
            // read section data at offset
            file.seek(SeekFrom::Start(section.offset))?;
            file.read_exact(&mut section_content)?;
            section_content
        } else {
            // No names, no exports.
            return Ok(exports);
        };

    let symbols_content =
        // TODO: ensure this is the only .dynsym section?
        if let Some(section) = sections.iter().find(|s| s.stype == SHT_DYNSYM) {
            let mut section_content = vec![0_u8; section.size as usize];
            file.seek(SeekFrom::Start(section.offset))?;
            file.read_exact(&mut section_content)?;
            section_content
        } else {
            // No DYNSYM, no exports
            return Ok(exports);
        };

    let export_symbol_size = 24;
    // TODO: check if it's exactly aligned?
    for chunk in symbols_content.chunks_exact(export_symbol_size) {
        let name_index = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
        if name_index == 0 { continue; }
        let info = chunk[4];
        let other = chunk[5];
        let section = u16::from_le_bytes(chunk[6..8].try_into().unwrap());
        let value = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let size = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        let name = &names[name_index as usize..];
        let end = name.iter().position(|&c| c == b'\0')
            .ok_or("Expect zero-terminated string")?;
        let name = std::str::from_utf8(&name[..end])
            .unwrap_or("BAD_SYMBOL_NAME")
            .to_string();

        let symbol = ExportSymbol {
            name_index,
            name,
            info,
            other,
            section,
            value,
            size,
        };

        exports.push(symbol);
    }

    Ok(exports)
}

pub fn parse_elf_info(file: &mut File) -> LazyResult<Elf64> {
    let mut ident = [0_u8; 16];
    file.read_exact(&mut ident[..])?;
    let magic: [u8; 4] = ident[..4].try_into().unwrap();
    let class = ident[4];
    let endianness = ident[5];
    let version = ident[6];
    let osabi = ident[7];

    if &magic != ELF_MAGIC { Err("invalid ELF magic header")?; }
    if class != CLASS_64BIT { Err("expect 64-bit ELF class")?; }
    if endianness != ENDIANNESS_LITTLE { Err("expect little endian file")?; }
    if version != ELF_VERSION { Err("unexpected ELF version")?; }
    if osabi != IDENT_SYSV && osabi != IDENT_LINUX {
        Err("Expect system SYSV or Linux")?
    }

    let mut headers = [0_u8; 0x40 - 0x10];
    file.read_exact(&mut headers[..])?;
    let file_type = u16::from_le_bytes(headers[0..2].try_into().unwrap());
    let file_type = ElfType::from_u16(file_type)
        .ok_or("invalid elf type!")?;
    let machine_type = u16::from_le_bytes(headers[2..4].try_into().unwrap());
    if machine_type != 0x3e { Err("Only know amd64 machine type")?; }
    let version = u32::from_le_bytes(headers[4..8].try_into().unwrap());
    let entry_point = u64::from_le_bytes(headers[8..16].try_into().unwrap());
    let header_table = u64::from_le_bytes(headers[16..24].try_into().unwrap());
    let section_table = u64::from_le_bytes(headers[24..32].try_into().unwrap());
    let flags = u32::from_le_bytes(headers[32..36].try_into().unwrap());
    let this_size = u16::from_le_bytes(headers[36..38].try_into().unwrap());
    if this_size as usize != ident.len() + headers.len() {
        Err("invalid ELF header size")?;
    }

    let header_size = u16::from_le_bytes(headers[38..40].try_into().unwrap());
    let header_count = u16::from_le_bytes(headers[40..42].try_into().unwrap());

    let section_size = u16::from_le_bytes(headers[42..44].try_into().unwrap());
    let section_count = u16::from_le_bytes(headers[44..46].try_into().unwrap());
    let section_names = u16::from_le_bytes(headers[46..48].try_into().unwrap());

    file.seek(SeekFrom::Start(header_table))?;
    let headers = parse_program_headers(file,
        header_count as usize, header_size as usize)?;

    file.seek(SeekFrom::Start(section_table))?;
    let sections = parse_sections(file,
        section_count as usize, section_size as usize, section_names as usize)?;

    let exports = parse_shared_symbols(file, &sections)?;

    Ok(Elf64 {
        file_type,
        machine_type,
        version,
        entry_point,
        headers,
        sections,
        flags,
        exports,
    })
}
