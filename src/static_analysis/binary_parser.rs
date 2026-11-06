use crate::arch::types::TargetArch;
use crate::static_analysis::entropy::shannon_entropy;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct SectionMetadata {
    pub name: String,
    pub virtual_address: u64,
    pub size: usize,
    pub entropy: f64,
    pub is_executable: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExtractedBinary {
    pub format: String,
    pub arch: TargetArch,
    pub entry_point: u64,
    pub sha256: String,
    pub text_section: Vec<u8>,
    pub text_vaddr: u64,
    pub sections: Vec<SectionMetadata>,
}

pub struct UniversalBinaryParser;

impl UniversalBinaryParser {
    /// Parse an untrusted binary buffer into an `ExtractedBinary`.
    /// Supports ELF (Linux), PE (Windows), Mach-O (macOS single & universal fat binaries),
    /// and raw opcode streams.
    pub fn parse(bytes: &[u8], forced_arch: Option<TargetArch>) -> Result<ExtractedBinary, String> {
        Self::parse_with_vaddr(bytes, forced_arch, None)
    }

    /// Parse an untrusted binary buffer into an `ExtractedBinary`, with optional custom base VADDR.
    pub fn parse_with_vaddr(
        bytes: &[u8],
        forced_arch: Option<TargetArch>,
        custom_vaddr: Option<u64>,
    ) -> Result<ExtractedBinary, String> {
        if bytes.is_empty() {
            return Err("Binary buffer is empty".to_string());
        }

        let sha256 = format!("{:x}", Sha256::digest(bytes));

        match goblin::Object::parse(bytes) {
            Ok(goblin::Object::Elf(elf)) => {
                let arch = if elf.header.e_machine == goblin::elf::header::EM_X86_64 {
                    TargetArch::X86_64
                } else if elf.header.e_machine == goblin::elf::header::EM_AARCH64 {
                    TargetArch::AArch64
                } else {
                    return Err(format!("Unsupported ELF machine architecture: 0x{:X}", elf.header.e_machine));
                };

                let mut sections = Vec::new();
                let mut text_section = Vec::new();
                let mut text_vaddr = elf.header.e_entry;

                for section in elf.section_headers.iter() {
                    let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("<unknown>").to_string();
                    let start = section.sh_offset as usize;
                    let end = (section.sh_offset + section.sh_size) as usize;
                    let is_exec = (section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0;

                    let data = if start <= bytes.len() && end <= bytes.len() && start <= end {
                        bytes[start..end].to_vec()
                    } else {
                        Vec::new()
                    };

                    let entropy = shannon_entropy(&data);
                    if name == ".text" || (is_exec && text_section.is_empty() && !data.is_empty()) {
                        text_section = data.clone();
                        text_vaddr = section.sh_addr;
                    }

                    sections.push(SectionMetadata {
                        name,
                        virtual_address: section.sh_addr,
                        size: section.sh_size as usize,
                        entropy,
                        is_executable: is_exec,
                        data,
                    });
                }

                if text_section.is_empty() {
                    text_section = bytes.to_vec();
                }

                Ok(ExtractedBinary {
                    format: "ELF (Linux)".to_string(),
                    arch,
                    entry_point: elf.header.e_entry,
                    sha256,
                    text_section,
                    text_vaddr,
                    sections,
                })
            }
            Ok(goblin::Object::PE(pe)) => {
                let arch = match pe.header.coff_header.machine {
                    goblin::pe::header::COFF_MACHINE_X86_64 => TargetArch::X86_64,
                    goblin::pe::header::COFF_MACHINE_ARM64 => TargetArch::AArch64,
                    other => return Err(format!("Unsupported PE machine architecture: 0x{:X}", other)),
                };

                let image_base = pe.image_base as u64;
                let entry_point = image_base + pe.entry as u64;

                let mut sections = Vec::new();
                let mut text_section = Vec::new();
                let mut text_vaddr = entry_point;

                for sec in pe.sections.iter() {
                    let name = sec.name().unwrap_or("<sec>").to_string();
                    let start = sec.pointer_to_raw_data as usize;
                    let size = sec.size_of_raw_data as usize;
                    let end = start + size;
                    let is_exec = (sec.characteristics & 0x2000_0000) != 0; // IMAGE_SCN_MEM_EXECUTE

                    let data = if start <= bytes.len() && end <= bytes.len() {
                        bytes[start..end].to_vec()
                    } else {
                        Vec::new()
                    };

                    let entropy = shannon_entropy(&data);
                    let vaddr = image_base + sec.virtual_address as u64;

                    if (name.eq_ignore_ascii_case(".text") || is_exec) && text_section.is_empty() && !data.is_empty() {
                        text_section = data.clone();
                        text_vaddr = vaddr;
                    }

                    sections.push(SectionMetadata {
                        name,
                        virtual_address: vaddr,
                        size,
                        entropy,
                        is_executable: is_exec,
                        data,
                    });
                }

                if text_section.is_empty() {
                    text_section = bytes.to_vec();
                }

                Ok(ExtractedBinary {
                    format: "PE/COFF (Windows)".to_string(),
                    arch,
                    entry_point,
                    sha256,
                    text_section,
                    text_vaddr,
                    sections,
                })
            }
            Ok(goblin::Object::Mach(mach)) => {
                match mach {
                    goblin::mach::Mach::Binary(macho) => {
                        let arch = if macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
                            TargetArch::AArch64
                        } else if macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
                            TargetArch::X86_64
                        } else {
                            return Err(format!("Unsupported Mach-O cputype: 0x{:X}", macho.header.cputype));
                        };

                        let entry_point = macho.entry;
                        let mut sections = Vec::new();
                        let mut text_section = Vec::new();
                        let mut text_vaddr = entry_point;

                        for segment in &macho.segments {
                            for (section, _) in &segment.sections().unwrap_or_default() {
                                let sectname = section.name().unwrap_or("<unknown>").to_string();
                                let segname = section.segname().unwrap_or("<unknown>").to_string();
                                let full_name = format!("{},{}", segname, sectname);
                                let is_exec = full_name.starts_with("__TEXT");

                                let offset = section.offset as usize;
                                let size = section.size as usize;
                                let data = if offset + size <= bytes.len() {
                                    bytes[offset..offset + size].to_vec()
                                } else {
                                    Vec::new()
                                };

                                let entropy = shannon_entropy(&data);
                                if sectname == "__text" && !data.is_empty() {
                                    text_section = data.clone();
                                    text_vaddr = section.addr;
                                }

                                sections.push(SectionMetadata {
                                    name: full_name,
                                    virtual_address: section.addr,
                                    size,
                                    entropy,
                                    is_executable: is_exec,
                                    data,
                                });
                            }
                        }

                        if text_section.is_empty() {
                            text_section = bytes.to_vec();
                        }

                        Ok(ExtractedBinary {
                            format: "Mach-O (macOS)".to_string(),
                            arch,
                            entry_point,
                            sha256,
                            text_section,
                            text_vaddr,
                            sections,
                        })
                    }
                    goblin::mach::Mach::Fat(fat) => {
                        for arch_res in fat.iter_arches() {
                            if let Ok(arch_info) = arch_res {
                                let target_arch = if arch_info.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
                                    TargetArch::AArch64
                                } else if arch_info.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
                                    TargetArch::X86_64
                                } else {
                                    continue;
                                };

                                if let Some(pref) = forced_arch {
                                    if target_arch != pref {
                                        continue;
                                    }
                                }

                                let slice_bytes = arch_info.slice(bytes);
                                if !slice_bytes.is_empty() {
                                    return Self::parse(slice_bytes, Some(target_arch));
                                }
                            }
                        }
                        Err("No supported x86_64 or AArch64 slices found in Universal Fat Mach-O".to_string())
                    }
                }
            }
            Err(_) | Ok(_) => {
                // Raw instruction stream fallback (e.g. raw shellcode, unit tests, microvm test vectors)
                let arch = forced_arch.unwrap_or(TargetArch::X86_64);
                let entropy = shannon_entropy(bytes);
                let base = custom_vaddr.unwrap_or(0x1000_0000);

                Ok(ExtractedBinary {
                    format: "Raw Machine Code Stream".to_string(),
                    arch,
                    entry_point: base,
                    sha256,
                    text_section: bytes.to_vec(),
                    text_vaddr: base,
                    sections: vec![SectionMetadata {
                        name: ".text (raw)".to_string(),
                        virtual_address: base,
                        size: bytes.len(),
                        entropy,
                        is_executable: true,
                        data: bytes.to_vec(),
                    }],
                })
            }
        }
    }
}
