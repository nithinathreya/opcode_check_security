use std::collections::HashMap;
use crate::security::violations::SecurityViolation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl PagePermissions {
    pub fn rx() -> Self {
        Self { read: true, write: false, execute: true }
    }

    pub fn rw() -> Self {
        Self { read: true, write: true, execute: false }
    }

    pub fn rwx() -> Self {
        Self { read: true, write: true, execute: true }
    }
}

pub struct GuestPage {
    pub gpa: u64,
    pub size: usize,
    pub data: Vec<u8>,
    pub permissions: PagePermissions,
    pub was_written_since_verification: bool,
}

/// Emulated hardware W^X Guest RAM with EPT / Stage-2 MMU page tracking.
pub struct GuestMemory {
    pub page_size: usize,
    pub pages: HashMap<u64, GuestPage>,
}

impl GuestMemory {
    pub fn new(page_size: usize) -> Self {
        Self {
            page_size,
            pages: HashMap::new(),
        }
    }

    /// Align an address down to its page boundary.
    pub fn page_align(&self, addr: u64) -> u64 {
        addr & !(self.page_size as u64 - 1)
    }

    /// Map a new guest memory region with specified initial permissions.
    pub fn map_region(&mut self, base_gpa: u64, size: usize, initial_data: Option<&[u8]>, perms: PagePermissions) {
        let aligned_base = self.page_align(base_gpa);
        let num_pages = (size + self.page_size - 1) / self.page_size;

        for i in 0..num_pages {
            let page_addr = aligned_base + (i * self.page_size) as u64;
            let offset = i * self.page_size;
            let mut page_data = vec![0u8; self.page_size];

            if let Some(data) = initial_data {
                if offset < data.len() {
                    let end = (offset + self.page_size).min(data.len());
                    page_data[..end - offset].copy_from_slice(&data[offset..end]);
                }
            }

            self.pages.insert(
                page_addr,
                GuestPage {
                    gpa: page_addr,
                    size: self.page_size,
                    data: page_data,
                    permissions: perms,
                    was_written_since_verification: false,
                },
            );
        }
    }

    /// Write data to guest memory. Automatically revokes Execute permission under W^X policy.
    pub fn write_memory(&mut self, gpa: u64, data: &[u8]) -> Result<(), SecurityViolation> {
        let page_addr = self.page_align(gpa);
        let offset = (gpa - page_addr) as usize;

        let page = self.pages.get_mut(&page_addr).ok_or_else(|| {
            SecurityViolation::EptWriteExecuteViolation {
                gpa_or_ipa: gpa,
                attempted_access: "Write to unmapped GPA".to_string(),
            }
        })?;

        if !page.permissions.write {
            return Err(SecurityViolation::EptWriteExecuteViolation {
                gpa_or_ipa: gpa,
                attempted_access: "Write attempted on read-only page".to_string(),
            });
        }

        let write_len = data.len().min(self.page_size.saturating_sub(offset));
        page.data[offset..offset + write_len].copy_from_slice(&data[..write_len]);
        page.was_written_since_verification = true;

        // W^X enforcement: Writing revokes execute permission until re-verified by hypervisor
        page.permissions.execute = false;

        Ok(())
    }

    /// Read data from guest memory.
    pub fn read_page(&self, gpa: u64) -> Option<&[u8]> {
        let page_addr = self.page_align(gpa);
        self.pages.get(&page_addr).map(|p| p.data.as_slice())
    }

    /// Verify an instruction fetch on a page. Returns an EPT/Stage-2 trap if W^X is violated.
    pub fn trap_on_instruction_fetch(&self, gpa: u64) -> Result<&[u8], SecurityViolation> {
        let page_addr = self.page_align(gpa);
        let page = self.pages.get(&page_addr).ok_or_else(|| {
            SecurityViolation::EptWriteExecuteViolation {
                gpa_or_ipa: gpa,
                attempted_access: "Instruction fetch on unmapped GPA".to_string(),
            }
        })?;

        // If page has write permission or was written without verification -> trap!
        if page.permissions.write || page.was_written_since_verification {
            return Err(SecurityViolation::EptWriteExecuteViolation {
                gpa_or_ipa: gpa,
                attempted_access: "Instruction execution trapped on writable or newly modified RAM page (W^X violation)".to_string(),
            });
        }

        if !page.permissions.execute {
            return Err(SecurityViolation::EptWriteExecuteViolation {
                gpa_or_ipa: gpa,
                attempted_access: "Execute permission denied on page".to_string(),
            });
        }

        Ok(&page.data)
    }

    /// Lock page to Read+Execute (clearing write bit) after opcode auditing completes cleanly.
    pub fn lock_page_rx(&mut self, gpa: u64) {
        let page_addr = self.page_align(gpa);
        if let Some(page) = self.pages.get_mut(&page_addr) {
            page.permissions.write = false;
            page.permissions.execute = true;
            page.was_written_since_verification = false;
        }
    }
}
