pub mod types;
pub mod x86_64;
pub mod arm64;

pub use types::{NormalizedInstruction, StaticBaseline, TargetArch};
pub use x86_64::X86_64Disassembler;
pub use arm64::Arm64Disassembler;

use crate::security::violations::SecurityViolation;

/// Trait implemented by architecture-specific disassemblers (x86_64 and AArch64).
pub trait ArchDisassembler: Send + Sync {
    /// Return the target architecture.
    fn arch(&self) -> TargetArch;

    /// Return the native hardware memory page size (4096 on x86_64 / standard ARM64, 16384 on Apple Silicon).
    fn page_size(&self) -> usize;

    /// Decode raw machine code bytes into a sequence of normalized instructions.
    fn decode_stream(&self, bytes: &[u8], base_addr: u64) -> Result<Vec<NormalizedInstruction>, SecurityViolation>;

    /// Detect if a live guest RAM page has been patched with an inline trampoline hook
    /// compared to the original disk baseline.
    fn is_inline_trampoline(&self, live_bytes: &[u8], baseline_bytes: &[u8]) -> Option<String>;
}
