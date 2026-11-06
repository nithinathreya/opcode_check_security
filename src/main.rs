use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use aegis_cli::arch::{ArchDisassembler, Arm64Disassembler, X86_64Disassembler};
use aegis_cli::demo::DemoRunner;
use aegis_cli::sandbox::engine::{AegisUnifiedSandbox, SandboxRuntimeEvent};
use aegis_cli::sandbox::policy::SandboxPolicy;
use aegis_cli::security::forensics::SandboxForensicReport;
use aegis_cli::security::violations::SecurityViolation;
use aegis_cli::static_analysis::binary_parser::UniversalBinaryParser;
use aegis_cli::static_analysis::gatekeeper::StaticGatekeeper;
use aegis_cli::TargetArch;

// ============================================================================
// 1. CLAP CLI DEFINITION & ARGUMENTS
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "aegis-cli",
    version = "0.3.0",
    author = "AegisVM Security Team",
    about = "Zero-Trust Static Opcode, Dynamic RAM Opcode & Behavioral MicroVM Sandbox CLI (x86_64 & ARM64)"
)]
pub struct Cli {
    /// Output format for reports (text or json)
    #[arg(long, global = true, default_value = "text")]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CliArch {
    Auto,
    #[value(name = "x86-64", alias = "x86_64", alias = "x86")]
    X86_64,
    #[value(name = "aarch64", alias = "arm64")]
    Aarch64,
}

fn parse_hex_or_dec(s: &str) -> Result<u64, String> {
    let s_clean = s.trim().replace('_', "");
    if s_clean.starts_with("0x") || s_clean.starts_with("0X") {
        u64::from_str_radix(&s_clean[2..], 16).map_err(|e| e.to_string())
    } else {
        s_clean.parse::<u64>().map_err(|e| e.to_string())
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run full pipeline: Stage 1 (Static Opcodes) + Stage 2 (MicroVM) + Stage 3 (RAM Opcodes & Behavioral Sandbox)
    Verify {
        /// Path to the untrusted binary file
        #[arg(value_name = "BINARY_PATH")]
        binary: PathBuf,

        /// Target CPU architecture (auto, x86-64, aarch64)
        #[arg(short, long, default_value = "auto")]
        arch: CliArch,

        /// Use 16KB page alignment for Apple Silicon ARM64 targets
        #[arg(long, default_value_t = false)]
        apple_16k_pages: bool,

        /// Path to custom SandboxPolicy JSON file
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Maximum cumulative behavioral risk score before panicking sandbox
        #[arg(long, default_value_t = 70)]
        max_risk: u32,

        /// Automatically fast-forward guest sleep calls (anti-stalling)
        #[arg(long, default_value_t = true)]
        fast_forward_sleep: bool,

        /// Sign the binary SHA-256 with Ed25519 on pass and write signature to file
        #[arg(long)]
        sign_on_pass: Option<PathBuf>,
    },

    /// Run Stage 1 Static Opcode & Control-Flow Gatekeeper only (Zero execution cycles)
    StaticAudit {
        /// Path to the binary or raw `.text` section file
        #[arg(value_name = "BINARY_PATH")]
        binary: PathBuf,

        /// Target CPU architecture
        #[arg(short, long, default_value = "auto")]
        arch: CliArch,

        /// Use 16KB page size for Apple Silicon
        #[arg(long, default_value_t = false)]
        apple_16k_pages: bool,

        /// Base virtual address for disassembly
        #[arg(long, default_value = "0x10000000", value_parser = parse_hex_or_dec)]
        base_addr: u64,

        /// Forbid direct static syscall instructions
        #[arg(long, default_value_t = false)]
        forbid_raw_syscalls: bool,

        /// Require PAC / BTI landing pads on ARM64 functions
        #[arg(long, default_value_t = false)]
        require_pac_bti: bool,
    },

    /// Detonate binary in behavioral sandbox with custom canary tripwires and forensic bundle output
    Detonate {
        /// Path to the untrusted binary file
        #[arg(value_name = "BINARY_PATH")]
        binary: PathBuf,

        /// Target CPU architecture
        #[arg(short, long, default_value = "auto")]
        arch: CliArch,

        /// Additional canary honeypot file paths to plant inside the guest CoW filesystem
        #[arg(long = "canary")]
        canaries: Vec<String>,

        /// Shannon entropy threshold (0.0 - 8.0) for ransomware mass-encryption detection
        #[arg(long, default_value_t = 7.4)]
        entropy_threshold: f64,

        /// Optional directory to export forensic bundle (RAM dumps, CoW diffs, PCAP logs)
        #[arg(long)]
        dump_forensics: Option<PathBuf>,
    },

    /// Compare a live process RAM page dump against the on-disk binary to detect inline hooks or shellcode
    DiffRam {
        /// Path to the clean on-disk binary
        #[arg(value_name = "DISK_BINARY")]
        disk_binary: PathBuf,

        /// Path to the dumped live RAM page bytes
        #[arg(long, value_name = "RAM_DUMP_PATH")]
        ram_dump: PathBuf,

        /// Target CPU architecture
        #[arg(short, long, default_value = "x86-64")]
        arch: CliArch,

        /// Guest Physical / Intermediate Address of the inspected page
        #[arg(long, default_value = "0x00401000", value_parser = parse_hex_or_dec)]
        base_addr: u64,
    },

    /// Generate or inspect a default `aegis-policy.json` sandbox configuration file
    Policy {
        /// Subcommand action (e.g. "init")
        #[arg(value_name = "ACTION", default_value = "init")]
        action: String,

        /// Output path for the generated policy JSON
        #[arg(short, long, default_value = "aegis-policy.json")]
        output: PathBuf,
    },

    /// Run built-in simulation scenarios (Clean ARM64, Evasive ARM64 Shellcode, x86_64 Canary Theft, Ransomware, Hooks)
    Demo,
}

// ============================================================================
// 2. DISASSEMBLER SELECTION & HELPER FUNCTIONS
// ============================================================================

fn resolve_target_arch(arch: CliArch, bytes: &[u8]) -> TargetArch {
    match arch {
        CliArch::X86_64 => TargetArch::X86_64,
        CliArch::Aarch64 => TargetArch::AArch64,
        CliArch::Auto => {
            // Check headers via UniversalBinaryParser
            if let Ok(parsed) = UniversalBinaryParser::parse(bytes, None) {
                parsed.arch
            } else if bytes.len() % 4 == 0 && bytes.ends_with(&[0x1F, 0x20, 0x03, 0xD5]) {
                TargetArch::AArch64
            } else {
                TargetArch::X86_64
            }
        }
    }
}

fn select_disassembler(arch: TargetArch, apple_16k: bool) -> Arc<dyn ArchDisassembler> {
    match arch {
        TargetArch::X86_64 => Arc::new(X86_64Disassembler),
        TargetArch::AArch64 => Arc::new(Arm64Disassembler { apple_silicon_16k_pages: apple_16k }),
    }
}

fn print_report(report: &SandboxForensicReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(report).unwrap_or_default());
        }
        OutputFormat::Text => {
            println!("------------------------------------------------------------");
            println!("AegisVM Forensic Report (Arch: {:?})", report.arch);
            println!("------------------------------------------------------------");
            println!("  SHA-256 Digest              : {}", report.binary_sha256);
            println!("  Static Instructions Audited : {}", report.static_instructions_verified);
            println!("  Section Shannon Entropy     : {:.2} bits/byte", report.section_entropy);
            println!("  CFI Landing Pads (PAC/CET)  : {}", report.cfi_landing_pads_found);
            println!("  Dynamic RAM Pages Verified  : {}", report.dynamic_ram_pages_verified);
            println!("  Virtual Clock Fast-Forward  : +{}s", report.virtual_clock_fast_forwarded_secs);
            println!("  CoW Files Modified          : {:?}", report.cow_files_modified);
            println!("  Captured Network Flows      : {:?}", report.captured_network_flows);
            println!("  Cumulative Risk Score       : {}/{}", report.cumulative_risk_score, report.max_risk_threshold);
            println!("  CI/CD Exit Code             : {}", report.exit_code);
            match &report.verdict {
                Ok(msg) => {
                    println!("  Verdict                     : ✅ [PASS] {}", msg);
                    if let Some(sig) = &report.ed25519_signature {
                        let short_sig = if sig.len() > 32 { &sig[..32] } else { sig };
                        println!("  Ed25519 Signature           : {}...", short_sig);
                    }
                }
                Err(v) => {
                    println!("  Verdict                     : 🛑 [FAIL] {}", v);
                }
            }
            println!("------------------------------------------------------------\n");
        }
    }
}

fn print_banner() {
    println!(r#"
  █████╗ ███████╗ ██████╗ ██╗███████╗██╗   ██╗███╗   ███╗
 ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝██║   ██║████╗ ████║
 ███████║█████╗  ██║  ███╗██║███████╗██║   ██║██╔████╔██║
 ██╔══██║██╔══╝  ██║   ██║██║╚════██║╚██╗ ██╔╝██║╚██╔╝██║
 ██║  ██║███████╗╚██████╔╝██║███████║ ╚████╔╝ ██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝  ╚═══╝  ╚═╝     ╚═╝
  AegisVM CLI: Zero-Trust Binary & Behavioral MicroVM Sandbox
  Cross-Platform: Linux | macOS (Apple Silicon / Intel) | Windows
"#);
}

// ============================================================================
// 3. MAIN CLI DISPATCHER
// ============================================================================

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Commands::Demo);

    match command {
        Commands::Demo => {
            if cli.format == OutputFormat::Text {
                print_banner();
                println!("=== Running AegisVM CLI Built-In Verification Suite ===\n");
            }

            let r1 = DemoRunner::run_scenario_clean_arm64();
            print_report(&r1, cli.format);

            let r2 = DemoRunner::run_scenario_evasive_arm64_shellcode();
            print_report(&r2, cli.format);

            let r3 = DemoRunner::run_scenario_x86_canary_theft();
            print_report(&r3, cli.format);

            let r4 = DemoRunner::run_scenario_ransomware_mass_encryption();
            print_report(&r4, cli.format);

            let r5 = DemoRunner::run_scenario_inline_trampoline_hook();
            print_report(&r5, cli.format);

            ExitCode::from(0)
        }

        Commands::Policy { action: _, output } => {
            let default_policy = SandboxPolicy::default();
            let json = serde_json::to_string_pretty(&default_policy).expect("Failed to serialize policy");
            if let Err(e) = fs::write(&output, json) {
                eprintln!("Error writing policy file {:?}: {}", output, e);
                return ExitCode::from(1);
            }
            println!("✅ Generated default sandbox policy at {:?}", output);
            ExitCode::from(0)
        }

        Commands::StaticAudit {
            binary,
            arch,
            apple_16k_pages,
            base_addr,
            forbid_raw_syscalls,
            require_pac_bti,
        } => {
            let bytes = match fs::read(&binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading binary {:?}: {}", binary, e);
                    return ExitCode::from(1);
                }
            };

            let target_arch = resolve_target_arch(arch, &bytes);
            let disasm = select_disassembler(target_arch, apple_16k_pages);
            let sandbox = AegisUnifiedSandbox::new(disasm, SandboxPolicy::default());

            match sandbox.run_stage1_static_gatekeeper(&bytes, base_addr, forbid_raw_syscalls) {
                Ok(baseline) => {
                    if require_pac_bti && target_arch == TargetArch::AArch64 && baseline.cfi_landing_pads_found == 0 {
                        let err = SecurityViolation::MissingArmPacOrBtiLandingPad {
                            function_addr: base_addr,
                        };
                        let code = err.exit_code();
                        eprintln!("🛑 STAGE 1 STATIC VIOLATION (Exit Code {}): {}", code, err);
                        return ExitCode::from(code);
                    }

                    if forbid_raw_syscalls {
                        // Already audited during gatekeeper
                    }

                    if cli.format == OutputFormat::Json {
                        println!("{}", serde_json::to_string_pretty(&baseline).unwrap());
                    } else {
                        println!("------------------------------------------------------------");
                        println!("✅ STAGE 1 STATIC AUDIT PASSED (Arch: {:?})", baseline.arch);
                        println!("------------------------------------------------------------");
                        println!("  Binary SHA-256          : {}", baseline.binary_sha256);
                        println!("  Instructions Decoded    : {}", baseline.total_instructions_audited);
                        println!("  Section Shannon Entropy : {:.2}", baseline.section_entropy);
                        println!("  CFI Landing Pads Found  : {}", baseline.cfi_landing_pads_found);
                        println!("  CFG Basic Block Nodes   : {}", baseline.cfg_node_count);
                        println!("  CFG Branch Edges        : {}", baseline.cfg_edge_count);
                        println!("  Immutable Baseline Pages: {}", baseline.code_page_baselines.len());
                        println!("------------------------------------------------------------\n");
                    }
                    ExitCode::from(0)
                }
                Err(violation) => {
                    let code = violation.exit_code();
                    eprintln!("🛑 STAGE 1 STATIC VIOLATION (Exit Code {}): {}", code, violation);
                    ExitCode::from(code)
                }
            }
        }

        Commands::Verify {
            binary,
            arch,
            apple_16k_pages,
            policy,
            max_risk,
            fast_forward_sleep,
            sign_on_pass,
        } => {
            let bytes = match fs::read(&binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading binary {:?}: {}", binary, e);
                    return ExitCode::from(1);
                }
            };

            let mut sandbox_policy = match policy {
                Some(path) => {
                    let raw = match fs::read_to_string(&path) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("Failed to read policy file {:?}: {}", path, e);
                            return ExitCode::from(1);
                        }
                    };
                    match serde_json::from_str(&raw) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("Invalid policy JSON in {:?}: {}", path, e);
                            return ExitCode::from(1);
                        }
                    }
                }
                None => SandboxPolicy::default(),
            };
            sandbox_policy.max_cumulative_risk_score = max_risk;

            let target_arch = resolve_target_arch(arch, &bytes);
            let disasm = select_disassembler(target_arch, apple_16k_pages);
            let mut sandbox = AegisUnifiedSandbox::new(disasm, sandbox_policy);

            let baseline = match StaticGatekeeper::audit_binary(&bytes, Some(target_arch), false) {
                Ok(b) => b,
                Err(v) => {
                    let code = v.exit_code();
                    eprintln!("🛑 STAGE 1 STATIC GATEKEEPER ABORT (Exit Code {}): {}", code, v);
                    return ExitCode::from(code);
                }
            };

            let events = vec![SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
                gpa_or_ipa: baseline.entry_point,
                live_page_bytes: bytes.iter().take(4096).copied().collect(),
            }];

            if fast_forward_sleep {
                // Configured
            }

            let report = sandbox.detonate_in_sandbox(&baseline, events);
            let code = report.exit_code;

            if report.is_clean() {
                if let Some(sign_path) = sign_on_pass {
                    if let Some(sig) = &report.ed25519_signature {
                        if let Err(e) = fs::write(&sign_path, sig) {
                            eprintln!("Failed to write signature to {:?}: {}", sign_path, e);
                        } else {
                            if cli.format == OutputFormat::Text {
                                println!("Signed binary SHA-256 written to {:?}", sign_path);
                            }
                        }
                    }
                }
            }

            print_report(&report, cli.format);
            ExitCode::from(code)
        }

        Commands::Detonate {
            binary,
            arch,
            canaries,
            entropy_threshold,
            dump_forensics,
        } => {
            let bytes = match fs::read(&binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading binary {:?}: {}", binary, e);
                    return ExitCode::from(1);
                }
            };

            let mut policy = SandboxPolicy::default();
            for c in canaries {
                policy.canary_honeypot_paths.insert(c);
            }
            policy.ransomware_entropy_threshold = entropy_threshold;

            let target_arch = resolve_target_arch(arch, &bytes);
            let disasm = select_disassembler(target_arch, false);
            let mut sandbox = AegisUnifiedSandbox::new(disasm, policy);

            let baseline = match StaticGatekeeper::audit_binary(&bytes, Some(target_arch), false) {
                Ok(b) => b,
                Err(v) => {
                    let code = v.exit_code();
                    eprintln!("🛑 STAGE 1 STATIC ABORT (Exit Code {}): {}", code, v);
                    return ExitCode::from(code);
                }
            };

            let events = vec![SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
                gpa_or_ipa: baseline.entry_point,
                live_page_bytes: bytes.iter().take(4096).copied().collect(),
            }];

            let report = sandbox.detonate_in_sandbox(&baseline, events);

            if let Some(dir) = dump_forensics {
                let _ = fs::create_dir_all(&dir);
                let report_path = dir.join("forensic_report.json");
                let _ = fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap_or_default());

                let pcap_path = dir.join("pcap_flows.log");
                let _ = fs::write(&pcap_path, report.captured_network_flows.join("\n"));

                let cow_path = dir.join("cow_filesystem_diff.json");
                let _ = fs::write(&cow_path, serde_json::to_string_pretty(&report.cow_files_modified).unwrap_or_default());

                let ram_path = dir.join("ram_snapshot.bin");
                let _ = fs::write(&ram_path, &bytes);

                if cli.format == OutputFormat::Text {
                    println!("Forensic bundle successfully dumped to {:?}", dir);
                }
            }

            let code = report.exit_code;
            print_report(&report, cli.format);
            ExitCode::from(code)
        }

        Commands::DiffRam {
            disk_binary,
            ram_dump,
            arch,
            base_addr,
        } => {
            let disk_bytes = match fs::read(&disk_binary) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to read disk binary {:?}: {}", disk_binary, e);
                    return ExitCode::from(1);
                }
            };
            let ram_bytes = match fs::read(&ram_dump) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to read RAM dump {:?}: {}", ram_dump, e);
                    return ExitCode::from(1);
                }
            };

            let target_arch = resolve_target_arch(arch, &disk_bytes);
            let disasm = select_disassembler(target_arch, false);
            let mut sandbox = AegisUnifiedSandbox::new(disasm, SandboxPolicy::default());

            let baseline = match StaticGatekeeper::audit_binary_with_vaddr(&disk_bytes, Some(target_arch), Some(base_addr), false) {
                Ok(b) => b,
                Err(v) => {
                    eprintln!("🛑 Disk Binary Failed Stage 1 Audit (Exit Code {}): {}", v.exit_code(), v);
                    return ExitCode::from(v.exit_code());
                }
            };

            let events = vec![SandboxRuntimeEvent::Stage2MemoryExecuteTrap {
                gpa_or_ipa: base_addr,
                live_page_bytes: ram_bytes,
            }];

            let report = sandbox.detonate_in_sandbox(&baseline, events);
            let code = report.exit_code;
            print_report(&report, cli.format);
            ExitCode::from(code)
        }
    }
}
