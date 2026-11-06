use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use aegis_vm::demo::DemoRunner;
use aegis_vm::static_analysis::gatekeeper::StaticGatekeeper;
use aegis_vm::{verify_and_detonate, TargetArch};

#[derive(Parser)]
#[command(name = "aegis-vm")]
#[command(author = "AegisVM Security Team")]
#[command(version = "0.2.0")]
#[command(about = "Unified Static/Dynamic Opcode Verifier & Behavioral MicroVM Sandbox (x86_64 & ARM64)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all multi-architecture demonstration scenarios (Clean ARM64, Evasive Shellcode, Canary Theft, Ransomware, Hooks)
    Demo,

    /// Audit static opcodes, entropy, and control-flow graph (Stage 1)
    Scan {
        /// Path to binary (ELF, PE, Mach-O, or raw machine code)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Force target architecture (x86_64 or aarch64)
        #[arg(short, long)]
        arch: Option<String>,

        /// Enable strict check rejecting any raw static syscalls
        #[arg(long, default_value_t = false)]
        strict_syscalls: bool,
    },

    /// Run full Stage 1 static verification + Stage 2/3 behavioral sandbox detonation
    Detonate {
        /// Path to binary (ELF, PE, Mach-O, or raw machine code)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Force target architecture (x86_64 or aarch64)
        #[arg(short, long)]
        arch: Option<String>,

        /// Output forensic report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn parse_arch(arch_str: &str) -> Option<TargetArch> {
    match arch_str.to_lowercase().as_str() {
        "x86_64" | "x86" | "amd64" => Some(TargetArch::X86_64),
        "aarch64" | "arm64" => Some(TargetArch::AArch64),
        _ => None,
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
  Unified Rust Opcode Verifier & Behavioral MicroVM Sandbox
  Cross-Platform Support: Linux | macOS (Apple Silicon / Intel) | Windows
"#);
}

fn run_all_demos() {
    print_banner();
    println!("Executing AegisVM Multi-Architecture Verification Scenarios...\n");

    let r1 = DemoRunner::run_scenario_clean_arm64();
    r1.print_summary();

    let r2 = DemoRunner::run_scenario_evasive_arm64_shellcode();
    r2.print_summary();

    let r3 = DemoRunner::run_scenario_x86_canary_theft();
    r3.print_summary();

    let r4 = DemoRunner::run_scenario_ransomware_mass_encryption();
    r4.print_summary();

    let r5 = DemoRunner::run_scenario_inline_trampoline_hook();
    r5.print_summary();
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Demo) => {
            run_all_demos();
        }
        Some(Commands::Scan { path, arch, strict_syscalls }) => {
            print_banner();
            let forced_arch = arch.as_deref().and_then(parse_arch);
            println!("Reading binary from: {}", path.display());

            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", path.display(), e);
                    std::process::exit(1);
                }
            };

            match StaticGatekeeper::audit_binary(&bytes, forced_arch, strict_syscalls) {
                Ok(baseline) => {
                    println!("\n✅ Stage 1 Static Gatekeeper PASSED");
                    println!("   • Target Architecture: {:?}", baseline.arch);
                    println!("   • Binary SHA-256:      {}", baseline.binary_sha256);
                    println!("   • Section Entropy:     {:.3} (Packed: {})", baseline.section_entropy, baseline.is_packed_or_high_entropy);
                    println!("   • Instructions Decoded: {}", baseline.total_instructions_audited);
                    println!("   • CFG Graph Nodes:     {}", baseline.cfg_node_count);
                    println!("   • CFG Graph Edges:     {}", baseline.cfg_edge_count);
                    println!("   • Immutable Pages:     {} pages in baseline map", baseline.code_page_baselines.len());
                }
                Err(violation) => {
                    eprintln!("\n🛑 Stage 1 Static Gatekeeper REJECTED Binary");
                    eprintln!("   Violation: {}", violation);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Detonate { path, arch, json }) => {
            let forced_arch = arch.as_deref().and_then(parse_arch);
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", path.display(), e);
                    std::process::exit(1);
                }
            };

            let report = verify_and_detonate(&bytes, forced_arch, None, Vec::new());
            if json {
                println!("{}", report.to_json().unwrap_or_default());
            } else {
                print_banner();
                report.print_summary();
            }

            if !report.is_clean() {
                std::process::exit(1);
            }
        }
    }
}
