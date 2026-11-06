use crate::sandbox::policy::SandboxPolicy;
use crate::security::violations::SecurityViolation;

/// Virtual TAP Network Interface with INetSim Sinkhole & PCAP flow recorder.
pub struct VirtualTapNetwork {
    pub pcap_flows: Vec<String>,
}

impl VirtualTapNetwork {
    pub fn new() -> Self {
        Self {
            pcap_flows: Vec::new(),
        }
    }

    /// Intercept and record outbound network packets from the guest.
    pub fn handle_packet(
        &mut self,
        pid: u32,
        dst_ip: &str,
        dst_port: u16,
        protocol: &str,
        payload_preview: &[u8],
        policy: &SandboxPolicy,
    ) -> Result<(), SecurityViolation> {
        let flow_entry = format!(
            "PID {:<5} | {:<5} -> {}:{} [{} bytes]",
            pid,
            protocol,
            dst_ip,
            dst_port,
            payload_preview.len()
        );
        self.pcap_flows.push(flow_entry);

        // Zero-trust enforcement: External egress is blocked unless explicitly whitelisted
        if !policy.allowed_outbound_ips.contains(dst_ip) {
            return Err(SecurityViolation::UnauthorizedNetworkExfiltration {
                dst_ip: dst_ip.to_string(),
                dst_port,
                protocol: protocol.to_string(),
            });
        }

        Ok(())
    }
}
