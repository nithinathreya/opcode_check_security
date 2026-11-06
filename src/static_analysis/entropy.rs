/// Computes the Shannon Entropy (0.0 to 8.0 bits per byte) of a slice of bytes.
///
/// An entropy value approaching 8.0 indicates high randomness, commonly associated
/// with encrypted payloads, compressed packers (UPX), or ransomware ciphertext.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = (c as f64) / len;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let zeros = vec![0u8; 1024];
        assert_eq!(shannon_entropy(&zeros), 0.0);
    }

    #[test]
    fn test_high_entropy() {
        // Uniform distribution over all 256 bytes yields exactly 8.0
        let mut uniform = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                uniform.push(b);
            }
        }
        let entropy = shannon_entropy(&uniform);
        assert!((entropy - 8.0).abs() < 1e-4);
    }
}
