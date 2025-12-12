//! Entropy calculation utilities

/// Calculate Shannon entropy of a byte slice
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &freq in &frequencies {
        if freq > 0 {
            let probability = freq as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

