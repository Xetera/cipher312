use crate::exports::xetera::cipher312::codec::GuestNormalizedCiphertext;

pub struct NormalizedCiphertext(String);

impl NormalizedCiphertext {
    pub fn new(input: &str) -> NormalizedCiphertext {
        let extra_bytes = input
            .chars()
            .filter(|&c| matches!(c, '4' | '5' | '6'))
            .count();

        let mut out = String::with_capacity(input.len() + extra_bytes);

        for c in input.chars() {
            match c {
                '4' => out.push_str("11"),
                '5' => out.push_str("22"),
                '6' => out.push_str("33"),
                _ => out.push(c),
            }
        }
        NormalizedCiphertext(out)
    }
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl GuestNormalizedCiphertext for NormalizedCiphertext {
    fn new(ciphertext: String) -> Self {
        NormalizedCiphertext::new(&ciphertext)
    }
    fn text(&self) -> String {
        self.0.clone()
    }
}
