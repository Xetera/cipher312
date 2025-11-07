use crate::{
    normalizer::{self, NormalizedCiphertext},
    Codec, DecodeResult, Grapheme,
};
use exports::xetera::cipher312::codec::{
    self, Guest, GuestNormalizedCiphertext, NormalizedCiphertextBorrow,
};

wit_bindgen::generate!({
    world: "cipher312"
});

impl Guest for Codec {
    type NormalizedCiphertext = normalizer::NormalizedCiphertext;
    type DecodeResult = crate::DecodeResult;
    fn decode_v1(input: NormalizedCiphertextBorrow) -> Result<codec::DecodeResult, ()> {
        let text = input.get::<NormalizedCiphertext>();
        match Codec::decode_v1(text) {
            Ok(result) => Ok(codec::DecodeResult::new(result)),
            Err(_) => Err(()),
        }
    }

    fn decode_v2(input: codec::NormalizedCiphertextBorrow) -> Result<codec::DecodeResult, ()> {
        let text = input.get::<NormalizedCiphertext>();
        match Codec::decode_v2(text) {
            Ok(result) => Ok(codec::DecodeResult::new(result)),
            Err(_) => Err(()),
        }
    }
    // TODO: tag this based on the correct version?
    fn decode(input: codec::NormalizedCiphertextBorrow) -> Result<codec::DecodeResult, ()> {
        let text = input.get::<NormalizedCiphertext>();
        match Codec::decode(text) {
            Ok(result) => Ok(codec::DecodeResult::new(result)),
            Err(_) => Err(()),
        }
    }
}

impl From<&Grapheme> for codec::Grapheme {
    fn from(result: &Grapheme) -> Self {
        match result {
            Grapheme::KnownValue(value) => codec::Grapheme::Codepoint(*value),
            Grapheme::UnknownSequence(sequence) => codec::Grapheme::Unknown(sequence.clone()),
            Grapheme::InvalidUnicode(_error) => codec::Grapheme::InvalidUnicode,
        }
    }
}

impl codec::GuestDecodeResult for DecodeResult {
    fn get_codepoints(&self) -> Vec<codec::Grapheme> {
        self.parsed
            .iter()
            .map(|codepoint| codepoint.into())
            .collect()
    }
    fn to_string(&self) -> String {
        ToString::to_string(self)
    }
}

impl GuestNormalizedCiphertext for NormalizedCiphertext {
    fn new(ciphertext: String) -> Self {
        NormalizedCiphertext::new(&ciphertext)
    }
    fn text(&self) -> String {
        self.text().to_string()
    }
}

export!(Codec);
