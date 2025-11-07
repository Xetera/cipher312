mod normalizer;
mod symbols;

use core::fmt;

use nom::{
    bytes::complete::{tag, take_until, take_while_m_n},
    multi::many1,
    sequence::delimited,
    IResult, Parser,
};

wit_bindgen::generate!({
    world: "cipher312"
});

use crate::{
    exports::xetera::cipher312::codec::{self, Guest, NormalizedCiphertextBorrow},
    normalizer::NormalizedCiphertext,
    symbols::{SymbolMapping, V1_SYMBOL_MAPPING, V2_SYMBOL_MAPPING},
};

#[derive(Clone, Debug)]
pub enum Grapheme {
    KnownValue(char),
    UnknownSequence(String),
    InvalidUnicode(UnicodeParseError),
}

fn char<T: Into<char>>(value: T) -> Grapheme {
    Grapheme::KnownValue(value.into())
}

#[derive(Debug)]
pub struct DecodeResult {
    parsed: Vec<Grapheme>,
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

type ReplacementRule<'a> = (&'a [u8], &'a str);

const REPLACEMENT_RULES: [ReplacementRule<'static>; 3] = [
    (b"11".as_slice(), "4"),
    (b"22".as_slice(), "5"),
    (b"33".as_slice(), "6"),
];

#[derive(Debug)]
struct Mapping {
    source: &'static str,
    variants: Vec<String>,
    target: char,
}

/// 111 -> [41, 14]
///
/// only works on 2 digit replacers
fn generate_variants_static(text: &str, replacements: &[ReplacementRule]) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut results = vec![];

    for i in 0..bytes.len().saturating_sub(1) {
        for &(source, target) in replacements {
            if bytes[i..i + 2] == *source {
                let mut variant = text.to_string();
                variant.replace_range(i..i + 2, target);
                results.push(variant);
            }
        }
    }

    results
}

#[derive(Debug)]
struct Mappings(Vec<Mapping>);

impl Mappings {
    fn new(kvs: &[SymbolMapping], replacement_rules: &[ReplacementRule]) -> Self {
        Self(
            kvs.iter()
                .map(|&(source, target)| Mapping {
                    source,
                    variants: generate_variants_static(source, replacement_rules),
                    target,
                })
                .collect(),
        )
    }
    fn parse<'a>(&self, input: &'a str) -> IResult<&'a str, Grapheme> {
        for mapping in &self.0 {
            if let Ok((rest, _)) = tag::<_, _, nom::error::Error<_>>(mapping.source)(input) {
                return Ok((rest, char(mapping.target)));
            }
            for variant in mapping.variants.iter() {
                if let Ok((rest, _)) = tag::<_, _, nom::error::Error<_>>(variant.as_str())(input) {
                    return Ok((rest, char(mapping.target)));
                }
            }
        }
        let (rest, trinary) = take_while_m_n(1, 3, |_| true).parse(input)?;
        Ok((rest, Grapheme::UnknownSequence(trinary.to_owned())))
    }
}

#[derive(Clone, Debug)]
pub enum UnicodeParseError {
    InvalidCipher,
    InvalidHexadecimal,
}

// TODO: this requires a lot
pub fn unicode_parser<'a>(
) -> impl Parser<&'a str, Output = Grapheme, Error = nom::error::Error<&'a str>> {
    const D: &str = "791";
    delimited(tag(D), take_until(D), tag(D)).map(|res: &str| {
        let normalized = NormalizedCiphertext::new(res);
        match Codec::decode_v2(&normalized) {
            Ok(decoded) => {
                let digits = decoded.to_string();
                let Ok(digit) = u32::from_str_radix(&digits, 16) else {
                    return Grapheme::InvalidUnicode(UnicodeParseError::InvalidHexadecimal);
                };
                let Some(chr) = char::from_u32(digit) else {
                    return Grapheme::InvalidUnicode(UnicodeParseError::InvalidHexadecimal);
                };
                Grapheme::KnownValue(chr)
            }
            Err(_) => Grapheme::InvalidUnicode(UnicodeParseError::InvalidCipher),
        }
    })
}

pub struct Codec;
impl Codec {
    /// Decodes specifically the early version of the
    /// trinary found before https://www.youtube.com/watch?v=VGK3Ag06VaU
    pub fn decode_v1(
        input: &NormalizedCiphertext,
    ) -> Result<DecodeResult, nom::Err<nom::error::Error<&str>>> {
        let mappings = Mappings::new(&V1_SYMBOL_MAPPING, &REPLACEMENT_RULES);
        many1(move |c| mappings.parse(c))
            .map(|graphemes: Vec<Grapheme>| DecodeResult { parsed: graphemes })
            .parse(input.text())
            .map(|a| a.1)
    }
    /// Decodes the new version of the trinary found after
    /// https://www.youtube.com/watch?v=VGK3Ag06VaU
    pub fn decode_v2(
        input: &NormalizedCiphertext,
    ) -> Result<DecodeResult, nom::Err<nom::error::Error<&str>>> {
        let mappings = Mappings::new(&V2_SYMBOL_MAPPING, &REPLACEMENT_RULES);
        let mut unicode = unicode_parser();
        many1(move |c| unicode.parse(c).or_else(|_| mappings.parse(c)))
            .map(|graphemes: Vec<Grapheme>| DecodeResult { parsed: graphemes })
            .parse(input.text())
            .map(|a| a.1)
    }
    /// Tries to decode the message using the new decoder and
    /// fallsback to the old if it doesn't work
    pub fn decode(
        input: &NormalizedCiphertext,
    ) -> Result<DecodeResult, nom::Err<nom::error::Error<&str>>> {
        match Codec::decode_v2(input) {
            Ok(result) => Ok(result),
            Err(_) => Codec::decode_v1(input),
        }
    }
    // fn encode_v2(input: &str) -> Result<String, ()> {
    //     input
    //         .chars()
    //         .into_iter()
    //         .map(|char| {
    //             if let Some(symbol) =
    //                 V2_SYMBOL_MAPPING
    //                     .iter()
    //                     .find_map(|&(v, k)| if k == char { Some(v) } else { None })
    //             {
    //                 Ok(symbol.to_string())
    //             } else {
    //                 Err(())
    //             }
    //         })
    //         .collect::<String>()
    // }
}

impl Guest for Codec {
    type NormalizedCiphertext = normalizer::NormalizedCiphertext;
    type DecodeResult = DecodeResult;
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

impl fmt::Display for DecodeResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.parsed
            .iter()
            .map(|g| match g {
                Grapheme::KnownValue(c) => c.to_string(),
                Grapheme::UnknownSequence(t) => format!("¿{}?", t),
                // TODO: handle this better
                Grapheme::InvalidUnicode(_) => "⊠".to_string(),
            })
            .collect::<Vec<String>>()
            .join("")
            .fmt(f)
    }
}

export!(Codec);

#[cfg(test)]
mod tests {
    use crate::normalizer::NormalizedCiphertext;
    use nom::{multi::many1, Parser};

    use crate::{Codec, DecodeResult, Mappings, REPLACEMENT_RULES};
    // text only tests that should be passed by both decoders
    const SHARED_TESTS: &[(&str, &str)] = &[
        ("54634341653520343124126312", "MISSION START"),
        ("1321521321353", "HELLO"),
        ("31561652412661031323424431215", "TRINARY UPDATE"),
        ("3515413121321526031323424431215", "WEATHER UPDATE"),
        ("3121534312", "TEST"),
        (
            "16555152604353261505441652312155241524315",
            "INNER CORE MAINTENANCE",
        ),
        (
            "2656161216521504321315412641524315012443124104412345326231312165352",
            "ROUTINE CLEARANCE DATA ABSORPTION",
        ),
        (
            "26153431326261546121512104423123154612165352",
            "RESURRECTED AFFECTION",
        ),
        ("31561652412661031323424431215121", "TRINARY UPDATED"),
        ("41fk", "A¿fk?"),
    ];
    fn run_test(
        input: &str,
        f: fn(i: &NormalizedCiphertext) -> Result<DecodeResult, nom::Err<nom::error::Error<&str>>>,
    ) -> DecodeResult {
        let normalized = NormalizedCiphertext::new(input);
        let result = match f(&normalized) {
            Ok(result) => result,
            Err(err) => panic!("Deciphering failed for input: {}, {:?}", input, err),
        };
        result
    }
    #[test]
    fn test_decipher_v1() {
        for &(input, expected) in SHARED_TESTS {
            assert_eq!(run_test(input, Codec::decode_v1).to_string(), expected);
        }
    }
    #[test]
    fn test_decipher_v2() {
        let cases = &[("794842328138412791", "👻")];
        for (input, expected) in [SHARED_TESTS, cases].concat() {
            assert_eq!(run_test(input, Codec::decode_v2).to_string(), expected);
        }
    }
    #[test]
    fn test_generate_variants() {
        let mappings = Mappings::new(&[("111", 'A'), ("112", 'B')], &REPLACEMENT_RULES);
        let parsed = many1(move |c| mappings.parse(c))
            .map(|e| DecodeResult { parsed: e })
            .parse("4114");
        assert_eq!(parsed.unwrap().1.to_string(), "AA")
    }
}
