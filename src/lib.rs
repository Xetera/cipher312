mod normalizer;
mod symbols;

use nom::{
    bytes::{complete::tag, take_until},
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

type ReplacementRule<'a> = (&'a [u8], &'a str);

const REPLACEMENT_RULES: [ReplacementRule<'static>; 3] = [
    (b"11".as_slice(), "4"),
    (b"22".as_slice(), "5"),
    (b"33".as_slice(), "6"),
];

#[derive(Debug)]
struct Mapping {
    source: &'static str,
    variants: Vec<&'static str>,
    target: char,
}

// 111 -> [41, 14]
// only works on 2 digit replacers
fn generate_variants_static(
    text: &'static str,
    replacements: &[ReplacementRule],
) -> Vec<&'static str> {
    let bytes = text.as_bytes();
    let mut results = vec![];

    for i in 0..bytes.len().saturating_sub(1) {
        for &(source, target) in replacements {
            if bytes[i..i + 2] == *source {
                let mut variant = text.to_string();
                variant.replace_range(i..i + 2, target);
                // crimes
                results.push(Box::leak(variant.into_boxed_str()) as &'static str);
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
            for &variant in &mapping.variants {
                if let Ok((rest, _)) = tag::<_, _, nom::error::Error<_>>(variant)(input) {
                    return Ok((rest, char(mapping.target)));
                }
            }
        }
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )))
    }
}

#[derive(Clone, Debug)]
pub enum UnicodeParseError {
    InvalidCipher,
    InvalidHexadecimal,
}

pub fn unicode_parser<'a>(
) -> impl Parser<&'a str, Output = Grapheme, Error = nom::error::Error<&'a str>> {
    const D: &str = "791";
    delimited(tag(D), take_until(D), tag(D)).map(|res| {
        let normalized = NormalizedCiphertext::new(res);
        match Codec::decode_v2(normalized) {
            Ok(("", decoded)) => {
                let digits = decoded.to_string();
                let Ok(digit) = u32::from_str_radix(&digits, 16) else {
                    return Grapheme::InvalidUnicode(UnicodeParseError::InvalidHexadecimal);
                };
                let Some(chr) = char::from_u32(digit) else {
                    return Grapheme::InvalidUnicode(UnicodeParseError::InvalidHexadecimal);
                };
                Grapheme::KnownValue(chr)
            }
            Ok((_, _)) | Err(_) => Grapheme::InvalidUnicode(UnicodeParseError::InvalidCipher),
        }
    })
}

pub struct Codec;
impl Codec {}

impl Guest for Codec {
    type NormalizedCiphertext = normalizer::NormalizedCiphertext;
    fn decode_v1(input: NormalizedCiphertextBorrow) -> Result<DecodeResult, ()> {
        let mappings = Mappings::new(&V1_SYMBOL_MAPPING, &REPLACEMENT_RULES);
        many1(move |c| mappings.parse(c))
            .map(|graphemes: Vec<Grapheme>| DecodeResult { parsed: graphemes })
            .parse(input)
            .map_err(|_| ())
            .map(|e| e.1)
    }

    fn decode_v2(input: codec::NormalizedCiphertextBorrow) -> IResult<DecodeResult, ()> {
        let mappings = Mappings::new(&V2_SYMBOL_MAPPING, &REPLACEMENT_RULES);
        let mut unicode = unicode_parser();
        many1(move |c| unicode.parse(c).or_else(|_| mappings.parse(c)))
            .map(|graphemes: Vec<Grapheme>| DecodeResult { parsed: graphemes })
            .parse(input.text())
    }
    // TODO: tag this based on the correct version?
    fn decode(input: codec::NormalizedCiphertextBorrow) -> Result<DecodeResult, ()> {
        Codec::decode_v1(input).or_else(|_| Codec::decode_v2(input))
    }
}

impl ToString for DecodeResult {
    fn to_string(&self) -> String {
        self.parsed
            .iter()
            .map(|g| match g {
                Grapheme::KnownValue(c) => c.to_string(),
                Grapheme::UnknownSequence(t) => format!("?-{}-?", t),
                Grapheme::InvalidUnicode(_) => "⊠".to_string(),
            })
            .collect::<Vec<String>>()
            .join("")
    }
}

export!(Codec);
export!(NormalizedCiphertext);

#[cfg(test)]
mod tests {
    // const mojibake: &'static str = "18581é‡ æ--°è£½ä½œ";
    use crate::exports::xetera::cipher312::codec::{self, Guest};
    use nom::{multi::many1, IResult, Parser};

    use crate::{
        exports::xetera::cipher312::codec::NormalizedCiphertext, Codec, DecodeResult, Mappings,
        REPLACEMENT_RULES,
    };
    // text only tests that should be passed by both decoders
    const SHARED_TESTS: &[(&str, &str)] = &[
        ("54634341653520343124126312", "MISSION START"),
        ("1321521321353", "HELLO"),
        ("31561652412661031323424431215", "TRINARY UPDATE"),
        ("3515413121321526031323424431215", "WEATHER UPDATE"),
    ];
    fn run_test(
        input: &str,
        f: fn(i: &codec::NormalizedCiphertext) -> Result<DecodeResult, ()>,
    ) -> DecodeResult {
        let normalized = NormalizedCiphertext::new(input.to_string());
        let result = match f(&normalized) {
            Ok(result) => (result),
            Err(err) => panic!("Deciphering failed for input: {}, {}", input, err),
        };
        // if leftover != "" {
        //     eprintln!("{:?} : leftover {}", result, leftover);
        //     panic!("Unexpected leftover ciphertext")
        // }
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
        let cases = &[
            ("794842328138412791", "👻"),
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
        ];
        for (input, expected) in [SHARED_TESTS, cases].concat() {
            assert_eq!(run_test(input, Codec::decode).to_string(), expected);
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
