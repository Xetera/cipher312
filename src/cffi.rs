use std::ffi::{c_char, CString};

use crate::{normalizer::NormalizedCiphertext, Codec};

#[repr(C)]
pub enum DecodeResultC {
    Success = 0,
    /// Either input or output is passed as a null pointer
    NullPointer = 1,
    /// The input string was invalid utf8
    InvalidUtf8 = 2,
    /// Something went wrong with the decoding
    DecodingFailed = 3,
    InternalError = 4,
}

/// decodes a trinary encoded const char* into a string
/// uses ?abc? for invalid trinary pairs that can't be decoded
/// # Safety
/// Requires a valid pointer for both input and out parameters
/// Both can be empty strings otherwise
#[no_mangle]
pub unsafe extern "C" fn decode_string(
    input: *const c_char,
    out: *mut *mut c_char,
) -> DecodeResultC {
    let slice = unsafe { std::ffi::CStr::from_ptr(input) };
    if input.is_null() || out.is_null() {
        return DecodeResultC::NullPointer;
    }
    let str = match slice.to_str() {
        Ok(str) => str,
        Err(_) => return DecodeResultC::InvalidUtf8,
    };
    let normalized = NormalizedCiphertext::new(str);
    match Codec::decode(&normalized) {
        Ok(result) => {
            let cstr = match CString::new(result.to_string()) {
                Ok(cstr) => cstr,
                Err(_) => return DecodeResultC::InternalError,
            };
            unsafe {
                *out = cstr.into_raw();
            }
            DecodeResultC::Success
        }
        Err(_) => DecodeResultC::DecodingFailed,
    }
}

/// # Safety
/// Should only be called with the string returned by a decode function result
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
