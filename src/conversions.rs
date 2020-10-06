use std;

// Conversions used internally to parse IPFIX headers and specifiers

#[inline]
pub fn be_buf_to_u16(s: &[u8]) -> u16 {
    unsafe { std::mem::transmute([s[1], s[0]]) }
}

#[inline]
pub fn be_buf_to_u32(s: &[u8]) -> u32 {
    unsafe { std::mem::transmute([s[3], s[2], s[1], s[0]]) }
}

#[inline]
pub fn be_buf_to_u64(s: &[u8]) -> u64 {
    unsafe { std::mem::transmute([s[7], s[6], s[5], s[4], s[3], s[2], s[1], s[0]]) }
}
