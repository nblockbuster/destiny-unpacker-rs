#![allow(dead_code)]
use std::{u8, u16, u32, u64}; 

pub fn le_u16(buf: &[u8]) -> u16 {
    return ((buf[1] as u16) << 8) | buf[0] as u16;
}

pub fn be_u16(buf: &[u8]) -> u16 {
    return ((buf[0] as u16) << 8) | buf[1] as u16;
}

pub fn le_u32(buf: &[u8]) -> u32 {
    return ((buf[3] as u32) << 24) | ((buf[2] as u32) << 16) | ((buf[1] as u32) << 8) | buf[0] as u32;
}

pub fn be_u32(buf: &[u8]) -> u32 {
    return ((buf[0] as u32) << 24) | ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
}

pub fn swap_u16_endianness(x:u16) -> u16 {
	return (x << 8) + (x >> 8);
}

pub fn swap_u32_endianness(x:u32) -> u32 {
    return (x >> 24) |
		((x << 8) & 0x00FF0000) |
		((x >> 8) & 0x0000FF00) |
		(x << 24);
}

pub fn swap_u64_endianness(x:u64) -> u64 {
    return (x << 56) |
		((x & 0x000000000000FF00) << 40) |
		((x & 0x0000000000FF0000) << 24) |
		((x & 0x00000000FF000000) << 8) |
		((x & 0x000000FF00000000) >> 8) |
		((x & 0x0000FF0000000000) >> 24) |
		((x & 0x00FF000000000000) >> 40) |
		(x >> 56);
}

pub fn hex_str_to_u16(hash:String) -> u16{
    return u16::from_str_radix(hash.as_str(), 16).unwrap();
}

pub fn hex_str_to_u32(hash:String) -> u32{
    return u32::from_str_radix(&hash, 16).unwrap();
}

pub fn hex_str_to_u64(hash:String) -> u64{
    return u64::from_str_radix(&hash, 16).unwrap();
}

pub fn u16_to_hex_str(hash:u32) -> String{
    return format!("{:04x}", hash)
}

pub fn u32_to_hex_str(hash:u32) -> String{
    return format!("{:08x}", hash)
}

pub fn get_hash_from_file(name:String) -> String {
    let firsthex_int:u16;
    let secondhex_int:u16;
    let one:u32;
    let pkgn = name.get(0..=3).unwrap();
    let id = name.get(5..).unwrap();
    firsthex_int = hex_str_to_u16(pkgn.to_string());
    secondhex_int = hex_str_to_u16(id.to_string());
    one = firsthex_int as u32 * 8192;
    return format!("{:08x}", swap_u32_endianness(one+secondhex_int as u32+2155872256));
}