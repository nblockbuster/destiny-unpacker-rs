#![allow(dead_code)]
use std::{u8, u16, u32, u64}; 
use libm::floorf;

#[inline(always)]
pub fn split_u16(spl:u16) -> [u8; 2] {
    let mut spl_arr: [u8; 2] = [0; 2];
    spl_arr[0] = (spl & 0xFF) as u8;
    spl_arr[1] = ((spl >> 8) & 0xFF) as u8;
    spl_arr
}
#[inline(always)]
pub fn split_u32(spl:u32) -> [u8; 4] {
    let mut spl_arr: [u8; 4] = [0; 4];
    spl_arr[0] = (spl & 0xFF) as u8;
    spl_arr[1] = ((spl >> 8) & 0xFF) as u8;
    spl_arr[2] = ((spl >> 16) & 0xFF) as u8;
    spl_arr[3] = ((spl >> 24) & 0xFF) as u8;
    spl_arr
}

#[inline(always)]
pub fn le_u16(buf: &[u8]) -> u16 {
    (u16::from(buf[1]) << 8) |
    u16::from(buf[0])
}
#[inline(always)]
pub fn be_u16(buf: &[u8]) -> u16 {
    (u16::from(buf[0]) << 8) |
    u16::from(buf[1])
}
#[inline(always)]
pub fn le_u32(buf: &[u8]) -> u32 {
    (u32::from(buf[3]) << 24) |
    (u32::from(buf[2]) << 16) |
    (u32::from(buf[1]) << 8) |
    u32::from(buf[0])
}
#[inline(always)]
pub fn be_u32(buf: &[u8]) -> u32 {
    (u32::from(buf[0]) << 24) |
    (u32::from(buf[1]) << 16) |
    (u32::from(buf[2]) << 8) |
    u32::from(buf[3])
}
#[inline(always)]
pub fn swap_u16_endianness(x:u16) -> u16 {
	(x << 8) + (x >> 8)
}

pub fn swap_u32_endianness(x:u32) -> u32 {
    (x >> 24) |
    ((x << 8) & 0x00FF_0000) |
    ((x >> 8) & 0x0000_FF00) |
    (x << 24)
}

pub fn swap_u64_endianness(x:u64) -> u64 {
    (x << 56) |
	((x & 0x0000_0000_0000_FF00) << 40) |
	((x & 0x0000_0000_00FF_0000) << 24) |
	((x & 0x0000_0000_FF00_0000) << 8) |
	((x & 0x0000_00FF_0000_0000) >> 8) |
	((x & 0x0000_FF00_0000_0000) >> 24) |
	((x & 0x00FF_0000_0000_0000) >> 40) |
	(x >> 56)
}
#[inline(always)]
pub fn hex_str_to_u16(hash:String) -> u16{
    u16::from_str_radix(hash.as_str(), 16).unwrap()
}
#[inline(always)]
pub fn hex_str_to_u32(hash:String) -> u32{
    u32::from_str_radix(&hash, 16).unwrap()
}
#[inline(always)]
pub fn hex_str_to_u64(hash:String) -> u64{
    u64::from_str_radix(&hash, 16).unwrap()
}
#[inline(always)]
pub fn u16_to_hex_str(hash:u16) -> String{
    format!("{:04x}", hash)
}
#[inline(always)]
pub fn u32_to_hex_str(hash:u32) -> String{
    format!("{:08x}", hash)
}

pub fn get_hash_from_file(name:String) -> String {
    let pkgn = name.get(0..=3).unwrap();
    let id = name.get(5..).unwrap();
    let firsthex_int:u16 = hex_str_to_u16(pkgn.to_string());
    let secondhex_int:u16 = hex_str_to_u16(id.to_string());
    let one:u32 = u32::from(firsthex_int) * 8192;
    format!("{:08x}", swap_u32_endianness(one+u32::from(secondhex_int)+2_155_872_256))
}

pub fn get_file_from_hash(hash:String) -> String {
    let first_int:u32 = hex_str_to_u32(hash);
    let one:u32 = first_int - 2_155_872_256;
    let first_hex:String = u16_to_hex_str(floorf(one as f32 /8192.0) as u16);
    let second_hex:String = u16_to_hex_str((first_int % 8192) as u16);
    format!("{}-{}", first_hex, second_hex)
}