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
    ((buf[1] as u16) << 8) |
    buf[0] as u16
}
#[inline(always)]
pub fn be_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) |
    buf[1] as u16
}
#[inline(always)]
pub fn le_u32(buf: &[u8]) -> u32 {
    ((buf[3] as u32) << 24) |
    ((buf[2] as u32) << 16) |
    ((buf[1] as u32) << 8) |
    buf[0] as u32
}
#[inline(always)]
pub fn be_u32(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24) |
    ((buf[1] as u32) << 16) |
    ((buf[2] as u32) << 8) |
    buf[3] as u32
}
#[inline(always)]
pub fn swap_u16_endianness(x:u16) -> u16 {
	(x << 8) + (x >> 8)
}

pub fn swap_u32_endianness(x:u32) -> u32 {
    (x >> 24) |
    ((x << 8) & 0x00FF0000) |
    ((x >> 8) & 0x0000FF00) |
    (x << 24)
}

pub fn swap_u64_endianness(x:u64) -> u64 {
    (x << 56) |
	((x & 0x000000000000FF00) << 40) |
	((x & 0x0000000000FF0000) << 24) |
	((x & 0x00000000FF000000) << 8) |
	((x & 0x000000FF00000000) >> 8) |
	((x & 0x0000FF0000000000) >> 24) |
	((x & 0x00FF000000000000) >> 40) |
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
    let one:u32 = firsthex_int as u32 * 8192;
    format!("{:08x}", swap_u32_endianness(one+secondhex_int as u32+2155872256))
}

pub fn get_file_from_hash(hash:String) -> String {
    let first_int:u32 = hex_str_to_u32(hash);
    let one:u32 = first_int - 2155872256;
    let first_hex:String = u16_to_hex_str(floorf(one as f32 /8192.0) as u16);
    let second_hex:String = u16_to_hex_str((first_int % 8192) as u16);
    format!("{}-{}", first_hex, second_hex)
}