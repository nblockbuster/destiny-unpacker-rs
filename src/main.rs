use std::env;
mod structs;
use std::fs;
use std::fs::File;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::io::Write;
//use openssl::symm::{decrypt_aead, Cipher, Crypter, Mode};
//use aead::{Aead, AeadCore, AeadInPlace};
use aes_gcm::{Aes128Gcm, Key, Nonce, Tag};
use aes_gcm::aead::{AeadInPlace, NewAead};
//use aes_gcm::aead::heapless::Vec;


//use common_math::rounding::*;
//use libm::floorf;
const BLOCK_SIZE: u32 = 262144;

fn main()
{
    /*
    let main_aes_key = [0xD6, 0x2A, 0xB2, 0xC1, 0x0C, 0xC0, 0x1B, 0xC5, 0x35, 0xDB, 0x7B, 0x86, 0x55, 0xC7, 0xDC, 0x3B];
    let aes_key = Key::<Aes128Gcm>::from_slice(&main_aes_key);
    let nonce = Nonce::from_slice(b"unique nonce");
    let cipher = Aes128Gcm::new(aes_key);
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(b"plaintext message");
    cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");
    println!("{:x?}", buffer);
    cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("Decrypt Failed!");
    println!("{:x?}", buffer);
    return;
    */

    //i couldve used a crate for this!

    let args: Vec<String> = env::args().collect();
    //println!("{:?}", args);
    if args.len() < 2 {
        println!("Usage: {} -p [Packages Path] -i [Package Id]", args[0]);
        return;
    }
    let package_check = &args[1];
    if package_check == "-p" && args.len() >= 3 {
        println!("Packages Path: {}", args[2]);
    } else {
        println!("Usage: {} -p [Packages Path] -i [Package Id]", args[0]);
        return
    }

    let id_check = &args[3];

    if id_check == "-i" && args.len() >= 5 {
        println!("Package Id: {}", args[4]);
    } else {
        println!("Usage: {} -p [Packages Path] -i [Package Id]", args[0]);
        return
    }

    let mut package = structs::Package::new(args[2].to_string(), args[4].to_string());
    package = read_header(package);
    package = modify_nonce(package);
    //read entry table with mutable package
    package = read_entry_table(package);
    //read blocks with mutable package
    package = read_block_table(package);
    extract_files(package);
}

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

pub fn read_header(mut package: structs::Package) -> structs::Package
{
    let mut file = File::open(package.package_path.clone()).expect("Error reading file");
    let mut header = structs::Header::new();
    
    file.seek(SeekFrom::Start(0x10)).expect("Error seeking");
    let mut u16buffer = [0; 2];
    let mut u32buffer = [0; 4];

    file.read(&mut u16buffer).expect("Error reading file");
    header.pkgid = le_u16(&u16buffer);

    file.seek(SeekFrom::Start(0x30)).expect("Error seeking");
    file.read(&mut u16buffer).expect("Error reading file");
    header.patchid = le_u16(&u16buffer);

    file.seek(SeekFrom::Start(0x44)).expect("Error seeking");
    file.read(&mut u32buffer).expect("Error reading file");
    header.entry_table_offset = le_u32(&u32buffer);
    
    file.seek(SeekFrom::Start(0x60)).expect("Error seeking");
    file.read(&mut u32buffer).expect("Error reading file");
    header.entry_table_size = le_u32(&u32buffer);
    
    file.seek(SeekFrom::Start(0x68)).expect("Error seeking");
    file.read(&mut u32buffer).expect("Error reading file");
    header.block_table_size = le_u32(&u32buffer);
    file.read(&mut u32buffer).expect("Error reading file");
    header.block_table_offset = le_u32(&u32buffer);

    file.seek(SeekFrom::Start(0xB8)).expect("Error seeking");
    file.read(&mut u32buffer).expect("Error reading file");
    header.hash64_table_size = le_u32(&u32buffer);
    file.read(&mut u32buffer).expect("Error reading file");
    header.hash64_table_offset = le_u32(&u32buffer);
    header.hash64_table_offset += 64;

    package.header = header;
    return package;
}

pub fn read_entry_table(mut package: structs::Package) -> structs::Package
{
    let mut file = File::open(package.package_path.clone()).expect("Error reading file");
    let a = package.header.entry_table_offset+package.header.entry_table_size*16;
    for i in (package.header.entry_table_offset..a).step_by(16)
    {
        let mut entry:structs::Entry = structs::Entry::new();

        let entrya:u32;
        let mut u32buffer = [0; 4];
        file.seek(SeekFrom::Start(i.into())).expect("Error seeking");
        file.read(&mut u32buffer).expect("Error reading file");
        entrya = be_u32(&u32buffer);
        entry.reference = format!("{:08x}", entrya);
        
        let entryb:u32;
        file.read(&mut u32buffer).expect("Error reading file");
        entryb = le_u32(&u32buffer);
        entry.numtype = ((entryb >> 9) & 0x7F) as u8;
        entry.numsubtype = ((entryb >> 6) & 0x7) as u8;

        let entryc:u32;
        file.read(&mut u32buffer).expect("Error reading file");
        entryc = le_u32(&u32buffer);
        
        entry.startingblock = entryc & 16383;
        entry.startingblockoffset = ((entryc >> 14) & 16383) << 4;

        let entryd:u32;
        file.read(&mut u32buffer).expect("Error reading file");
        entryd = le_u32(&u32buffer);

        entry.filesize = (entryd & 0x03FFFFFF) << 4 | (entryc >> 28) & 0xF;

        package.entries.push(entry);
    }
    package.entries.remove(0);
    return package;
}

pub fn read_block_table(mut package:structs::Package) -> structs::Package
{
    let mut file = File::open(package.package_path.clone()).expect("Error reading file");
    let a = package.header.block_table_offset+package.header.block_table_size*48;
    for b in (package.header.block_table_offset..a).step_by(48)
    {
        let mut block:structs::Block = structs::Block::new();
        let mut u32buffer = [0; 4];
        let mut u16buffer = [0; 2];
        let mut gcmtag_buffer = [0; 16];
        file.seek(SeekFrom::Start(b.into())).expect("Error seeking");
        file.read(&mut u32buffer).expect("Error reading file");
        block.offset = le_u32(&u32buffer);
        file.read(&mut u32buffer).expect("Error reading file");
        block.size = le_u32(&u32buffer);
        
        file.read(&mut u16buffer).expect("Error reading file");
        block.patchid = le_u16(&u16buffer);
        
        file.read(&mut u16buffer).expect("Error reading file");
        block.bitflag = le_u16(&u16buffer);

        file.seek(SeekFrom::Current(0x20)).expect("Error seeking");
        file.read(&mut gcmtag_buffer).expect("Error reading file");
        block.gcmtag = gcmtag_buffer;
        //println!("Offset: {}\nSize: {}\nPatchID: {}", &block.offset, &block.size, &block.patchid);
        package.blocks.push(block);
        //std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    package.blocks.remove(0);
    return package;
}

fn modify_nonce(mut package: structs::Package) -> structs::Package
{
    package.nonce[0] ^= (package.header.pkgid >> 8) as u8 & 0xFF;
    package.nonce[11] ^= package.header.pkgid as u8 & 0xFF;
    return package;
}

fn extract_files(package: structs::Package)
{
    let mut pkg_patch_stream_paths: Vec<String> = Vec::new();
    let output_path = format!("output/{}", package.package_id);
    fs::create_dir_all(output_path.clone()).expect("Error creating directory");
    for i in 0..=package.header.patchid
    {
        let a = i as u8 + 48;
        let pkg_patch_path = package.package_path.clone();
        let mut b:String = pkg_patch_path.to_string();
        b.remove(b.len()-5);
        b.insert(pkg_patch_path.len()-5, a as char);
        println!("Buh {} @ {}", i, b);
        pkg_patch_stream_paths.push(b.to_string());
    }
    //println!("Package has {} entries.", package.entries.len());
    //println!("Entry Reference: {}, File Size: {}", &package.entries[1].reference, &package.entries[1].filesize);
    for i in 0..package.entries.len()
    {
        let entry = &package.entries[i];
        //println!("Entry Reference: {}, File Size: {}", &entry.reference, &entry.filesize);
        if entry.numtype != 26
        {
            //println!("Entry is not 26 (wem/bnk). Skipping");
            continue;
        }
        let mut cur_block_id = entry.startingblock;
        //println!("curblockid: {}, starting blockoffset: {} ", cur_block_id, entry.startingblockoffset);
        let mut block_count:u32 = libm::floorf((entry.startingblockoffset as f32 + entry.filesize as f32 - 1.0_f32) / BLOCK_SIZE as f32) as u32;
        if entry.filesize == 0
        {
            block_count = 0;
        }
        let last_block_id = cur_block_id + block_count;
        let mut file_buffer = vec![0u8; entry.filesize as usize];
        let mut current_buffer_offset = 0;
        while cur_block_id <= last_block_id
        {
            let current_block = &package.blocks[cur_block_id as usize];
            let mut file = File::open(&pkg_patch_stream_paths[current_block.patchid as usize]).expect("Error reading file");
            //println!("seek to {} in file {}", current_block.offset, pkg_patch_stream_paths[current_block.patchid as usize]);
            file.seek(SeekFrom::Start(current_block.offset as u64)).expect("Error seeking");
            let mut block_buffer = vec![0; current_block.size as usize];
            let result = file.read(&mut block_buffer).expect("Error reading file");
            if result != current_block.size as usize
            {
                println!("Error reading file");
            }
            let mut decrypt_buffer:Vec<u8> = vec![0u8; current_block.size as usize];
            let mut decomp_buffer:Vec<u8> = vec![0u8; BLOCK_SIZE as usize];
            //println!("Decrypt Check: {}", current_block.bitflag & 2);
            if current_block.bitflag & 0x2 != 0
            {
                //decrypt_buffer = block_buffer;
                println!("Block is encrypted.");
                decrypt_buffer = decrypt_block(&package, &current_block, &block_buffer);
                //break;
            }
            else
            {
                
                decrypt_buffer = block_buffer
            }
            //println!("Decomp Check: {}", current_block.bitflag & 1);
            if current_block.bitflag & 0x1 != 0
            {
                //decomp_buffer = decrypt_buffer;
                println!("Block is compressed.");
                decomp_buffer = decompress_block(&current_block, &decrypt_buffer);
                //break;
            }
            else
            {
                decomp_buffer = decrypt_buffer;
            }
            if cur_block_id == entry.startingblock
            {
                //println!("Start block");
                let mut _cpy_size = 0;

                if cur_block_id == last_block_id
                {
                    _cpy_size = entry.filesize;
                    //println!("Start block is last block. Cpy size: {}", _cpy_size);
                }
                else
                {
                    _cpy_size = BLOCK_SIZE - entry.startingblockoffset;
                    //println!("Start block not last block. Cpy size: {}, Last Block: {}", _cpy_size, last_block_id);
                }
                //println!("Copying from starting offset {} to end offset {}", entry.startingblockoffset, entry.startingblockoffset + _cpy_size);
                file_buffer[0.._cpy_size as usize].copy_from_slice(&decomp_buffer[entry.startingblockoffset as usize..entry.startingblockoffset as usize + _cpy_size as usize]);

                current_buffer_offset += _cpy_size as usize;
                //println!("{} copied.\nFinish Start block", _cpy_size);
                //std::thread::sleep(std::time::Duration::from_millis(1000));
            }
            else if cur_block_id == last_block_id
            {
                //println!("Last block. Current buffer offset: {}", current_buffer_offset);
                file_buffer[current_buffer_offset as usize..]
                .copy_from_slice(&decomp_buffer[..(entry.filesize - current_buffer_offset as u32) as usize]);
                //println!("Finish Last block");
            }
            else
            {
                //println!("Mid block");
                //Copy amount BLOCK_SIZE from decomp_buffer to file_buffer at offset current_buffer_offset
                file_buffer[current_buffer_offset as usize..(current_buffer_offset + BLOCK_SIZE as usize) as usize].copy_from_slice(&decomp_buffer[0..BLOCK_SIZE as usize]);
                current_buffer_offset += BLOCK_SIZE as usize;
                //println!("Finish Mid block. Current Buffer Offset: {}", current_buffer_offset);
            }
            file.flush().expect("Error flushing file");
            cur_block_id +=1;
            //println!("blockid+=1 =: {}", cur_block_id);
            decomp_buffer.clear();
        }
        //println!("{}", format!("{}/{}-{:04x}.bin", output_path, package.package_id, i));
        //let name = format!("{}/{}-{:04x}.wem", output_path, package.package_id, i);
        if le_u32(&file_buffer[0..4]) == 0
        {
            continue;
        }
        let mut cus_out:String = output_path.clone();
        let mut ext = "wem";
        let mut file_name = entry.reference.to_uppercase();
        if entry.numsubtype == 6
        {
            ext = "bnk";
            cus_out.push_str("/bnk"); 
            file_name = format!("{}-{:04x}", package.package_id, i);
        }
        let name = format!("{}/{}.{}", &cus_out, file_name, ext);
        let mut output_file = File::create(&name).expect("Error creating file");
        output_file.write(&file_buffer).expect("Error writing file");
        //close file
        output_file.flush().expect("Error flushing file");
        output_file.sync_all().expect("Error syncing file");
        file_buffer.clear();
        println!("Extracted to {}", &name);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!("Extracted all wem files.");
}

//fn decompress_block() -> Result<u32, Box<dyn std::error::Error>> { 
//}


#[allow(non_snake_case)]
fn decompress_block(block: &structs::Block, decrypt_buffer: &Vec<u8>) -> Vec<u8>
{
    unsafe {
        let lib = libloading::Library::new("oo2core_9_win64.dll").expect("Failed to load Oodle.");
        let OodleLZ_Decompress: libloading::Symbol<extern "C" fn(compressed_bytes:Vec<u8>, size_of_compressed_bytes:i64,
            decompressed_bytes: *mut Vec<u8>, size_of_decompressed_bytes:i64,
            a:u32, b:u32, c:u32, d:u32, e:u32, f:u32, g:u32, h:u32, i:u32, threadModule:u32) -> i64>
        = lib.get(b"OodleLZ_Decompress").expect("Failed to load OodleLZ_Decompress funtion.");

        //let decomp = OodleLZ_Decompress();
        //let symbol = symbol.into_raw();
        //Ok(OodleLZ_Decompress());
        let mut decomp_buffer: Vec<u8> = vec![0u8; BLOCK_SIZE as usize];
        let result:i64 = OodleLZ_Decompress(decrypt_buffer.to_vec(), block.size as i64, &mut decomp_buffer, BLOCK_SIZE as i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3);
        println!("Oodle Result: {}", result);
        println!("{:x?}", decomp_buffer);
        std::thread::sleep(std::time::Duration::from_millis(10000));
        //result = OodleLZ_Decompress(&decrypt_buffer, block.size as i64, &decomp_buffer, BLOCK_SIZE as i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3);
        return decomp_buffer;
    }
}


fn decrypt_block(package: &structs::Package, block: &structs::Block, block_buffer: &Vec<u8>) -> Vec<u8>
{
    let mut package_nonce:Vec<u8> = vec![0u8; 12];
    package_nonce.copy_from_slice(&package.nonce);

    package_nonce[0] ^= (package.header.pkgid >> 8) as u8 & 0xFF;
    package_nonce[1] ^= 38;
    package_nonce[11] ^= package.header.pkgid as u8 & 0xFF;
    let mut decrypt_buffer:Vec<u8> = vec![0u8; block.size as usize];
    let alt_key = &block.bitflag & 4 != 0;
    println!("Block alt key check: {}", &block.bitflag & 4);
    let key;
    if alt_key
    {
        println!("Block uses alt key.");
        key = &package.aes_alt_key;
    }
    else
    {
        println!("Block uses normal key.");
        key = &package.aes_key;
    }
    /*
    let mut decrypter = Crypter::new(
        Cipher::aes_128_gcm(),
        Mode::Decrypt,
        key,
        Some(&package_nonce)
    ).unwrap();
    decrypter.set_tag(&block.gcmtag).expect("Failed setting GCM Tag.");
    let mut count = decrypter.update(block_buffer, &mut decrypt_buffer).expect("Decrypt failed updating!");
    count += decrypter.finalize(&mut decrypt_buffer[count..]).expect("Decrypt failed finalizing!");
    println!("Decrypted count: {}", count);
    */
    //let main_aes_key = [0xD6, 0x2A, 0xB2, 0xC1, 0x0C, 0xC0, 0x1B, 0xC5, 0x35, 0xDB, 0x7B, 0x86, 0x55, 0xC7, 0xDC, 0x3B];
    let aes_key = Key::<Aes128Gcm>::from_slice(key);
    let tag = Tag::from_slice(&block.gcmtag);
    let nonce = Nonce::from_slice(&package_nonce);
    let cipher = Aes128Gcm::new(aes_key);
    let mut buffer: Vec<u8> = Vec::new();
    buffer.extend_from_slice(block_buffer);
    cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag).expect_err("Decrypt Failed!");
    //cipher.decrypt_in_place(nonce, b"", &mut buffer).expect_err("Decrypt Failed!");
    //println!("{:x?}", buffer);
    return buffer;
}