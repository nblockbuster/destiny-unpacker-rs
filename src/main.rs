use std::env;
mod structs;
use std::fs;
use std::fs::File;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::io::Write;
//use openssl::symm::{decrypt, Cipher};
//use common_math::rounding::*;
//use libm::floorf;
const BLOCK_SIZE: u32 = 0x40000;

fn main()
{
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    if args.len() < 2 {
        println!("Usage: {} -p [Packages Path] -i [Package Id]", args[0]);
        return;
    }
    let package_check = &args[1];
    if package_check == "-p" && args.len() >= 3 {
        println!("Packages Path: {}", args[2]);
    } else{
        println!("Usage: {} -p [Packages Path] -i [Package Id]", args[0]);
        return
    }

    let id_check = &args[3];

    if id_check == "-i" && args.len() >= 5 {
        println!("Package Id: {}", args[4]);
    } else{
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
        
        entry.startingblock = entryc & 0xFFFFFF;
        entry.startingblockoffset = ((entryc >> 14) & 0x3FFF) <<4;

        let entryd:u32;
        file.read(&mut u32buffer).expect("Error reading file");
        entryd = le_u32(&u32buffer);

        entry.filesize = (entryd & 0x3FFFFFF) << 4 | (entryc >> 28) & 0xF;

        package.entries.push(entry);
    }
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
        package.blocks.push(block);
    }
    return package;
}

fn modify_nonce(mut package: structs::Package) -> structs::Package
{
    package.nonce[0] ^= (package.header.pkgid >> 8) as u8 & 0xFF;
    package.nonce[11] ^= package.header.pkgid as u8 & 0xFF;
    return package;
}

fn byte_copy(from: &[u8], mut to: &mut [u8]) -> usize {
    to.write(&from).unwrap()
}

fn extract_files(package: structs::Package)
{
    let mut pkg_patch_stream_paths: Vec<String> = Vec::new();
    let output_path = format!("output/{}", package.package_id);
    fs::create_dir_all(output_path.clone()).expect("Error creating directory");
    for i in 0..package.header.patchid
    {
        let a = i as u8 + 48;
        let pkg_patch_path = package.package_path.clone();
        let mut b:String = pkg_patch_path.to_string();
        b.remove(b.len()-5);
        b.insert(pkg_patch_path.len()-5, a as char);
        //println!("Buh! {}", b);
        pkg_patch_stream_paths.push(b.to_string());
    }
    println!("Package has {} entries.", package.entries.len());
    //println!("Entry Reference: {}, File Size: {}", &package.entries[1].reference, &package.entries[1].filesize);
    for i in 1..package.entries.len()
    {
        let entry = &package.entries[i];
        println!("Entry Reference: {}, File Size: {}", &entry.reference, &entry.filesize);
        if entry.numtype != 26 && entry.numsubtype != 7
        {
            continue;
        }
        let mut cur_block_id = entry.startingblock;
        let mut block_count:u32 = libm::floorf((entry.startingblockoffset as f32 + entry.filesize as f32 - 1.0_f32) / BLOCK_SIZE as f32) as u32;
        if entry.filesize == 0
        {
            block_count = 0;
        }
        let last_block_id = cur_block_id + block_count;
        let mut file_buffer = vec![0u8; entry.filesize as usize];
        let mut current_buffer_offset = 0;
        let cur_block_offset = 0;
        while cur_block_offset <= last_block_id
        {
            let current_block = &package.blocks[cur_block_id as usize];
            let mut file = File::open(&pkg_patch_stream_paths[current_block.patchid as usize]).expect("Error reading file");
            println!("seek to {}", current_block.offset);
            file.seek(SeekFrom::Start(current_block.offset as u64)).expect("Error seeking");
            let mut block_buffer = vec![0; current_block.size as usize];
            let result = file.read(&mut block_buffer).expect("Error reading file");
            if result != current_block.size as usize
            {
                println!("Error reading file");
            }
            let mut decrypt_buffer = vec![0u8; current_block.size as usize];
            let mut decomp_buffer = vec![0u8; BLOCK_SIZE as usize];
            println!("Decrypt Check: {}", current_block.bitflag & 2);
            if current_block.bitflag & 0x2 != 0
            {
                //decrypt_buffer = block_buffer;
                println!("Block is encrypted. Skipping?");
                break;
            }
            else
            {
                decrypt_buffer = block_buffer
            }
            println!("Decomp Check: {}", current_block.bitflag & 1);
            if current_block.bitflag & 0x1 != 0
            {
                //decomp_buffer = decrypt_buffer;
                println!("Block is compressed. Skipping?");
                break;
            }
            else
            {
                decomp_buffer = decrypt_buffer;
            }
            if cur_block_id == entry.startingblock
            {
                println!("Start block");
                let mut _cpy_size = 0;

                if cur_block_id == last_block_id
                {
                    _cpy_size = entry.filesize;
                    println!("Start block is last block. Cpy size: {}", _cpy_size);
                }
                else
                {
                    _cpy_size = BLOCK_SIZE - entry.startingblockoffset;
                    println!("Start block not last block. Cpy size: {}", _cpy_size);
                }
                //file_buffer.copy_from_slice(&decomp_buffer[entry.startingblockoffset as usize.._cpy_size as usize]);
                unsafe {
                    //file_buffer.copy_nonoverlapping(&decomp_buffer[entry.startingblockoffset as usize.._cpy_size as usize]);
                    let dst_ptr = &mut file_buffer[current_buffer_offset] as *mut u8;
                    let src_ptr = &decomp_buffer[entry.startingblockoffset as usize] as *const u8;
                    std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, _cpy_size as usize)
                }
                //byte_copy(&decomp_buffer[entry.startingblockoffset as usize.._cpy_size as usize], &mut file_buffer[current_buffer_offset..]);
                current_buffer_offset += _cpy_size as usize;
                println!("{:?}", file_buffer);
                println!("{} copied.\nFinish Start block", _cpy_size);
                std::thread::sleep_ms(500);
            }
            else if cur_block_id == last_block_id
            {
                println!("Last block");
                file_buffer[current_buffer_offset as usize..].copy_from_slice(&decomp_buffer[0..entry.filesize as usize]);
                println!("Finish Last block");
            }
            else
            {
                println!("Mid block");
                //Copy amount BLOCK_SIZE from decomp_buffer to file_buffer at offset current_buffer_offset
                file_buffer[current_buffer_offset as usize..(current_buffer_offset + BLOCK_SIZE as usize) as usize].copy_from_slice(&decomp_buffer[0..BLOCK_SIZE as usize]);
                current_buffer_offset += BLOCK_SIZE as usize;
                println!("Finish Mid block");
            }
            file.flush().expect("Error flushing file");
            cur_block_id+=1;
            decomp_buffer.clear();
        }
        println!("{}", format!("{}/{}-{:04x}.bin", output_path, package.package_id, i));
        let name = format!("{}/{}-{:04x}.bin", output_path, package.package_id, i);
        let mut output_file = File::create(&name).expect("Error creating file");
        output_file.write(&file_buffer).expect("Error writing file");
        //close file
        output_file.flush().expect("Error flushing file");
        output_file.sync_all().expect("Error syncing file");
        file_buffer.clear();
        println!("Extracted to {}", &name);
        std::thread::sleep_ms(1000);
    }
}

/*

fn init_oodle() -> i64
{
    unsafe{
        let lib = winapi::um::libloaderapi::LoadLibraryA(b"oo2core_9_win64.dll".as_ptr() as *const i8);
        let func = winapi::um::libloaderapi::GetProcAddress(lib, b"OodleLZ_Decompress".as_ptr() as *const i8) as i64;
        if func == 0
        {
            println!("Error loading OodleLZ_Decompress");
        }
        return func;
    }
}

fn decomp_block(block: &structs::Block, decrypt_buffer: &Vec<u8>, decomp_buffer: &mut Vec<u8>)
{
    let result:i64 = 0;
    let oodle_decomp = init_oodle();
    result = oodle_decomp(decrypt_buffer, block.size, decomp_buffer, BLOCK_SIZE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3);
}



fn decrypt_block(package: &structs::Package, block: &structs::Block, block_buffer: &Vec<u8>, decrypt_buffer: &mut Vec<u8>)
{
    //decrypt block_buffer data using OpenSSL AES decryption
    //store result in decrypt_buffer
    //iv found as package.nonce, aes key found as package.aes_key
    let mut aes_key = [0; 0x10];
    let mut iv = [0; 0x10];
    aes_key.copy_from_slice(&package.aes_key);
    iv.copy_from_slice(&package.nonce);
    //let cipher = Cipher::aes_128_gcm();
    
    let mut decrypter = openssl::symm::Crypter::new(
        Cipher::aes_128_gcm(),
        openssl::symm::Mode::Decrypt,
        &aes_key,
        Some(&iv)).unwrap();

    
    let mut decrypted_buffer = vec![0; block.size as usize];

    let mut count = decrypter.update(&block_buffer, &mut decrypted_buffer).unwrap();
    count += decrypter.finalize(&mut decrypted_buffer[count..]).unwrap();
    decrypt_buffer.copy_from_slice(&decrypted_buffer);
}

    /*
    let mut decrypter = openssl::symm::decrypt(
        cipher,
        &aes_key,
        Some(&iv),
        &block_buffer).unwrap();
    */
    //aes_decryptor.set_key(&aes_key);
    //aes_decryptor.set_iv(&iv);

    //let mut decryptor = openssl::symm::Crypter::new(aes_decryptor, openssl::symm::Mode::Decrypt);
    //decryptor.init(openssl::symm::Operation::Decrypt).expect("Error initializing decryptor");
    //decrypt_buffer = decryptor.update(&block_buffer).expect("Error decrypting block");
    //decryptor.finalize().expect("Error finalizing decryptor");
    //return decrypt_buffer
    
//}
*/