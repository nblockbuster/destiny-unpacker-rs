use std::path::Path;
use std::process;
#[path = "utils.rs"]
mod utils;
pub use utils::*;
#[path = "structs.rs"]
pub mod structs;
pub use structs::*;
use std::{fs, thread, process::Command, io::SeekFrom, io::{BufReader, BufWriter, prelude::*}, fs::File};
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};

const BLOCK_SIZE:u32 = 262144;

pub struct Package {
    pub header: Header,
    pub packages_path: String,
    pub entries: Vec<Entry>,
    pub package_path: String,
    pub package_id: String,
    pub nonce: [u8; 12],
    pub blocks: Vec<Block>,
    pub aes_key: [u8; 16],
    pub aes_alt_key: [u8; 16],
    pub oodle:libloading::Library,
}

impl Package {
    pub fn new(pkgspath:String, pkgid:String) -> Package {
        let mut _exists:bool=true;
        let packages_path = pkgspath;
        let package_id = pkgid;
        _exists = Path::new(&packages_path).exists();
        if !_exists {
            println!("Packages Path does not exist");
            process::exit(1);
        }
        let package_path = get_latest_patch_id_path(&packages_path, &package_id);
        let pkgp = package_path;
        Package {
            header: Header::new(),
            nonce: [0x84, 0xEA, 0x11, 0xC0, 0xAC, 0xAB, 0xFA, 0x20, 0x33, 0x11, 0x26, 0x99],
            blocks: vec![Block::new()],
            packages_path,
            package_id,
            package_path: pkgp,
            entries: vec![Entry::new(); 8192],
            aes_key: [0xD6, 0x2A, 0xB2, 0xC1, 0x0C, 0xC0, 0x1B, 0xC5, 0x35, 0xDB, 0x7B, 0x86, 0x55, 0xC7, 0xDC, 0x3B],
            aes_alt_key: [0x3A, 0x4A, 0x5D, 0x36, 0x73, 0xA6, 0x60, 0x58, 0x7E, 0x63, 0xE6, 0x76, 0xE4, 0x08, 0x92, 0xB5],
            oodle: unsafe { libloading::Library::new("oo2core_9_win64.dll") }.unwrap(),
        }
    }

    pub fn read_header(&mut self) -> bool
    {
        let mut u16buffer = [0; 2];
        let mut u32buffer = [0; 4];
        let file = File::open(self.package_path.clone()).expect("Error reading file");
        let mut reader = BufReader::new(file);
        let mut header = Header::new();
        reader.seek(SeekFrom::Start(0x10)).expect("Error seeking file");
        

        reader.read_exact(&mut u16buffer).expect("Error reading file");
        header.pkgid = le_u16(&u16buffer);

        reader.seek(SeekFrom::Start(0x30)).expect("Error seeking");
        reader.read_exact(&mut u16buffer).expect("Error reading file");
        header.patchid = le_u16(&u16buffer);

        reader.seek(SeekFrom::Start(0x44)).expect("Error seeking");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.entry_table_offset = le_u32(&u32buffer);
        
        reader.seek(SeekFrom::Start(0x60)).expect("Error seeking");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.entry_table_size = le_u32(&u32buffer);
        
        reader.seek(SeekFrom::Start(0x68)).expect("Error seeking");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.block_table_size = le_u32(&u32buffer);
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.block_table_offset = le_u32(&u32buffer);

        reader.seek(SeekFrom::Start(0xB8)).expect("Error seeking");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.hash64_table_size = le_u32(&u32buffer);
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        header.hash64_table_offset = le_u32(&u32buffer);
        header.hash64_table_offset += 64;

        reader.seek(SeekFrom::Start(0)).expect("Error seeking");

        self.header = header;

        true
    }
      
    pub fn read_entry_table(&mut self) -> bool
    {
        let file = File::open(self.package_path.clone()).expect("Error reading file");
        let mut reader = BufReader::new(file);
        let a = self.header.entry_table_offset+self.header.entry_table_size*16;
        for i in (self.header.entry_table_offset.to_owned()..a).step_by(16)
        {
            let mut entry: Entry = Entry::new();

            let mut u32buffer = [0; 4];
            reader.seek(SeekFrom::Start(i.into())).expect("Error seeking");
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            let entrya:u32 = be_u32(&u32buffer);
            entry.reference = format!("{:08x}", entrya);
            
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            let entryb:u32 = le_u32(&u32buffer);
            entry.numtype = ((entryb >> 9) & 0x7F) as u8;
            entry.numsubtype = ((entryb >> 6) & 0x7) as u8;

            reader.read_exact(&mut u32buffer).expect("Error reading file");
            let entryc:u32 = le_u32(&u32buffer);
            
            entry.startingblock = entryc & 16383;
            entry.startingblockoffset = ((entryc >> 14) & 16383) << 4;

            reader.read_exact(&mut u32buffer).expect("Error reading file");
            let entryd:u32 = le_u32(&u32buffer);

            entry.filesize = (entryd & 0x03FFFFFF) << 4 | (entryc >> 28) & 0xF;

            self.entries.push(entry);
        }
        reader.seek(SeekFrom::Start(0)).expect("Error seeking");
        self.entries.remove(0);
        
        true
    }  

    pub fn read_block_table(&mut self) -> bool
    {
        let file = File::open(self.package_path.clone()).expect("Error reading file");
        let mut reader = BufReader::new(file);
        let a = self.header.block_table_offset+self.header.block_table_size*48;
        for b in (self.header.block_table_offset..a).step_by(48)
        {
            let mut block: Block = Block::new();
            let mut u32buffer = [0; 4];
            let mut u16buffer = [0; 2];
            let mut gcmtag_buffer = [0; 16];
            reader.seek(SeekFrom::Start(b.into())).expect("Error seeking");
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            block.offset = le_u32(&u32buffer);
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            block.size = le_u32(&u32buffer);
            
            reader.read_exact(&mut u16buffer).expect("Error reading file");
            block.patchid = le_u16(&u16buffer);
            
            reader.read_exact(&mut u16buffer).expect("Error reading file");
            block.bitflag = le_u16(&u16buffer);

            reader.seek(SeekFrom::Current(0x20)).expect("Error seeking");
            reader.read_exact(&mut gcmtag_buffer).expect("Error reading file");
            block.gcmtag = gcmtag_buffer;
            self.blocks.push(block);
        }
        reader.seek(SeekFrom::Start(0)).expect("Error seeking");
        self.blocks.remove(0);

        true
    }

    pub fn modify_nonce(&mut self)
    {
        self.nonce[0] ^= (self.header.pkgid >> 8) as u8;
        self.nonce[11] ^= self.header.pkgid as u8;
    }

    pub fn extract_files(self, extr_opts: structs::ExtrOpts)
    {
        let mut cipher_ctx = CipherCtx::new().unwrap();

        let output_path = extr_opts.output_path.clone();
        let mut pkg_patch_stream_paths: Vec<String> = Vec::new();
        for i in 0..=self.header.patchid
        {
            let a = i as u8 + 48;
            let pkg_patch_path = self.package_path.clone();
            let mut b:String = pkg_patch_path.to_string();
            b.remove(b.len()-5);
            b.insert(pkg_patch_path.len()-5, a as char);
            pkg_patch_stream_paths.push(b.to_string());
        }
        let thread = thread::spawn(move || {
            for i in 0..self.entries.len()
            {
                let entry = &self.entries[i];
                
                if extr_opts.skip_non_audio && !(entry.numtype == 26 && (entry.numsubtype == 6 || entry.numsubtype == 7)) {
                    continue;
                }

                let mut cur_block_id = entry.startingblock;
                let mut block_count:u32 = libm::floorf((entry.startingblockoffset as f32 + entry.filesize as f32 - 1.0) / BLOCK_SIZE as f32) as u32;
                if entry.filesize == 0
                {
                    block_count = 0;
                }
                let last_block_id = cur_block_id + block_count;
                let mut file_buffer = vec![0u8; entry.filesize as usize];
                let mut current_buffer_offset = 0;
                while cur_block_id <= last_block_id
                {
                    let current_block = &self.blocks[cur_block_id as usize];
                    let file = File::open(&pkg_patch_stream_paths[current_block.patchid as usize]).expect("Error reading file");
                    let mut reader = BufReader::new(file);
                    reader.seek(SeekFrom::Start(current_block.offset as u64)).expect("Error seeking");
                    let mut block_buffer = vec![0; current_block.size as usize];
                    let result = reader.read(&mut block_buffer).expect("Error reading file");
                    if result != current_block.size as usize
                    {
                        println!("Error reading file");
                    }
                    let mut _decrypt_buffer:Vec<u8> = vec![0u8; current_block.size as usize];
                    let mut _decomp_buffer:Vec<u8> = vec![0u8; BLOCK_SIZE as usize];
                    if current_block.bitflag & 0x2 != 0
                    {
                        _decrypt_buffer = self.decrypt_block(current_block, block_buffer, &mut cipher_ctx);
                    }
                    else
                    {
                        
                        _decrypt_buffer = block_buffer
                    }
                    if current_block.bitflag & 0x1 != 0
                    {
                        _decomp_buffer = self.decompress_block(current_block, &mut _decrypt_buffer, &extr_opts.oodle);
                    }
                    else
                    {
                        _decomp_buffer = _decrypt_buffer;
                    }
                    if cur_block_id == entry.startingblock
                    {
                        let mut _cpy_size = 0;

                        if cur_block_id == last_block_id
                        {
                            _cpy_size = entry.filesize;
                        }
                        else
                        {
                            _cpy_size = BLOCK_SIZE - entry.startingblockoffset;
                        }
                        file_buffer[0.._cpy_size as usize].copy_from_slice(&_decomp_buffer[entry.startingblockoffset as usize..entry.startingblockoffset as usize + _cpy_size as usize]);

                        current_buffer_offset += _cpy_size as usize;
                    }
                    else if cur_block_id == last_block_id
                    {
                        file_buffer[current_buffer_offset as usize..]
                        .copy_from_slice(&_decomp_buffer[..(entry.filesize - current_buffer_offset as u32) as usize]);
                    }
                    else
                    {
                        file_buffer[current_buffer_offset as usize..(current_buffer_offset + BLOCK_SIZE as usize) as usize].copy_from_slice(&_decomp_buffer[0..BLOCK_SIZE as usize]);
                        current_buffer_offset += BLOCK_SIZE as usize;
                    }
                    reader.seek(SeekFrom::Start(0)).expect("Error seeking");
                    cur_block_id +=1;
                    _decomp_buffer.clear();
                }
                let mut cus_out = output_path.clone();
                let mut _file_name:String = String::new();
                let mut _ext = "";
                if entry.numtype == 26 && entry.numsubtype == 7
                {
                    _ext = "wem";
                    cus_out += "\\wem";
                    _file_name = hex_str_to_u32(entry.reference.clone()).to_string();
                    if extr_opts.hexid {
                        _file_name = entry.reference.to_uppercase();
                    }
                }
                else if entry.numtype == 26 && entry.numsubtype == 6
                {
                    _ext = "bnk";
                    cus_out.push_str("/bnk"); 
                    _file_name = format!("{}-{:04x}", self.package_id, i);
                }
                else if entry.numtype != 26 && (entry.numsubtype != 6 || entry.numsubtype != 7)
                {
                    _ext = "bin";
                    cus_out.push_str(format!("/unknown/{}/", entry.reference.to_uppercase()).as_str());
                    _file_name = get_hash_from_file(format!("{}-{:04x}", self.package_id, i));
                }          
                fs::create_dir_all(&cus_out).expect("Error creating directory");
                let mut stream = BufWriter::new(File::create(format!("{}/{}.{}", cus_out, _file_name, _ext)).expect("Error creating file"));
                stream.write_all(&file_buffer).expect("Error writing file");
                stream.flush().unwrap();
                file_buffer.clear();
            }
        });
        thread.join().unwrap();
        
        if extr_opts.wavconv {
            let wem_dir = extr_opts.output_path.clone() + "\\wem\\";
            fs::create_dir_all(extr_opts.output_path + "\\wav").expect("Error creating directory");
            let thread = thread::spawn(move || {
                for entry in fs::read_dir(wem_dir).unwrap() {
                let path_bufer = entry.unwrap().path();
                let wem_path = path_bufer.display().to_string().replace('/', "\\");
                let wav_path = wem_path.clone().replace("\\wem\\", "\\wav\\").replace(".wem", ".wav");
                //let vgms_arg:String = format!("res\\vgmstream\\vgmstream-cli.exe -o \"{}\" \"{}\"", wav_path, wem_path);
                //let vgmarg = vgms_arg.as_str();
                //println!("{}", vgmarg);
                let output = Command::new("cmd").arg("/C").arg("res\\vgmstream\\vgmstream-cli.exe").arg("-o").arg(&wav_path).arg(&wem_path).output().expect("Failed to execute vgmstream.");
                if !output.status.success()
                {
                    println!("{}", String::from_utf8_lossy(&output.stderr));
                }
                if output.status.success()
                {
                    println!("{}", String::from_utf8_lossy(&output.stdout));
                    fs::remove_file(wem_path).expect("Failed removing wem file");
                }
            }
            });
            thread.join().unwrap();
        }

    }

    fn decrypt_block(&self, block: &structs::Block, mut block_buffer: Vec<u8>, ctx: &mut CipherCtx) -> Vec<u8>
    {
        let mut decrypt_buffer:Vec<u8> = vec![];
        let alt_key = &block.bitflag & 4 != 0;
        let mut _key = &[0u8; 16];
        if alt_key
        {
            _key = &self.aes_alt_key;
        }
        else
        {
            _key = &self.aes_key;
        };
        let cipher = Cipher::aes_128_gcm();
        ctx.decrypt_init(Some(cipher), Some(_key), Some(&self.nonce)).unwrap();
        ctx.set_tag(&block.gcmtag).unwrap();
        ctx.cipher_update_vec(&block_buffer, &mut decrypt_buffer).unwrap();
        ctx.cipher_final_vec(&mut decrypt_buffer).expect_err("Failed finalizing decrypter");

        block_buffer.clear();

        decrypt_buffer
    }

    #[allow(non_snake_case)]
    fn decompress_block(&self, block: &structs::Block, decrypt_buffer: &mut Vec<u8>, lib: &libloading::Library) -> Vec<u8>
    {
        unsafe {
            let mut decomp_buffer = [0u8; 262144 as usize];
            let OodleLZ_Decompress: libloading::Symbol<extern "C" fn(compressed_bytes: &u8, size_of_compressed_bytes:i64, decompressed_bytes: *mut u8, size_of_decompressed_bytes:i64,
                a:u32, b:u32, c:u32, d:u32, e:u32, f:u32, g:u32, h:u32, i:u32, threadModule:u32) -> i64> = lib.get(b"OodleLZ_Decompress").expect("Failed to load OodleLZ_Decompress function.");
            let _result:i64 = OodleLZ_Decompress(&decrypt_buffer[0], block.size as i64, &mut decomp_buffer[0], 262144 as i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3);
            decrypt_buffer.clear();

            decomp_buffer.to_vec()
        }
    }

    pub fn get_entry_reference(&self, hash:String) -> String
    {
        let id:u32 = hex_str_to_u32(hash) % 8192;
        let mut file = File::open(self.package_path.clone()).expect("Error opening file");
        let mut reader = BufReader::new(&file);
        let mut u32buffer = [0; 4];
        reader.seek(SeekFrom::Start(0x44)).expect("Error seeking file");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entry_table_offset = le_u32(&u32buffer);
        reader.seek(SeekFrom::Start((entry_table_offset+id*16) as u64)).expect("Error seeking file");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entrya = be_u32(&u32buffer);
        file.flush();

        u32_to_hex_str(entrya)
    }

    pub fn get_entry_types(&self, hash:String, mut subtype: u8) -> u8
    {
        let id:u32 = hex_str_to_u32(hash) % 8192;
        let mut file = File::open(self.package_path.clone()).expect("Error opening file");
        let mut reader = BufReader::new(&file);
        let mut u32buffer = [0; 4];
        reader.seek(SeekFrom::Start(0x44)).expect("Error seeking file");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entry_table_offset = le_u32(&u32buffer);
        reader.seek(SeekFrom::Start((entry_table_offset+id*16+4) as u64)).expect("Error seeking file");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entryb = be_u32(&u32buffer);
        file.flush();

        let _type:u8 = ((entryb >> 9) & 0x7F) as u8;
        subtype = ((entryb >> 6) & 0x7) as u8;
        _type
    }

    pub fn get_entry_data(&mut self, hash: String, mut file_size: u32) -> Vec<u8>
    {
        let id:u32 = hex_str_to_u32(hash) % 8192;
        if self.header.pkgid == 0
        {
            let status:bool = self.read_header();
            if !status
            {
                let empty:Vec<u8> = vec![0u8];
                return empty;
            }
        }

        if id >= self.header.entry_table_size {
            return vec![0u8];
        }

        let mut file = File::open(self.package_path.clone()).expect("Error reading file");
        let mut reader = BufReader::new(&file);

        let mut entry: Entry = Entry::new();
        let mut u32buffer = [0; 4];
        reader.seek(SeekFrom::Start((self.header.entry_table_offset+id*16+8) as u64)).expect("Error seeking file");
        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entryc:u32 = le_u32(&u32buffer);
        
        entry.startingblock = entryc & 16383;
        entry.startingblockoffset = ((entryc >> 14) & 16383) << 4;

        reader.read_exact(&mut u32buffer).expect("Error reading file");
        let entryd:u32 = le_u32(&u32buffer);

        entry.filesize = (entryd & 0x03FFFFFF) << 4 | (entryc >> 28) & 0xF;

        file_size = entry.filesize.to_owned();

        let oodle:libloading::Library = unsafe { libloading::Library::new("oo2core_9_win64.dll") }.unwrap();

        let buffer:Vec<u8> = self.get_buffer_from_entry(entry, oodle);
        file.flush();

        buffer
        
    }

    pub fn get_all_files_given_ref(&mut self, reference:String) -> Vec<String>
    {
        let mut hashes = vec![String::new()];

        let status = self.read_header();
        if !status { return vec![String::new()]; }

        self.read_entry_table();

        for i in 0..self.entries.len()
        {
            let entry:Entry = self.entries[i].clone();
            if entry.reference.to_uppercase() == reference.to_uppercase()
            {
                let a:u32 = self.header.pkgid as u32 * 8192;
                let b:u32 = a + i as u32 + 2155872256; //0x80800000
                hashes.push(u32_to_hex_str(b));
            }
        }   

        hashes
    }

    pub fn get_buffer_from_entry(&mut self, entry: structs::Entry, oodle:libloading::Library) -> Vec<u8>
    {
        let mut cipher_ctx = CipherCtx::new().unwrap();
        if entry.filesize == 0 {
            return vec![0u8];
        }
        let block_count:u32 = libm::floorf((entry.startingblockoffset as f32 + entry.filesize as f32 - 1.0) / 262144 as f32) as u32;

        let file = File::open(self.package_path.clone()).expect("Error reading file");
        let mut reader = BufReader::new(file);
        //let a = self.header.block_table_offset+self.header.block_table_size*48;
        for b in (self.header.block_table_offset+entry.startingblock*48..self.header.block_table_offset+entry.startingblock*48+block_count*48).step_by(48)
        {
            let mut block: Block = Block::new();
            let mut u32buffer = [0; 4];
            let mut u16buffer = [0; 2];
            let mut gcmtag_buffer = [0; 16];
            reader.seek(SeekFrom::Start(b.into())).expect("Error seeking");
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            block.offset = le_u32(&u32buffer);
            reader.read_exact(&mut u32buffer).expect("Error reading file");
            block.size = le_u32(&u32buffer);
            
            reader.read_exact(&mut u16buffer).expect("Error reading file");
            block.patchid = le_u16(&u16buffer);
            
            reader.read_exact(&mut u16buffer).expect("Error reading file");
            block.bitflag = le_u16(&u16buffer);

            reader.seek(SeekFrom::Current(0x20)).expect("Error seeking");
            reader.read_exact(&mut gcmtag_buffer).expect("Error reading file");
            block.gcmtag = gcmtag_buffer;
            self.blocks.push(block);
        }
        let mut file_buffer = vec![0u8; entry.filesize as usize];
        let mut current_buffer_offset = 0;
        let mut current_block_id = 0;
        for current_block in &self.blocks
        {
            let mut b:String = self.package_path.to_string();
            b.remove(b.len()-5);
            b.insert(self.package_path.len()-5, char::from_u32(current_block.patchid as u32).unwrap());

            let file = File::open(&self.package_path).expect("Error reading file");
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(current_block.offset as u64)).expect("Error seeking");
            let mut block_buffer:Vec<u8> = vec![0u8; current_block.size as usize];
            let result = reader.read(&mut block_buffer).expect("Error reading file");
            if result != current_block.size as usize
            {
                println!("Error reading file");
            }
            let mut _decrypt_buffer:Vec<u8> = vec![0u8; current_block.size as usize];
            let mut _decomp_buffer:Vec<u8> = vec![0u8; 262144 as usize];
            if current_block.bitflag & 0x2 != 0
            {
                _decrypt_buffer = self.decrypt_block(&current_block, block_buffer, &mut cipher_ctx);
            }
            else
            {
                
                _decrypt_buffer = block_buffer
            }
            if current_block.bitflag & 0x1 != 0
            {
                _decomp_buffer = self.decompress_block(&current_block, &mut _decrypt_buffer, &oodle);
            }
            else
            {
                _decomp_buffer = _decrypt_buffer;
            }
            if current_block_id == 0
            {
                let mut _cpy_size = 0;

                if current_block_id == block_count
                {
                    _cpy_size = entry.filesize;
                }
                else
                {
                    _cpy_size = 262144 - entry.startingblockoffset;
                }
                file_buffer[0.._cpy_size as usize].copy_from_slice(&_decomp_buffer[entry.startingblockoffset as usize..entry.startingblockoffset as usize + _cpy_size as usize]);

                current_buffer_offset += _cpy_size as usize;
            }
            else if current_block_id == block_count
            {
                file_buffer[current_buffer_offset as usize..]
                .copy_from_slice(&_decomp_buffer[..(entry.filesize - current_buffer_offset as u32) as usize]);
            }
            else
            {
                file_buffer[current_buffer_offset as usize..(current_buffer_offset + 262144 as usize) as usize].copy_from_slice(&_decomp_buffer[0..BLOCK_SIZE as usize]);
                current_buffer_offset += 262144 as usize;
            }
            reader.seek(SeekFrom::Start(0)).expect("Error seeking");
            current_block_id +=1;
            _decomp_buffer.clear();
        }
        self.blocks.clear();
        return file_buffer;
    }
}

pub fn get_latest_patch_id_path(packages_path: &str, package_id: &str) -> String
{
    let mut latest_patch_id:u16 = u16::MIN;
    let mut package_name:String = String::new();
    let mut pa:String;
    for entry in std::fs::read_dir(packages_path).unwrap() {
        let entry = entry.unwrap();
        let path:String = entry.path().display().to_string();   
        if path.contains(package_id) {
            let patch_str = &path[path.len()-5..];
            let patch_str = &patch_str[0..1];
            let patch_id:u16 = patch_str.parse::<u16>().unwrap();
            if patch_id > latest_patch_id {
                latest_patch_id = patch_id;
                let path2 = path.replace('\\', "/");
                pa = path2.clone().to_owned();
                package_name = pa.to_string()[0..pa.to_string().len()-6].to_string();
                let pos = package_name.rfind('/');
                let val = package_name.len()-pos.unwrap();
                package_name = package_name[pos.unwrap()..].to_string();
                package_name = package_name[..val].to_string();
            }
        }
    }
    println!("{packages_path}/{package_name}_{latest_patch_id}.pkg");
    
    format!("{}/{}_{}.pkg", packages_path, package_name, &latest_patch_id.to_string())
}