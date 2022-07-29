#[derive(Clone)]
pub struct Entry {
    pub reference: String,
    pub numtype: u8,
    pub numsubtype: u8,
    pub startingblock: u32,
    pub startingblockoffset: u32,
    pub filesize: u32
}

#[derive(Copy, Clone)]
pub struct Header {
    pub pkgid: u16,
    pub patchid: u16,
    pub entry_table_offset: u32,
    pub entry_table_size: u32,
    pub block_table_offset: u32,
    pub block_table_size: u32,
    pub hash64_table_offset: u32,
    pub hash64_table_size: u32,
}

#[derive(Copy, Clone)]
pub struct Block
{
	pub id: u32,
	pub offset: u32,
    pub size: u32,
    pub patchid: u16,
    pub bitflag: u16,
    pub gcmtag: [u8; 16],
}

pub struct ExtrOpts {
    pub hexid:bool,
    pub skip_non_audio:bool,
    pub wavconv:bool,
    pub music_only:bool,
    pub oodle:libloading::Library,
    pub output_path:String
}

impl Header {
    pub fn new() -> Header {
        Header {
            pkgid: 0,
            patchid: 0,
            entry_table_offset: 0,
            entry_table_size: 0,
            block_table_offset: 0,
            block_table_size: 0,
            hash64_table_offset: 0,
            hash64_table_size: 0,
        }
    }
}
impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

impl Entry {
    pub fn new() -> Entry {
        Entry {
            reference: String::new() ,
            numtype: 0,
            numsubtype: 0,
            startingblock: 0,
            startingblockoffset: 0,
            filesize: 0,
        }
    }
}
impl Default for Entry {
    fn default() -> Self {
        Self::new()
    }
}

impl Block {
    pub fn new() -> Block {
        Block {
            id: 0,
            offset: 0,
            size: 0,
            patchid: 0,
            bitflag: 0,
            gcmtag: [0; 16],
        }
    }
}
impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtrOpts {
    pub fn new() -> ExtrOpts {
        ExtrOpts {
            hexid: false,
            skip_non_audio: true,
            wavconv: false,
            music_only: false,
            oodle: unsafe { libloading::Library::new("oo2core_9_win64.dll") }.unwrap(),
            output_path: String::new(),
        }
    }
}
impl Default for ExtrOpts {
    fn default() -> Self {
        Self::new()
    }
}