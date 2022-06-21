//mod utils;
//mod structs;
mod package;
//mod vgmstream;
//use utils::*;
//use structs::*;
use package::*;
//use vgmstream::*;
extern crate getopts;
use getopts::Options;
use std::env;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {}", program);
    print!("{}", opts.usage(&brief));
}

fn main()
{   
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.reqopt("p", "", "Packages Path", "PATH");
    opts.reqopt("i", "", "Package ID", "ID");
    opts.optopt("o", "", "Output Path", "PATH");
    opts.optflag("n", "nonaudio", "Does NOT skip non-audio related files");
    opts.optflag("h", "hexid", "Exports .WEMs as hexidecimal IDs");
    opts.optflag("w", "wavconv", "Exports wems as wavs, deleting the wems");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { println!("{}",f); print_usage(&program, opts); return; }
    };

    let pkgspath = matches.opt_str("p").unwrap();
    let pkgid = matches.opt_str("i").unwrap();
    let mut _output_path_base:String = String::new();
    if matches.opt_present("o") {
        _output_path_base = matches.opt_str("o").unwrap();
    }
    else {
        _output_path_base = format!("{}/output/{}", env::current_dir().unwrap().display(), pkgid);
    }

    let mut skip_non_audio:bool = true;
    let mut hexid:bool = false;
    let mut wavconv:bool = false;

    if matches.opt_present("n") {
        skip_non_audio = false;
    }
    if matches.opt_present("h") {
        hexid = true;
    }
    if matches.opt_present("w") {
        wavconv = true
    }

    let mut extr_opts:package::structs::ExtrOpts = package::structs::ExtrOpts::new();
    extr_opts.skip_non_audio = skip_non_audio;
    extr_opts.hexid = hexid;
    extr_opts.wavconv = wavconv;
    extr_opts.output_path = _output_path_base;

    let mut package = Package::new(pkgspath, pkgid);
    package.read_header();
    package.modify_nonce();
    package.read_entry_table();
    package.read_block_table();
    //let now = Instant::now();
    package.extract_files(extr_opts);
    //println!("Done extracting. Took {}ms", now.elapsed().as_millis());
}
