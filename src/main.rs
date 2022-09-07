mod package;
use package::Package;
extern crate getopts;
use getopts::Options;
use std::{env};//, collections::HashSet, io::prelude::*};

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
    opts.optopt("i", "", "Package ID", "ID");
    opts.optopt("o", "", "Output Path", "PATH");
    opts.optflag("n", "nonaudio", "Does NOT skip non-audio related files");
    opts.optflag("h", "hexid", "Exports .WEMs as hexidecimal IDs");
    opts.optflag("w", "wavconv", "Exports wems as wavs, deleting the wems");
    opts.optflag("b", "batchexport", "Exports every package.");
    //opts.optflag("m", "musiconly", "Only exports music.");
    opts.optflag("s", "singlefile", "Only extracts a single file given its hash.");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { println!("{}",f); print_usage(&program, opts); return; }
    };

    if !matches.opt_present("i") && !matches.opt_present("b") && !matches.opt_present("p")
    {
        print_usage(&program, opts);
        return;
    }


    let pkgspath = matches.opt_str("p").unwrap();
    let mut pkgid= String::new();
    if matches.opt_present("i")
    {
        pkgid = matches.opt_str("i").unwrap();
    }
    let mut _output_path_base:String = String::new();
    if matches.opt_present("o") {
        _output_path_base = matches.opt_str("o").unwrap();
    }
    else if matches.opt_present("i")
    {
        _output_path_base = format!("{}/output/{}", env::current_dir().unwrap().display(), pkgid);
    }
    else 
    {
       _output_path_base = format!("{}/output/", env::current_dir().unwrap().display());
    }
    
    let mut extr_opts:package::structs::ExtrOpts = package::structs::ExtrOpts::new();
    extr_opts.output_path = _output_path_base;
    extr_opts.skip_non_audio = true;

    if matches.opt_present("n") {
        extr_opts.skip_non_audio = false;
    }
    if matches.opt_present("h") {
        extr_opts.hexid = true;
    }
    if matches.opt_present("w") {
        extr_opts.wavconv = true
    }

    let mut package = Package::new(pkgspath, pkgid);

    package.read_header();
    package.modify_nonce();
    package.read_entry_table();
    package.read_block_table();
    package.extract_files(extr_opts);
}
