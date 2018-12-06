extern crate libc;
#[macro_use]
extern crate clap;

use libc::*;
use std::ffi::CString;
mod injector;
use clap::{App, Arg, SubCommand};
use std::env;
use std::io;

struct AppOptions {
    pid: u32,
    dll_path: String,
}

fn opt_parser_init() -> AppOptions {
    let app = app_from_crate!()
        .arg(
            Arg::with_name("process_id")
                .help("DLL Injection target process id")
                .short("p")
                .long("pid")
                .takes_value(true)
                .required(true),
        ).arg(
            Arg::with_name("dll_file_path")
                .help("Injection DLL path")
                .short("f")
                .long("file")
                .takes_value(true)
                .required(true),
        ).get_matches();

    AppOptions {
        pid: app
            .value_of("process_id")
            .unwrap()
            .parse::<u32>()
            .unwrap_or_default(),
        dll_path: app.value_of("dll_file_path").unwrap().to_owned(),
    }
}

fn init_app() -> AppOptions {
    opt_parser_init()
}

fn main() {
    let AppOptions { pid, dll_path } = init_app();
    let _r = injector::dll_attach(dll_path, pid)
        .map_err(|e| eprintln!("{}", e))
        .map(|_s|{
            println!("dll injection success!");
        });
}
