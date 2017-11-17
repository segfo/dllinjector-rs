extern crate libc;
#[macro_use]
extern crate clap;

use libc::*;
use std::ffi::{CString};
mod segfo;
use segfo::windows::Windows::*;
use std::env;
use std::io;
use clap::{App, Arg, SubCommand};

struct AppOptions{
    pid:u32,
    dllPath:String
}

fn opt_parser_init()->AppOptions{
    let app = app_from_crate!()
        .arg(Arg::with_name("process_id")
            .help("DLL Injection target process id")
            .short("p").long("pid")
            .takes_value(true)
            .required(true)
        ).arg(Arg::with_name("dll_file_path")
            .help("Injection DLL path")
            .short("f").long("file")
            .takes_value(true)
            .required(true)
        ).get_matches();

    AppOptions{
        pid:app.value_of("process_id").unwrap().parse::<u32>().unwrap_or_default(),
        dllPath:app.value_of("dll_file_path").unwrap().to_owned()
    }
}

fn init_app()->AppOptions{
    opt_parser_init()
}

fn main() {
    let AppOptions{pid,dllPath} = init_app();

    unsafe{
        let hProc=OpenProcess(AccessRight::ALL_ACCESS as DWORD,0,pid);
        // Wcharの長さを指定しないといけないが、len()だと配列そのものの長さになるので、sizeofStringを実装。
        let vmem = VirtualAllocEx(hProc,std::ptr::null(), dllPath.toWchars().sizeofString() as u32 ,VirtualMemory::COMMIT as u32,MemoryProtection::READWRITE as u32);
        let status = WriteProcessMemory(hProc,vmem,dllPath.toWchars().as_ptr() as *const c_void,dllPath.toWchars().sizeofString() as u32,std::ptr::null_mut());
        if  status == 0{
            println!("write process memory failed.");
            return;
        }
        // CreateRemoteThread で LoadLibrary
        let kernel32 = LoadLibraryW("kernel32.dll\0".toWchars().as_ptr());
        let loadlibraryw = GetProcAddress(kernel32,b"LoadLibraryW\0".as_ptr());
        let mut tid:u32 = 0;
        let hThread = CreateRemoteThread(hProc,std::ptr::null_mut(),0,loadlibraryw,vmem,0,&mut tid);
        if VirtualFreeEx(hProc,vmem,0,VirtualMemory::RELEASE as u32) == 0{
            println!("free Error");
            return;
        }
        if hThread != std::ptr::null(){
            WaitForSingleObject(hThread,INFINITE);
        }
        FreeLibrary(kernel32);
        CloseHandle(hProc);
    }
}
