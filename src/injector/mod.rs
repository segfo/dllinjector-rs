pub mod windows;
use self::windows::*;
use libc::*;
use std::fs;

pub fn dll_attach(dll_path: String, pid: u32) -> Result<ProcessInfo, Box<std::error::Error>> {
    if !fs::metadata(dll_path.clone()).is_ok() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("file not found : {}",dll_path)
        )));
    }
    unsafe {
        let h_proc = OpenProcess(AccessRight::ALL_ACCESS as DWORD, 0, pid);
        // Wcharの長さを指定しないといけないが、len()だと配列そのものの長さになるので、sizeofStringを実装。
        let vmem = VirtualAllocEx(
            h_proc,
            std::ptr::null(),
            dll_path.toWchars().sizeofString() as u32,
            VirtualMemory::COMMIT as u32,
            MemoryProtection::READWRITE as u32,
        );
        let status = WriteProcessMemory(
            h_proc,
            vmem,
            dll_path.toWchars().as_ptr() as *const c_void,
            dll_path.toWchars().sizeofString() as u32,
            std::ptr::null_mut(),
        );
        if status == 0 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("write process memory failed\npid : {}", pid)
            )));
        }
        // CreateRemoteThread で LoadLibrary
        let kernel32 = LoadLibraryW("kernel32.dll\0".toWchars().as_ptr());
        let loadlibraryw = GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr());
        let mut tid: u32 = 0;
        let h_thread = CreateRemoteThread(
            h_proc,
            std::ptr::null_mut(),
            0,
            loadlibraryw,
            vmem,
            0,
            &mut tid,
        );
        println!("success!");
        FreeLibrary(kernel32);
        Ok(ProcessInfo::new(h_thread, h_proc, vmem))
    }
}

pub struct ProcessInfo {
    h_thread: HANDLE,
    h_proc: LPVOID,
    vmem: LPVOID,
}

impl ProcessInfo {
    fn new(h_thread: HANDLE, h_proc: LPVOID, vmem: LPVOID) -> Self {
        ProcessInfo {
            h_thread: h_thread,
            h_proc: h_proc,
            vmem: vmem,
        }
    }
}

// アタッチしたDLLが終了するのを待ってデタッチする
pub fn dll_detach_wait(process: ProcessInfo) -> Result<(), Box<std::error::Error>> {
    unsafe {
        if process.h_thread != std::ptr::null() {
            WaitForSingleObject(process.h_thread, INFINITE);
        }
        dll_detach(process);
    }
    return Ok(());
}

fn dll_detach(process: ProcessInfo)->Result<(), Box<std::error::Error>>{
    unsafe{
        if VirtualFreeEx(
        process.h_proc,
        process.vmem,
        0,
        VirtualMemory::RELEASE as u32,
    ) == 0
        {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::ConnectionAborted,"")));
        }
        CloseHandle(process.h_proc);
    }
    return Ok(())
}
