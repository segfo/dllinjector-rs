pub mod Windows{
    use libc::*;
    use std::mem;

    pub struct HANDLE_inst;
    pub struct HMODULE_inst;
    pub type WSTR=Vec<u16>;
    pub type LPWSTR=*const u16;
    pub type LPCSTR=*const u8;
    pub type HANDLE=*const HANDLE_inst;
    pub type HMODULE=*const HMODULE_inst;
    pub type LPVOID=*const c_void;
    pub type UINT=i32;
    pub type DWORD=u32;
    pub type BOOL=i32;
    pub type LPDWORD=*mut DWORD;
    pub type LPSECURITY_ATTRIBUTES=*mut SECURITY_ATTRIBUTES;
    pub type LPTHREAD_START_ROUTINE=fn(lpThreadParameter:LPVOID);
    pub const INFINITE:u32=0xFFFFFFFF;
    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
        nLength:DWORD,
        lpSecurityDescriptor:LPVOID,
        bInheritHandle:BOOL
    }
    pub enum MemoryProtection{
        NOACCESS=0x01,READONLY=0x02,READWRITE=0x04,WRITECOPY=0x08,
        EXECUTE=0x10,EXECUTE_READ=0x20,EXECUTE_READWRITE=0x40,EXECUTE_WRITECOPY=0x80,
        GUARD=0x100,NOCACHE=0x200,WRITECOMBINE=0x400,TARGETS_INVALID=0x40000000
    }
    pub enum VirtualMemory{
        COMMIT=0x00001000,RESERVE=0x00002000,DECOMMIT=0x4000,RELEASE=0x8000,
        RESET=0x00080000,RESET_UNDO=0x1000000,LARGE_PAGES=0x20000000,
        PHYSICAL=0x00400000,TOP_DOWN=0x00100000,
    }
    pub enum AccessRight{
        ALL_ACCESS=0x001F0FFF,PROCESS_CREATE_PROCESS=0x0080,PROCESS_CREATE_THREAD=0x0002,
        PROCESS_DUP_HANDLE=0x0040,PROCESS_QUERY_INFORMATION=0x0400,
        PROCESS_QUERY_LIMITED_INFORMATION=0x1000,PROCESS_SET_QUOTA=0x0100,
        PROCESS_SET_INFORMATION=0x0200,PROCESS_TERMINATE=0x0001,
        PROCESS_VM_OPERATION=0x0008,PROCESS_VM_READ=0x0010,
        PROCESS_VM_WRITE=0x0020,SYNCHRONIZE=0x00100000
    }

    #[link(name = "kernel32")]
    #[allow(non_snake_case)]
    extern "system" {
        pub fn LoadLibraryW(fileName: LPWSTR) -> HMODULE;
        pub fn FreeLibrary(dll:HMODULE);
        pub fn OpenProcess(access:DWORD,inherit:BOOL,pid:DWORD)->HANDLE;
        pub fn VirtualAllocEx(hProcess:HANDLE,start:LPVOID,size:DWORD,allocType:DWORD,protectType:DWORD)->LPVOID;
        pub fn VirtualFreeEx(hProcess:HANDLE,start:LPVOID,size:DWORD,freeType:DWORD)->BOOL;
        pub fn CloseHandle(object:HANDLE);
        pub fn WriteProcessMemory(hProcess:HANDLE,baseAddr:LPVOID,buffer:LPVOID,bytes:DWORD,writed:LPDWORD)->BOOL;
        pub fn GetModuleHandleW(lpModuleName:LPWSTR) -> HMODULE;
        pub fn GetProcAddress(hModules:HMODULE,procName:LPCSTR) -> LPTHREAD_START_ROUTINE;
        pub fn CreateRemoteThread(
            hProcess:HANDLE,secAttr:LPSECURITY_ATTRIBUTES,
            stackSize:DWORD,startAddr:LPTHREAD_START_ROUTINE,
            lpParameter:LPVOID,dwCreationFlags:DWORD,lpThreadId:LPDWORD)->HANDLE;
        pub fn WaitForSingleObject(hHandle:HANDLE,dwMilliseconds:DWORD)->DWORD;
    }

    pub trait WindowsString{
        fn fromWcharPtr(&self,ptr: *const u16) -> String;
        fn toWchars(&self) -> WSTR;
    }
    impl WindowsString for str{
        fn fromWcharPtr(&self,ptr: *const u16) -> String {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            unsafe {
                assert!(!ptr.is_null());
                let len = (0..::std::isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
                let slice = ::std::slice::from_raw_parts(ptr, len);
                OsString::from_wide(slice).to_string_lossy().into_owned()
            }
        }

        fn toWchars(&self) -> WSTR {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            OsStr::new(self).encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>()
        }
    }
    pub trait WSTRING{
        fn sizeofString(&self)->usize;
    }
    impl WSTRING for WSTR{
        fn sizeofString(&self)->usize{
            mem::size_of::<u16>()*self.len()
        }
    }
}
