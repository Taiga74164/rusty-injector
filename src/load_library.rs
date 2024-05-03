extern crate winapi;

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, HANDLE};
use winapi::um::handleapi::CloseHandle;

pub unsafe fn load_library_dll(h_proc: HANDLE, dll_path: &CString) -> bool {
    let h_kernel = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
    if h_kernel.is_null() {
        return false;
    }

    let load_lib = GetProcAddress(h_kernel, "LoadLibraryA\0".as_ptr() as *const i8);
    if load_lib.is_null() {
        return false;
    }
    
    let alloc_mem = VirtualAllocEx(h_proc, null_mut(), dll_path.as_bytes_with_nul().len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if alloc_mem.is_null() {
        return false;
    }

    let write_mem = WriteProcessMemory(h_proc, alloc_mem, dll_path.as_ptr() as *const _, dll_path.as_bytes_with_nul().len(), null_mut());
    if write_mem == 0 {
        return false;
    }

    let h_thread = CreateRemoteThread(h_proc, null_mut(), 0, Some(std::mem::transmute(load_lib)), alloc_mem, 0, null_mut());
    if h_thread.is_null() {
        return false;
    }

    CloseHandle(h_proc);

    true
}