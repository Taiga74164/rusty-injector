extern crate winapi;

mod load_library;
mod util;

use std::ptr::null_mut;

use std::ffi::CString;
use winapi::um::processthreadsapi::CreateProcessA;
use winapi::um::winnt::HANDLE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{PROCESS_INFORMATION, STARTUPINFOA, ResumeThread};
use winapi::um::winbase::CREATE_SUSPENDED;

use util::select_file;
use load_library::load_library_dll;

fn open_process(path: CString, handle_ptr: *mut HANDLE, thread_ptr: *mut HANDLE) -> bool {
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // println!("Opening process: {:?}", path);
    let success = unsafe {
        CreateProcessA(
            path.as_ptr(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };
    if success == 0 {
        println!("Error: {}", unsafe { winapi::um::errhandlingapi::GetLastError() });
        return false;
    }

    unsafe {
        *handle_ptr = pi.hProcess;
        *thread_ptr = pi.hThread;
    }

    true
}

fn main() {
    // println!("Hello, world!");
    let file_option = select_file("Executable Files (*.exe)\0*.exe\0", "Select the game executable");
    println!("Selected file: {:?}", file_option);

    let mut handle: HANDLE = null_mut();
    let mut thread: HANDLE = null_mut();

    if let Some(file) = file_option {
        let file_str = CString::new(file).unwrap();
        println!("file_str: {:?}", file_str);
        let success = open_process(file_str, &mut handle, &mut thread);
        if success {
            println!("Process opened successfully");
        } else {
            println!("Failed to open process");
        }
    }
    
    let dll_option = select_file("DLL Files (*.dll)\0*.dll\0", "Select the DLL to inject");
    println!("Selected DLL: {:?}", dll_option);

    if let Some(dll) = dll_option {
        let dll_str = CString::new(dll).unwrap();
        println!("dll_str: {:?}", dll_str);
        let success = unsafe { load_library_dll(handle, &dll_str) };
        if success {
            println!("DLL injected successfully");
        } else {
            println!("Failed to inject DLL");
        }
    }

    unsafe {
        ResumeThread(thread);
        CloseHandle(handle);
        CloseHandle(thread);
    }
}


