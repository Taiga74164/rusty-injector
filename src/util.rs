extern crate winapi;

// https://doc.rust-lang.org/std/os/windows/ffi/trait.OsStrExt.html
// https://friendlyuser.github.io/posts/tech/rust/Interacting_with_Windows_File_System_using_WinAPI_in_Rust/
use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::commdlg::{GetOpenFileNameW, OPENFILENAMEW};
use winapi::um::commdlg::{OFN_PATHMUSTEXIST, OFN_FILEMUSTEXIST};

pub fn select_file(filestr: &str, title: &str) -> Option<String> {
    let mut curr_path: [u16; 260] = [0; 260];
    unsafe {
        winapi::um::processenv::GetCurrentDirectoryW(curr_path.len() as u32, curr_path.as_mut_ptr());
    }

    let filter_str: Vec<u16> = OsString::from(filestr).encode_wide().chain(Some(0).into_iter()).collect();
    let title_str: Vec<u16> = OsString::from(title).encode_wide().chain(Some(0).into_iter()).collect();

    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    let mut sz_file: [u16; 260] = [0; 260];
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = null_mut();
    ofn.lpstrFile = sz_file.as_mut_ptr();
    ofn.nMaxFile = sz_file.len() as u32;
    ofn.lpstrFilter = filter_str.as_ptr();
    ofn.lpstrTitle = title_str.as_ptr();
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = null_mut();
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = curr_path.as_ptr();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    let result = unsafe { 
        if (GetOpenFileNameW(&mut ofn) == 1) {
            let len = sz_file.iter().take_while(|&&c| c != 0).count();
            let path = std::slice::from_raw_parts(sz_file.as_ptr(), len);
            let path_string = String::from_utf16_lossy(path);
            Some(path_string)

        } else {
            None
        }
    };

    unsafe {
        winapi::um::processenv::SetCurrentDirectoryW(curr_path.as_ptr());
    }

    result
}