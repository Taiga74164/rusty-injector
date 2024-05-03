// extern crate winapi;

// use std::fs::File;
// use std::io::{self, Read};
// use std::ptr::null_mut;
// use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, HMODULE, LPVOID, FALSE, TRUE, FARPROC};
// use winapi::shared::basetsd::DWORD64;
// use winapi::shared::ntdef::{HANDLE, LPCSTR};
// use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
// use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
// use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
// use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_GUARD, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, IMAGE_DOS_SIGNATURE, IMAGE_SECTION_HEADER, PRUNTIME_FUNCTION, PROCESS_ALL_ACCESS, RtlAddFunctionTable, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_BASE_RELOCATION};
// use winapi::um::errhandlingapi::GetLastError;
// type FLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HINSTANCE;
// type FGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;
// type FDllEntryPoint = unsafe extern "system" fn(LPVOID, DWORD, LPVOID) -> BOOL;

// #[cfg(target_arch = "x86_64")]
// type FRtylAddFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION, DWORD, DWORD64) -> BOOL;

// #[repr(C)]
// struct ManualMappingData {
//     p_load_library_a: FLoadLibraryA,
//     p_get_proc_address: FGetProcAddress,
//     #[cfg(target_arch = "x86_64")]
//     p_rtl_add_function_table: FRtylAddFunctionTable,
//     p_base: LPVOID,
//     h_module: HINSTANCE,
//     fdw_reason_param: DWORD,
//     reserved_param: LPVOID,
//     seh_support: BOOL,
// }

// unsafe fn shellcode(p_data: *mut ManualMappingData) {
//     if p_data.is_null() {
//         (*p_data).h_module = 0x404040 as HINSTANCE;
//         return;
//     }

//      let data = &mut *p_data;
//      let p_base = data.p_base;

//      let dos_header = &*(p_base as *const IMAGE_DOS_HEADER);
//      let e_lfanew = dos_header.e_lfanew as usize;
//      let p_nt_header = &*(p_base.offset(e_lfanew as isize) as *const IMAGE_NT_HEADERS);
//      let p_opt_header = &p_nt_header.OptionalHeader;

//      let load_library_a: unsafe extern "system" fn(lp_lib_filename: *const i8) -> HINSTANCE = std::mem::transmute(data.p_load_library_a);
//      let get_proc_address: unsafe extern "system" fn(h_module: HINSTANCE, lp_proc_name: *const i8) -> FARPROC = std::mem::transmute(data.p_get_proc_address);
     
//      let location_delta = p_base as isize - p_opt_header.ImageBase as isize;
//      if location_delta != 0 {
//         if p_opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size > 0 {
//             let mut p_reloc_data = p_base.add(p_opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;
//             let p_reloc_end = p_reloc_data.add(p_opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].Size.try_into().unwrap());

//             while p_reloc_data < p_reloc_end {
//                 let reloc_block = &*p_reloc_data;
//                 let entry_count = reloc_block.SizeOfBlock as usize / std::mem::size_of::<u16>();
//                 let p_relative_info = p_reloc_data.add(1) as *const u16;

//                 for i in 0..entry_count {
//                     let p_relative = p_base.add(reloc_block.VirtualAddress as usize + (*p_relative_info.offset(i as isize) & 0xFFF) as usize) as *mut usize;
//                     *p_relative = *p_relative + location_delta as usize;

//                     // >> 0x0C) == IMAGE_REL_BASED_DIR64)
                    
//                 }
//             }
//         }
//     }
// }

// unsafe fn manual_map_dll(h_proc: HANDLE, dll_data: &[u8]) -> bool {
//     let dos_header = dll_data.as_ptr() as *const IMAGE_DOS_HEADER;
//     if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
//         eprintln!("Invalid DOS signature.");
//         return false;
//     }

//     let nt_headers = &*(dll_data.as_ptr().offset((*dos_header).e_lfanew as isize) as *const IMAGE_NT_HEADERS);
//     if nt_headers.Signature != IMAGE_NT_SIGNATURE {
//         eprintln!("Invalid NT signature.");
//         return false;
//     }

//     let optional_header = &nt_headers.OptionalHeader;
//     let image_base = VirtualAllocEx(h_proc, optional_header.SizeOfImage as LPVOID, optional_header.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//     if image_base.is_null() {
//         eprintln!("Failed to allocate memory in remote process.");
//         return false;
//     }

//     let data = ManualMappingData {
//         p_load_library_a: LoadLibraryA,
//         p_get_proc_address: GetProcAddress,
//         #[cfg(target_arch = "x86_64")]
//         p_rtl_add_function_table: unsafe { std::mem::transmute_copy(&RtlAddFunctionTable) }, // Hope this works
//         p_base: image_base,
//         h_module: null_mut(),
//         fdw_reason_param: 1,
//         reserved_param: null_mut(),
//         seh_support: TRUE,
//     };

//     // File header
//     let header_size = optional_header.SizeOfHeaders as usize;
//     if WriteProcessMemory(h_proc, image_base, dll_data.as_ptr() as LPVOID, header_size, null_mut()) == 0 {
//         eprintln!("Failed to write headers to remote process.");
//         VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//         return false;
//     }

//     let section_header = (dll_data.as_ptr() as *const IMAGE_SECTION_HEADER).offset(nt_headers.FileHeader.SizeOfOptionalHeader as isize);
//     for i in 0..nt_headers.FileHeader.NumberOfSections {
//         let section = &*section_header.offset(i as isize);
//         if section.SizeOfRawData == 0 {
//             continue;
//         }

//         let section_base = image_base.offset(section.VirtualAddress as isize);
//         if WriteProcessMemory(h_proc, section_base, dll_data.as_ptr().offset(section.PointerToRawData as isize) as LPVOID, section.SizeOfRawData as usize, null_mut()) == 0 {
//             eprintln!("Failed to write section to remote process.");
//             VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//             return false;
//         }
//     }

//     // Mapping params
//     let mapping_data_alloc = VirtualAllocEx(h_proc, null_mut(), std::mem::size_of::<ManualMappingData>(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//     if mapping_data_alloc.is_null() {
//         eprintln!("Failed to allocate memory for mapping data.");
//         VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//         return false;
//     }

//     if WriteProcessMemory(h_proc, mapping_data_alloc, &data as *const ManualMappingData as LPVOID, std::mem::size_of::<ManualMappingData>(), null_mut()) == 0 {
//         eprintln!("Failed to write mapping data to remote process.");
//         VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//         VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE);
//         return false;
//     }

//     // Shell code
//     let shell_code = VirtualAllocEx(h_proc, null_mut(), 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//     if shell_code.is_null() {
//         eprintln!("Failed to allocate memory for shell code.");
//         VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//         VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE);
//         return false;
//     }

//     if WriteProcessMemory(h_proc, shell_code, shell_code, 0x100, null_mut()) == 0 {
//         eprintln!("Failed to write shell code to remote process.");
//         VirtualFreeEx(h_proc, image_base, 0, MEM_RELEASE);
//         VirtualFreeEx(h_proc, mapping_data_alloc, 0, MEM_RELEASE);
//         VirtualFreeEx(h_proc, shell_code, 0, MEM_RELEASE);
//         return false;
//     }

//     true
// }