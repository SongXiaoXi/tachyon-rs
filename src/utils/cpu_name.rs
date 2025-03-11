use std::sync::OnceLock;

cfg_if::cfg_if!{
    if #[cfg(target_os = "macos")] {
        pub fn cpu_name() -> &'static str {
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                let mut buffer = Vec::<u8>::with_capacity(128);
                let mut buffer_len = buffer.capacity();
                unsafe {
                    libc::sysctlbyname(b"machdep.cpu.brand_string\0".as_ptr() as *const _, buffer.as_mut_ptr() as *mut _, &mut buffer_len as *mut _ as *mut _, std::ptr::null_mut(), 0);
                    buffer.set_len(buffer_len);
                    if buffer[buffer_len - 1] == 0 {
                        buffer.set_len(buffer_len - 1);
                    }
                }
                String::from_utf8(buffer).unwrap()
            }).as_str()
        }
    } else if #[cfg(target_vendor = "apple")] {
        pub fn cpu_name() -> &'static str {
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                type CFStringRef = *const libc::c_void;
                #[link(name = "CoreFoundation", kind = "framework")]
                extern "C" {
                    fn CFStringCreateWithBytesNoCopy(alloc: *const libc::c_void, bytes: *const u8, len: usize, encoding: u32, isExternalRepresentation: u8, contentsDeallocator: *const libc::c_void) -> CFStringRef;
                    fn CFRelease(cf: *const libc::c_void);
                    fn CFStringGetCStringPtr(cf: CFStringRef, encoding: u32) -> *const libc::c_char;
                    static kCFAllocatorNull: *const libc::c_void;
                }
                #[allow(non_upper_case_globals)]
                const kCFStringEncodingUTF8: u32 = 0x08000100;
                unsafe {
                    let libmg = libc::dlopen("/usr/lib/libMobileGestalt.dylib\0".as_ptr() as _, libc::RTLD_LAZY);
                    if libmg.is_null() {
                        return "iOS Device without MobileGestalt".to_string();
                    }
                    let func = libc::dlsym(libmg, "MGCopyAnswer\0".as_ptr() as _);
                    if func.is_null() {
                        libc::dlclose(libmg);
                        return "Unknown iOS Device without MGCopyAnswer".to_string();
                    }
                    #[allow(non_snake_case)]
                    let MGCopyAnswer = std::mem::transmute::<_, extern "C" fn(CFStringRef) -> CFStringRef>(func);
                    let marketing_name = "marketing-name";
                    let marketing_name_key = CFStringCreateWithBytesNoCopy(std::ptr::null(), marketing_name.as_ptr() as _, marketing_name.len() as _, kCFStringEncodingUTF8, 0, kCFAllocatorNull);
                    let marketing_name = MGCopyAnswer(marketing_name_key);
                    if marketing_name.is_null() {
                        CFRelease(marketing_name_key as _);
                        libc::dlclose(libmg);
                        return "Null iOS marketing name".to_string();
                    }

                    let name = std::ffi::CStr::from_ptr(CFStringGetCStringPtr(marketing_name, kCFStringEncodingUTF8)).to_string_lossy().to_string();

                    CFRelease(marketing_name_key as _);
                    CFRelease(marketing_name as _);
                    libc::dlclose(libmg);

                    name
                }
            }).as_str()
        }
    } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
        pub fn cpu_name() -> &'static str {
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                #[cfg(target_arch = "x86_64")]
                use std::arch::x86_64::__cpuid;
                #[cfg(target_arch = "x86")]
                use std::arch::x86::__cpuid;

                let mut brand_string = [0u8; 48];
                unsafe {
                    for i in 0..3 {
                        let cpuid_result = __cpuid(0x80000002 + i);
                        let i = i as usize;
                        brand_string[i * 16..i * 16 + 4].copy_from_slice(&cpuid_result.eax.to_ne_bytes());
                        brand_string[i * 16 + 4..i * 16 + 8].copy_from_slice(&cpuid_result.ebx.to_ne_bytes());
                        brand_string[i * 16 + 8..i * 16 + 12].copy_from_slice(&cpuid_result.ecx.to_ne_bytes());
                        brand_string[i * 16 + 12..i * 16 + 16].copy_from_slice(&cpuid_result.edx.to_ne_bytes());
                    }
                }
                String::from_utf8_lossy(&brand_string).trim_matches(|c: char| c.is_whitespace() || c=='\0').to_string()
            }).as_str()
        }
    } else if #[cfg(any(target_os = "linux", target_os = "android"))] {
        pub fn cpu_name() -> &'static str {
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                use std::path::Path;
                use std::fs;
                use std::io::BufReader;
                use std::io::BufRead;
                let path = Path::new("/proc/device-tree/model");

                if let Ok(content) = fs::read_to_string(&path) {
                    return content.trim_end_matches('\0').to_string();
                }
                let path = Path::new("/proc/cpuinfo");
                if let Ok(file) = fs::File::open(&path) {
                    for line in BufReader::new(file).lines() {
                        if let Ok(line) = line {
                            if line.starts_with("model name") || line.starts_with("Hardware") {
                                let parts: Vec<&str> = line.split(':').collect();
                                if parts.len() == 2 {
                                    return parts[1].trim_matches(|c: char| c.is_whitespace() || c=='\0').to_string();
                                }
                            }
                        }
                    }
                }
                "Unknown CPU".to_string()
            }).as_str()
        }
    } else {
        pub fn cpu_name() -> &'static str {
            "Unknown CPU"
        }
    }
}