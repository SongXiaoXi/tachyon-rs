use std::sync::OnceLock;

cfg_if::cfg_if!{
    if #[cfg(target_os = "macos")] {
        /// Get the CPU name from sysctlbyname("machdep.cpu.brand_string") on macOS.
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
        /// Get the device marketing name from MobileGestalt on iOS.
        pub fn cpu_name() -> &'static str {
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                type CFStringRef = *const libc::c_void;
                #[link(name = "CoreFoundation", kind = "framework")]
                extern "C" {
                    fn CFStringCreateWithBytesNoCopy(alloc: *const libc::c_void, bytes: *const u8, len: usize, encoding: u32, isExternalRepresentation: u8, contentsDeallocator: *const libc::c_void) -> CFStringRef;
                    fn CFRelease(cf: *const libc::c_void);
                    fn CFStringGetLength(cf: CFStringRef) -> i64;
                    fn CFStringGetCString(cf: CFStringRef, buffer: *mut libc::c_char, buffer_size: libc::c_long, encoding: u32) -> u8;
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

                    let len = CFStringGetLength(marketing_name);
                    let mut c_buf = vec![0i8; (len as usize) * 4 + 1];
                    let ok = CFStringGetCString(marketing_name, c_buf.as_mut_ptr(), c_buf.len() as _, kCFStringEncodingUTF8);
                    let name = if ok != 0 {
                        std::ffi::CStr::from_ptr(c_buf.as_ptr()).to_string_lossy().to_string()
                    } else {
                        "Unknown iOS Device Name".to_string()
                    };

                    CFRelease(marketing_name_key as _);
                    CFRelease(marketing_name as _);
                    libc::dlclose(libmg);

                    name
                }
            }).as_str()
        }
    } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
        /// Get the CPU name from CPUID on x86 and x86_64.
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
    } else if #[cfg(target_os = "linux")] {
        /// Get the CPU name from /proc/cpuinfo or /proc/device-tree/model on Linux.
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
    } else if #[cfg(target_os = "android")] {
        /// Get the CPU name from build.prop on Android.
        pub fn cpu_name() -> &'static str {
            use super::android::system_property_get;
            use std::ffi::CStr;
            static NAME: OnceLock<String> = OnceLock::new();
            NAME.get_or_init(|| {
                if let Some(soc_model) = system_property_get(unsafe { CStr::from_ptr(b"ro.soc.model\0".as_ptr()) }) {
                    return soc_model;
                }
                if let Some(hw_model) = system_property_get(unsafe { CStr::from_ptr(b"ro.product.model\0".as_ptr()) }) {
                    return hw_model;
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