use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

unsafe extern "C" fn property_callback(payload: *mut String, _name: *const c_char, value: *const c_char, _serial: u32) {
    let cvalue = CStr::from_ptr(value);
    (*payload) = cvalue.to_str().unwrap().to_string();
}

type Callback = unsafe extern "C" fn(*mut String, *const c_char, *const c_char, u32);

type SystemPropertyGetFn = unsafe extern "C" fn(*const c_char, *mut c_char) -> c_int;
type SystemPropertyFindFn = unsafe extern "C" fn(*const c_char) -> *const c_void;
type SystemPropertyReadCallbackFn = unsafe extern "C" fn(*const c_void, Callback, *mut String) -> *const c_void;

static ONCE: std::sync::OnceLock<(Option<SystemPropertyGetFn>, Option<SystemPropertyFindFn>, Option<SystemPropertyReadCallbackFn>)> = std::sync::OnceLock::new();
/// This function retrieves the value of a system property by its name.
/// It uses the Android NDK's system property API to access the properties.
pub fn system_property_get(name: &CStr) -> Option<String> {
    let (get_fn, find_fn, read_callback_fn) = ONCE.get_or_init(|| {
        let lib = unsafe { libc::dlopen("libc.so\0".as_ptr() as _, libc::RTLD_LAZY) };
        if lib.is_null() {
            return (None, None, None);
        }
        let get = unsafe { libc::dlsym(lib, "__system_property_get\0".as_ptr() as _) };
        let find = unsafe { libc::dlsym(lib, "__system_property_find\0".as_ptr() as _) };
        let read_callback = unsafe { libc::dlsym(lib, "__system_property_read_callback\0".as_ptr() as _) };
        unsafe {
            (
                std::mem::transmute::<_, Option<SystemPropertyGetFn>>(get),
                std::mem::transmute::<_, Option<SystemPropertyFindFn>>(find),
                std::mem::transmute::<_, Option<SystemPropertyReadCallbackFn>>(read_callback),
            )
        }
    });

    if let (Some(find_fn), Some(read_callback_fn)) = (find_fn, read_callback_fn) {
        let prop = unsafe { find_fn(name.as_ptr()) };
        if prop.is_null() {
            return None;
        }
        let mut value = String::new();
        unsafe {
            read_callback_fn(prop, property_callback, &mut value as *mut _);
        }
        return Some(value);
    }

    if let Some(get_fn) = get_fn {
        // PROPERTY_VALUE_MAX = 92 in Android's libc/include/sys/system_properties.h
        let mut buffer = [0u8; 92 + 1];
        let len = unsafe { get_fn(name.as_ptr(), buffer.as_mut_ptr() as *mut c_char) };
        if len > 0 {
            buffer[92] = 0;
            let cstr = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
            cstr.to_str().map(|s| s.to_string()).ok()
        } else {
            None
        }
    } else {
        None
    }

}
    
