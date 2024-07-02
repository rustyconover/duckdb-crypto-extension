use std::alloc::Layout;
use std::ffi::{c_char, c_uchar, c_void, CString};
use std::ptr;
use std::slice;
use std::str;
use std::sync::Once;

use digest::{DynDigest, Mac};

use hmac::SimpleHmac;

macro_rules! make_str {
    ( $s : expr , $len : expr ) => {
        unsafe { str::from_utf8_unchecked(slice::from_raw_parts($s as *const u8, $len)) }
    };
}

// Dynamic hash function
fn use_hasher(hasher: &mut dyn DynDigest, data: &[u8]) -> Box<[u8]> {
    hasher.update(data);
    hasher.finalize_reset()
}

// You can use something like this when parsing user input, CLI arguments, etc.
// DynDigest needs to be boxed here, since function return should be sized.
fn select_hasher(s: &str) -> Option<Box<dyn DynDigest>> {
    match s {
        "blake2b-512" => Some(Box::<blake2::Blake2b512>::default()),
        "keccak224" => Some(Box::<sha3::Keccak224>::default()),
        "keccak256" => Some(Box::<sha3::Keccak256>::default()),
        "keccak384" => Some(Box::<sha3::Keccak384>::default()),
        "keccak512" => Some(Box::<sha3::Keccak512>::default()),
        "md4" => Some(Box::<md4::Md4>::default()),
        "md5" => Some(Box::<md5::Md5>::default()),
        "sha1" => Some(Box::<sha1::Sha1>::default()),
        "sha2-224" => Some(Box::<sha2::Sha224>::default()),
        "sha2-256" => Some(Box::<sha2::Sha256>::default()),
        "sha2-384" => Some(Box::<sha2::Sha384>::default()),
        "sha2-512" => Some(Box::<sha2::Sha512>::default()),
        "sha3-224" => Some(Box::<sha3::Sha3_224>::default()),
        "sha3-256" => Some(Box::<sha3::Sha3_256>::default()),
        "sha3-384" => Some(Box::<sha3::Sha3_384>::default()),
        "sha3-512" => Some(Box::<sha3::Sha3_512>::default()),
        _ => None,
    }
}

fn available_hash_algorithms() -> Vec<&'static str> {
    vec![
        "blake2b-512",
        "keccak224",
        "keccak256",
        "keccak384",
        "keccak512",
        "md4",
        "md5",
        "sha1",
        "sha2-224",
        "sha2-256",
        "sha2-384",
        "sha2-512",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
    ]
}

#[repr(C)]
pub enum ResultCString {
    Ok(*mut c_char),
    Err(*mut c_char),
}

#[no_mangle]
/// Hash a varchar using the specified hashing algorithm.
pub extern "C" fn hashing_varchar(
    hash_name: *const c_char,
    hash_name_len: usize,

    content: *const c_char,
    len: usize,
) -> ResultCString {
    if hash_name.is_null() || content.is_null() {
        return ResultCString::Ok(ptr::null_mut());
    }

    let hash_name_str = make_str!(hash_name, hash_name_len);
    let content_slice = unsafe { slice::from_raw_parts(content as *const c_uchar, len) };

    match select_hasher(hash_name_str) {
        Some(mut hasher) => {
            let hash_result = use_hasher(&mut *hasher, content_slice);

            // Now hex encode the byte string.
            let hex_encoded = base16ct::lower::encode_string(&hash_result);

            ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
        }
        None => {
            let error_message = format!(
                "Invalid hash algorithm '{}' available algorithms are: {}",
                hash_name_str,
                available_hash_algorithms().join(", ")
            );
            ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
        }
    }
}

macro_rules! make_hmac {
    ($hash_function : ty, $key: expr, $content: expr) => {
        match SimpleHmac::<$hash_function>::new_from_slice($key).and_then(|mut hmac| {
            hmac.update($content);
            Ok(Box::new(hmac.finalize()))
        }) {
            Ok(final_result) => {
                let hex_encoded =
                    base16ct::lower::encode_string(final_result.into_bytes().as_slice());
                ResultCString::Ok(create_cstring_with_custom_allocator(&hex_encoded).into_raw())
            }
            Err(_) => {
                let error_message = "Failed to create HMAC";
                ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
            }
        }
    };
}

#[no_mangle]
/// Create a HMAC using the specified hash function and key.
pub extern "C" fn hmac_varchar(
    hash_name: *const c_char,
    hash_name_len: usize,

    key: *const c_char,
    key_len: usize,

    content: *const c_char,
    len: usize,
) -> ResultCString {
    if hash_name.is_null() || content.is_null() {
        return ResultCString::Ok(ptr::null_mut());
    }

    let hash_name_str = make_str!(hash_name, hash_name_len);
    let key_slice = unsafe { slice::from_raw_parts(key as *const c_uchar, key_len) };
    let content_slice = unsafe { slice::from_raw_parts(content as *const c_uchar, len) };

    match hash_name_str {
        "blake2b-512" => {
            make_hmac!(blake2::Blake2b512, key_slice, content_slice)
        }
        "keccak224" => {
            make_hmac!(sha3::Keccak224, key_slice, content_slice)
        }
        "keccak256" => {
            make_hmac!(sha3::Keccak256, key_slice, content_slice)
        }
        "keccak384" => {
            make_hmac!(sha3::Keccak384, key_slice, content_slice)
        }
        "keccak512" => {
            make_hmac!(sha3::Keccak512, key_slice, content_slice)
        }
        "md4" => {
            make_hmac!(md4::Md4, key_slice, content_slice)
        }
        "md5" => {
            make_hmac!(md5::Md5, key_slice, content_slice)
        }
        "sha1" => {
            make_hmac!(sha1::Sha1, key_slice, content_slice)
        }
        "sha2-224" => {
            make_hmac!(sha2::Sha224, key_slice, content_slice)
        }
        "sha2-256" => {
            make_hmac!(sha2::Sha256, key_slice, content_slice)
        }
        "sha2-384" => {
            make_hmac!(sha2::Sha384, key_slice, content_slice)
        }
        "sha2-512" => {
            make_hmac!(sha2::Sha512, key_slice, content_slice)
        }
        "sha3-224" => {
            make_hmac!(sha3::Sha3_224, key_slice, content_slice)
        }
        "sha3-256" => {
            make_hmac!(sha3::Sha3_256, key_slice, content_slice)
        }
        "sha3-384" => {
            make_hmac!(sha3::Sha3_384, key_slice, content_slice)
        }
        "sha3-512" => {
            make_hmac!(sha3::Sha3_512, key_slice, content_slice)
        }
        _ => {
            let error_message = format!(
                "Invalid hash algorithm '{}' available algorithms are: {}",
                hash_name_str,
                available_hash_algorithms().join(", ")
            );
            ResultCString::Err(create_cstring_with_custom_allocator(&error_message).into_raw())
        }
    }
}

fn create_cstring_with_custom_allocator(s: &str) -> CString {
    // Convert the input string to a CString
    let c_string = CString::new(s).expect("CString::new failed");

    // Duplicate the CString using the global allocator
    let len = c_string.as_bytes_with_nul().len();
    let layout = Layout::from_size_align(len, 1).unwrap();

    unsafe {
        let ptr = ALLOCATOR.malloc.unwrap()(layout.size()) as *mut c_char;
        if ptr.is_null() {
            panic!("Failed to allocate memory from duckdb");
        }
        ptr::copy_nonoverlapping(c_string.as_ptr(), ptr, len);
        CString::from_raw(ptr)
    }
}

#[cfg(test)]
mod tests {}

type DuckDBMallocFunctionType = unsafe extern "C" fn(usize) -> *mut ::std::os::raw::c_void;
type DuckDBFreeFunctionType = unsafe extern "C" fn(*mut c_void);

struct Allocator {
    malloc: Option<DuckDBMallocFunctionType>,
    free: Option<DuckDBFreeFunctionType>,
}

// Create a global instance of the Allocator struct.
static mut ALLOCATOR: Allocator = Allocator {
    malloc: None,
    free: None,
};

// A Once instance to ensure that the allocator is only initialized once.
static INIT: Once = Once::new();

#[no_mangle]
pub extern "C" fn init_memory_allocation(
    malloc_fn: DuckDBMallocFunctionType,
    free_fn: DuckDBFreeFunctionType,
) {
    unsafe {
        INIT.call_once(|| {
            ALLOCATOR.malloc = Some(malloc_fn);
            ALLOCATOR.free = Some(free_fn);
        });
    }
}
