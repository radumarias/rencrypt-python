use std::sync::Once;
use libc::{self, size_t};
use libsodium_sys::{
    sodium_init
    , sodium_mlock
    , sodium_munlock,
};
use zeroize::Zeroize;

/// The global [`sync::Once`] that ensures we only perform
/// library initialization one time.
static INIT: Once = Once::new();

/// A flag that returns whether this library has been safely
/// initialized.
static mut INITIALIZED: bool = false;

pub struct SecretVec<T: Zeroize> {
    secret: Vec<T>,
}

impl<T: Zeroize + Default + Clone> SecretVec<T> {
    pub fn new<F>(len: usize, f: F) -> Self
        where F: FnOnce(&mut [T])
    {
        let v = T::default();
        let mut secret: Vec<T> = vec![v; len];
        unsafe { mlock(secret.as_mut_ptr(), len); }
        f(&mut secret);
        SecretVec {
            secret,
        }
    }
}

impl<T: Zeroize> AsRef<[T]> for SecretVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.secret
    }
}

impl<T: Zeroize> AsMut<[T]> for SecretVec<T> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.secret
    }
}

impl<T: Zeroize> Drop for SecretVec<T> {
    fn drop(&mut self) {
        self.secret.zeroize();
        unsafe { munlock(self.secret.as_mut_ptr(), self.secret.len()); }
    }
}

// impl<T> Debug for SecretVec<T> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "SecretVec<{}>[REDACTED]", std::any::type_name::<T>())
//     }
// }

/// Initialized libsodium. This function *must* be called at least once
/// prior to using any of the other functions in this library, and
/// callers *must* verify that it returns `true`. If it returns `false`,
/// libsodium was unable to be properly set up and this library *must
/// not* be used.
///
/// Calling it multiple times is a no-op.
fn init() -> bool {
    unsafe {
        INIT.call_once(|| {
            // NOTE: Calls to transmute fail to compile if the source
            // and destination type have a different size. We (ab)use
            // this fact to statically assert the size of types at
            // compile-time.
            //
            // We assume that we can freely cast between rust array
            // sizes and [`libc::size_t`]. If that's not true, DO NOT
            // COMPILE.
            #[allow(clippy::useless_transmute)]
                let _ = std::mem::transmute::<usize, size_t>(0);

            let mut failure = false;

            // sodium_init returns 0 on success, -1 on failure, and 1 if
            // the library is already initialized; someone else might
            // have already initialized it before us, so we only care
            // about failure
            failure |= sodium_init() == -1;

            INITIALIZED = !failure;
        });

        INITIALIZED
    }
}

/// Calls the platform's underlying `mlock(2)` implementation.
unsafe fn mlock<T>(ptr: *mut T, len: usize) -> bool {
    if !init() {
        panic!("Failed to initialize libsodium");
    }
    sodium_mlock(ptr.cast(), len) == 0
}

/// Calls the platform's underlying `munlock(2)` implementation.
unsafe fn munlock<T>(ptr: *mut T, len: usize) -> bool {
    if !init() {
        panic!("Failed to initialize libsodium");
    }
    sodium_munlock(ptr.cast(), len) == 0
}
