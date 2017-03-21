use syscall::nr::CLONE;
use nix::libc::{c_long, syscall};
//use syscall::{syscall2};

#[cfg(any(target_arch="s390", target_arch="cris"))]
pub fn raw_clone(flags: c_long) -> c_long {
    /* On s390 and cris the order of the first and second arguments
     * of the raw clone() system call is reversed. */
    unsafe { syscall(CLONE as c_long, 0, flags) }
}

#[cfg(not(any(target_arch="s390", target_arch="cris")))]
pub fn raw_clone(flags: c_long) -> c_long {
    unsafe { syscall(CLONE as c_long, flags, 0) }
}
