#![no_std]

#[no_mangle]
pub static mut pid_to_hide_len: u32 = 0;


#[no_mangle]
pub static mut target_pid: u64 = 0;

#[no_mangle]
pub static mut pid_to_hide: [u8; MAX_FILE_LEN] = [0; MAX_FILE_LEN];

pub const MAX_FILE_LEN: usize = 10;