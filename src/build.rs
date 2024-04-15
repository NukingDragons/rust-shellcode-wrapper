use hex::FromHex;
use regex::Regex;
use std::error::Error;
use std::fs::{read_to_string, File};
use std::io::prelude::*;

fn main() -> Result<(), Box<dyn Error>>
{
	let contents = read_to_string("src/shellcode.c")?;

	let re = Regex::new(r"\\x[A-Fa-f0-9]{2}")?;
	let badchars = ['\\', 'x'];
	let hexstring: Vec<String> =
		re.find_iter(&contents).map(|m| m.as_str().chars().filter(|x| !badchars.contains(x)).collect()).collect();
	let bytes = <Vec<u8>>::from_hex(hexstring.join(""))?;

	let mut file = File::create("src/shellcode.rs")?;
	file.write_all(b"pub fn get_shellcode() -> Vec<&'static str>\n{\n\tvec![\n")?;

	for byte in bytes
	{
		let hash = md5::compute([byte]);

		file.write_all(&format!("\t\t\"{:x}\",\n", hash).into_bytes())?;
	}

	file.write_all(b"\t]\n}\n")?;

	Ok(())
}
