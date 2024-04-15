# Rust Shellcode Wrapper

Attempts to dodge AV by MD5 summing each byte of the shellcode, and then sleeping for 15-minutes to prevent heuristics checks. Credit to [numonce](https://github.com/numonce) for helping me with this.

# Building

Prior to building, run `rustup target install x86_64-pc-windows-gnu`

As long as you can create or output a *stageless* payload, and the shellcode is in the format of "\xDE\xAD\xBE\xEF", then this wrapper will work.
This includes the payloads from CobaltStrike and msfvenom, just set the output format to 'C' and place the shellcode in `src/shellcode.c`

Then, run `cargo build --target=x86_64-pc-windows-gnu --release`. In the output directory, there will be a `runner.exe` and a `service.exe`

# Usage

The `runner.exe` can be directly invoked to run the specified shellcode.

Alternatively, you can create a service pointing to the `service.exe` for persistence/privilege escalation.
