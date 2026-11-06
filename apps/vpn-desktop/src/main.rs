//! Desktop UI shell.
//!
//! Phase 0: console placeholder that exercises the IPC types.
//! Phase 2: Slint window, tray icon, profile list, routing preset editor.

use anyhow::Result;
use vpn_ipc::Request;

fn main() -> Result<()> {
    println!("hausond vpn desktop (UI scaffold)");
    println!("IPC request example: {:?}", Request::Status);
    println!("Slint UI lands in phase 2 — see README roadmap.");
    Ok(())
}
