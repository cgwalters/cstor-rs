//! tar-diff: Compare two tar archives entry-by-entry
//!
//! This tool helps debug tar-split reassembly by comparing
//! the reconstructed tar with the original. It reports:
//! - Missing entries (in one archive but not the other)
//! - Metadata differences (size, mode, mtime, uid, gid)
//! - Content differences (SHA256 hash comparison)

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use tar::{Archive, EntryType};

/// Parsed tar entry with metadata and optional content hash.
#[derive(Debug)]
struct TarEntry {
    path: String,
    size: u64,
    mode: u32,
    mtime: u64,
    uid: u64,
    gid: u64,
    entry_type: u8,
    /// SHA256 hash of file content (only for regular files with size > 0).
    content_hash: Option<String>,
}

/// Read all entries from a tar archive, computing content hashes for regular files.
fn read_tar_entries(path: &PathBuf) -> Result<Vec<TarEntry>> {
    let file = File::open(path)?;
    let mut archive = Archive::new(file);
    let mut entries = Vec::new();

    for (i, entry_result) in archive.entries()?.enumerate() {
        let mut entry = entry_result.context(format!("Failed to read entry {}", i))?;

        let header = entry.header();
        let path = entry.path()?.to_string_lossy().to_string();
        let size = header.size()?;
        let mode = header.mode()?;
        let mtime = header.mtime()?;
        let uid = header.uid()?;
        let gid = header.gid()?;
        let entry_type = header.entry_type().as_byte();

        // Compute hash of content for regular files
        let content_hash = if entry_type == EntryType::Regular.as_byte() && size > 0 {
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 8192];
            loop {
                let n = entry.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
            }
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        entries.push(TarEntry {
            path,
            size,
            mode,
            mtime,
            uid,
            gid,
            entry_type,
            content_hash,
        });
    }

    Ok(entries)
}

/// Convert a tar entry type byte to a human-readable string.
fn entry_type_str(t: u8) -> &'static str {
    match t {
        b'0' | 0 => "file",
        b'1' => "hardlink",
        b'2' => "symlink",
        b'3' => "chardev",
        b'4' => "blockdev",
        b'5' => "directory",
        b'6' => "fifo",
        _ => "unknown",
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <tar1> <tar2>", args[0]);
        eprintln!("\nCompare two tar archives entry-by-entry.");
        std::process::exit(1);
    }

    let tar1_path = PathBuf::from(&args[1]);
    let tar2_path = PathBuf::from(&args[2]);

    println!("Reading {}...", tar1_path.display());
    let entries1 = read_tar_entries(&tar1_path)?;
    println!("  {} entries", entries1.len());

    println!("Reading {}...", tar2_path.display());
    let entries2 = read_tar_entries(&tar2_path)?;
    println!("  {} entries", entries2.len());

    // Build maps by path for quick lookup
    let map1: HashMap<_, _> = entries1.iter().map(|e| (e.path.clone(), e)).collect();
    let map2: HashMap<_, _> = entries2.iter().map(|e| (e.path.clone(), e)).collect();

    println!("\n=== Comparison ===\n");

    // Check for entries only in tar1
    let only_in_1: Vec<_> = entries1
        .iter()
        .filter(|e| !map2.contains_key(&e.path))
        .collect();
    if !only_in_1.is_empty() {
        println!(
            "Entries only in {} ({} entries):",
            tar1_path.display(),
            only_in_1.len()
        );
        for entry in only_in_1.iter().take(10) {
            println!(
                "  - {} ({}, {} bytes)",
                entry.path,
                entry_type_str(entry.entry_type),
                entry.size
            );
        }
        if only_in_1.len() > 10 {
            println!("  ... and {} more", only_in_1.len() - 10);
        }
        println!();
    }

    // Check for entries only in tar2
    let only_in_2: Vec<_> = entries2
        .iter()
        .filter(|e| !map1.contains_key(&e.path))
        .collect();
    if !only_in_2.is_empty() {
        println!(
            "Entries only in {} ({} entries):",
            tar2_path.display(),
            only_in_2.len()
        );
        for entry in only_in_2.iter().take(10) {
            println!(
                "  + {} ({}, {} bytes)",
                entry.path,
                entry_type_str(entry.entry_type),
                entry.size
            );
        }
        if only_in_2.len() > 10 {
            println!("  ... and {} more", only_in_2.len() - 10);
        }
        println!();
    }

    // Compare entries that exist in both
    let mut differences = Vec::new();
    for e1 in &entries1 {
        if let Some(e2) = map2.get(&e1.path) {
            let mut diffs = Vec::new();

            if e1.entry_type != e2.entry_type {
                diffs.push(format!(
                    "type: {} vs {}",
                    entry_type_str(e1.entry_type),
                    entry_type_str(e2.entry_type)
                ));
            }
            if e1.size != e2.size {
                diffs.push(format!("size: {} vs {}", e1.size, e2.size));
            }
            if e1.mode != e2.mode {
                diffs.push(format!("mode: {:o} vs {:o}", e1.mode, e2.mode));
            }
            if e1.mtime != e2.mtime {
                diffs.push(format!("mtime: {} vs {}", e1.mtime, e2.mtime));
            }
            if e1.uid != e2.uid {
                diffs.push(format!("uid: {} vs {}", e1.uid, e2.uid));
            }
            if e1.gid != e2.gid {
                diffs.push(format!("gid: {} vs {}", e1.gid, e2.gid));
            }
            if e1.content_hash != e2.content_hash {
                diffs.push(format!(
                    "content: {} vs {}",
                    e1.content_hash.as_deref().unwrap_or("none"),
                    e2.content_hash.as_deref().unwrap_or("none")
                ));
            }

            if !diffs.is_empty() {
                differences.push((e1.path.clone(), diffs));
            }
        }
    }

    if !differences.is_empty() {
        println!("Entries with differences ({} entries):", differences.len());
        for (path, diffs) in differences.iter().take(20) {
            println!("  {}:", path);
            for diff in diffs {
                println!("    {}", diff);
            }
        }
        if differences.len() > 20 {
            println!(
                "  ... and {} more entries with differences",
                differences.len() - 20
            );
        }
        println!();
    }

    // Summary
    if only_in_1.is_empty() && only_in_2.is_empty() && differences.is_empty() {
        println!("Tar archives are identical.");
    } else {
        println!("Summary:");
        println!("  Only in tar1: {} entries", only_in_1.len());
        println!("  Only in tar2: {} entries", only_in_2.len());
        println!("  Different:    {} entries", differences.len());
        println!(
            "  Identical:    {} entries",
            entries1.len() - only_in_1.len() - differences.len()
        );
    }

    Ok(())
}
