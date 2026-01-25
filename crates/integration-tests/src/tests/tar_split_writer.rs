//! Integration tests for TarSplitWriter.

use std::io::{Cursor, Read};
use std::path::PathBuf;

use crate::integration_test;
use cstor_rs::{TarSplitWriter, TocEntry, TocEntryType};

integration_test!(test_tar_split_writer_empty, || {
    let writer = TarSplitWriter::new();
    let output = writer.finish()?;

    // Should produce valid gzip output
    let mut decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    // Should contain the tar footer (two 512-byte zero blocks)
    assert!(!decompressed.is_empty());

    // Parse as NDJSON
    for line in decompressed.lines() {
        let parsed: serde_json::Value = serde_json::from_str(line)?;
        // Should be type 2 (segment) entries for footer
        assert!(parsed.get("type").is_some());
    }

    Ok(())
});

integration_test!(test_tar_split_writer_directory, || {
    let mut writer = TarSplitWriter::new();

    let entry = TocEntry {
        name: PathBuf::from("mydir"),
        entry_type: TocEntryType::Dir,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: None,
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };

    writer.add_toc_entry(&entry, None::<std::fs::File>)?;
    let output = writer.finish()?;

    // Decompress and verify
    let mut decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    // Should have at least one type 2 entry (tar header)
    let lines: Vec<&str> = decompressed.lines().collect();
    assert!(!lines.is_empty());

    // First entry should be the directory header
    let first: serde_json::Value = serde_json::from_str(lines[0])?;
    assert_eq!(first["type"], 2); // Segment type

    Ok(())
});

integration_test!(test_tar_split_writer_file_with_content, || {
    let mut writer = TarSplitWriter::new();

    let content = b"Hello, tar-split!";

    let entry = TocEntry {
        name: PathBuf::from("hello.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        size: Some(content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: Some("testuser".to_string()),
        group_name: Some("testgroup".to_string()),
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };

    // Add entry with content for CRC calculation
    let cursor = Cursor::new(content.to_vec());
    writer.add_toc_entry(&entry, Some(cursor))?;
    let output = writer.finish()?;

    // Decompress
    let mut decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    // Should have entries for: header (type 2), file reference (type 1), padding (type 2), footer (type 2)
    let mut found_file_entry = false;
    for line in decompressed.lines() {
        let parsed: serde_json::Value = serde_json::from_str(line)?;
        if parsed["type"] == 1 {
            // File entry
            found_file_entry = true;
            assert_eq!(parsed["name"], "./hello.txt");
            assert_eq!(parsed["size"], content.len() as i64);
            // Should have a crc64 field
            assert!(parsed.get("crc64").is_some());
        }
    }

    assert!(found_file_entry, "should have a type 1 file entry");

    Ok(())
});

integration_test!(test_tar_split_writer_symlink, || {
    let mut writer = TarSplitWriter::new();

    let entry = TocEntry {
        name: PathBuf::from("mylink"),
        entry_type: TocEntryType::Symlink,
        mode: 0o777,
        uid: 0,
        gid: 0,
        size: None,
        modtime: None,
        link_name: Some("/target/path".to_string()),
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };

    writer.add_toc_entry(&entry, None::<std::fs::File>)?;
    let output = writer.finish()?;

    // Verify it's valid gzip
    let mut decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    // Should have segment entries (type 2) for the header
    let mut has_segment = false;
    for line in decompressed.lines() {
        let parsed: serde_json::Value = serde_json::from_str(line)?;
        if parsed["type"] == 2 {
            has_segment = true;
        }
    }
    assert!(has_segment, "should have segment entries");

    Ok(())
});

integration_test!(test_tar_split_writer_multiple_entries, || {
    let mut writer = TarSplitWriter::new();

    // Add a directory
    let dir_entry = TocEntry {
        name: PathBuf::from("mydir"),
        entry_type: TocEntryType::Dir,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: None,
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    writer.add_toc_entry(&dir_entry, None::<std::fs::File>)?;

    // Add a file
    let file_content = b"File in directory";
    let file_entry = TocEntry {
        name: PathBuf::from("mydir/file.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(file_content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    writer.add_toc_entry(&file_entry, Some(Cursor::new(file_content.to_vec())))?;

    // Add a symlink
    let symlink_entry = TocEntry {
        name: PathBuf::from("mydir/link"),
        entry_type: TocEntryType::Symlink,
        mode: 0o777,
        uid: 0,
        gid: 0,
        size: None,
        modtime: None,
        link_name: Some("file.txt".to_string()),
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    writer.add_toc_entry(&symlink_entry, None::<std::fs::File>)?;

    let output = writer.finish()?;

    // Decompress and count entries
    let mut decoder = flate2::read::GzDecoder::new(&output[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    let mut type1_count = 0;
    let mut type2_count = 0;

    for line in decompressed.lines() {
        let parsed: serde_json::Value = serde_json::from_str(line)?;
        match parsed["type"].as_i64() {
            Some(1) => type1_count += 1,
            Some(2) => type2_count += 1,
            _ => {}
        }
    }

    // Should have 1 type 1 entry (for the file with content)
    assert_eq!(type1_count, 1);

    // Should have multiple type 2 entries (headers for dir, file, symlink, plus padding and footer)
    assert!(type2_count >= 4);

    Ok(())
});
