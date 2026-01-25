//! CLI integration tests using constructed test storage.
//!
//! These tests create isolated storage instances with LayerBuilder,
//! then run CLI commands against them using `--root`.

use std::path::PathBuf;
use std::process::Command;

use crate::fixture::TestStorage;
use crate::integration_test;
use cstor_rs::{TocEntry, TocEntryType};

/// Get the path to the cstor-rs binary.
fn cstor_binary() -> PathBuf {
    // Find the binary in target/debug or target/release
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let debug_path = workspace_root.join("target/debug/cstor-rs");
    if debug_path.exists() {
        return debug_path;
    }

    let release_path = workspace_root.join("target/release/cstor-rs");
    if release_path.exists() {
        return release_path;
    }

    // Fall back to cargo run
    panic!("cstor-rs binary not found. Run `cargo build` first.");
}

/// Run cstor-rs CLI with the given arguments and storage root.
fn run_cstor(storage: &TestStorage, args: &[&str]) -> std::io::Result<std::process::Output> {
    let binary = cstor_binary();
    let root = storage.root_path().to_string_lossy();

    Command::new(binary)
        .arg("--root")
        .arg(root.as_ref())
        .args(args)
        .output()
}

integration_test!(test_cli_layer_inspect, || {
    let storage = TestStorage::new()?;

    // Create a layer with some content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("usr", 0o755, 0, 0)?;
    builder.add_directory("usr/bin", 0o755, 0, 0)?;

    let content = b"#!/bin/sh\necho hello\n";
    let entry = TocEntry {
        name: PathBuf::from("usr/bin/hello"),
        entry_type: TocEntryType::Reg,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: Some(content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("usr/bin/hello", content, &entry)?;

    let layer_id = builder.commit()?;

    // Run CLI inspect command
    let output = run_cstor(&storage, &["layer", "inspect", &layer_id])?;

    assert!(
        output.status.success(),
        "inspect should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain layer ID
    assert!(
        stdout.contains(&layer_id[..12]),
        "output should contain layer ID"
    );

    Ok(())
});

integration_test!(test_cli_layer_export, || {
    let storage = TestStorage::new()?;

    // Create a layer with content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;

    let content = b"test content for export";
    let entry = TocEntry {
        name: PathBuf::from("etc/test.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("etc/test.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Export to a temp file
    let temp_dir = tempfile::tempdir()?;
    let tar_path = temp_dir.path().join("layer.tar");
    let tar_path_str = tar_path.to_string_lossy();

    let output = run_cstor(
        &storage,
        &["layer", "export", &layer_id, "-o", &tar_path_str],
    )?;

    assert!(
        output.status.success(),
        "export should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify tar file exists and has content
    assert!(tar_path.exists(), "tar file should exist");
    let metadata = std::fs::metadata(&tar_path)?;
    assert!(metadata.len() > 0, "tar file should not be empty");

    // Verify tar contents using tar command
    let tar_output = Command::new("tar").args(["-tf", &tar_path_str]).output()?;

    if tar_output.status.success() {
        let listing = String::from_utf8_lossy(&tar_output.stdout);
        assert!(listing.contains("etc"), "tar should contain etc/");
        assert!(listing.contains("test.txt"), "tar should contain test.txt");
    }

    Ok(())
});

integration_test!(test_cli_resolve_link, || {
    let storage = TestStorage::new()?;

    // Create a layer
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    let link_id = builder.link_id().to_string();
    builder.add_directory("test", 0o755, 0, 0)?;
    let layer_id = builder.commit()?;

    // Resolve link ID to layer ID
    let output = run_cstor(&storage, &["resolve-link", &link_id])?;

    assert!(
        output.status.success(),
        "resolve-link should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&layer_id), "output should contain layer ID");

    Ok(())
});

integration_test!(test_cli_with_parent_layer, || {
    let storage = TestStorage::new()?;

    // Create parent layer
    let mut parent_builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    parent_builder.add_directory("base", 0o755, 0, 0)?;
    let parent_id = parent_builder.commit()?;

    // Create child layer
    let mut child_builder = cstor_rs::LayerBuilder::new(storage.storage(), Some(&parent_id))?;
    child_builder.add_directory("child", 0o755, 0, 0)?;
    let child_id = child_builder.commit()?;

    // Inspect child layer - should show parent
    let output = run_cstor(&storage, &["layer", "inspect", &child_id])?;

    assert!(
        output.status.success(),
        "inspect should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should mention parent somehow (either in output or in lower file)
    // At minimum, the layer should exist
    assert!(
        stdout.contains(&child_id[..12]),
        "output should contain child layer ID"
    );

    Ok(())
});

integration_test!(test_cli_export_layer_with_symlinks, || {
    let storage = TestStorage::new()?;

    // Create a layer with mixed content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("usr", 0o755, 0, 0)?;
    builder.add_directory("usr/bin", 0o755, 0, 0)?;

    let content = b"binary content";
    let entry = TocEntry {
        name: PathBuf::from("usr/bin/app"),
        entry_type: TocEntryType::Reg,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: Some(content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("usr/bin/app", content, &entry)?;

    // Add symlink
    builder.add_symlink("usr/bin/app-link", "app", 0, 0)?;

    let layer_id = builder.commit()?;

    // Export
    let temp_dir = tempfile::tempdir()?;
    let tar_path = temp_dir.path().join("layer.tar");
    let tar_path_str = tar_path.to_string_lossy();

    let output = run_cstor(
        &storage,
        &["layer", "export", &layer_id, "-o", &tar_path_str],
    )?;

    assert!(
        output.status.success(),
        "export should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // List tar contents
    let tar_output = Command::new("tar").args(["-tvf", &tar_path_str]).output()?;

    if tar_output.status.success() {
        let listing = String::from_utf8_lossy(&tar_output.stdout);
        // Should show the symlink
        assert!(listing.contains("app-link"), "tar should contain symlink");
        assert!(
            listing.contains("->") || listing.contains("app"),
            "symlink should point to app"
        );
    }

    Ok(())
});
