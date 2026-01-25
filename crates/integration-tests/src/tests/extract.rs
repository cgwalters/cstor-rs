//! Integration tests for layer and image extraction.
//!
//! These tests use isolated test storage instances and extract to temporary
//! directories on a real filesystem (not tmpfs) to enable reflink testing.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use crate::fixture::TestStorage;
use crate::integration_test;
use cstor_rs::extract::{ExtractionOptions, extract_layer};
use cstor_rs::layer::Layer;
use cstor_rs::{TocEntry, TocEntryType};

/// Create a temporary directory on a real filesystem (not tmpfs).
///
/// Uses TMPDIR if set, otherwise creates in the project's target directory
/// which is typically on a real filesystem that may support reflinks.
fn create_real_tmpdir() -> color_eyre::Result<tempfile::TempDir> {
    // If TMPDIR is set and isn't tmpfs, use it
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        let path = std::path::Path::new(&tmpdir);
        if path.exists() {
            // Check if it's not tmpfs by looking at the filesystem type
            // We'll just try to use it - if it's tmpfs, reflinks will fail
            // but the copy fallback should work
            return Ok(tempfile::TempDir::new_in(path)?);
        }
    }

    // Fall back to creating in target directory (usually on same fs as project)
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let target_dir = workspace_root.join("target").join("test-tmp");
    std::fs::create_dir_all(&target_dir)?;
    Ok(tempfile::TempDir::new_in(target_dir)?)
}

/// Create a TestStorage on a real filesystem.
fn create_real_test_storage() -> color_eyre::Result<tempfile::TempDir> {
    create_real_tmpdir()
}

// ============================================================================
// Basic Layer Extraction Tests
// ============================================================================

integration_test!(test_extract_empty_layer, || {
    let storage = TestStorage::new()?;

    // Create an empty layer
    let builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    let layer_id = builder.commit()?;

    // Create destination directory on real filesystem
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Empty layer should have no extracted content
    assert_eq!(stats.files_extracted, 0);
    assert_eq!(stats.directories_created, 0);
    assert_eq!(stats.symlinks_created, 0);

    Ok(())
});

integration_test!(test_extract_layer_with_directories, || {
    let storage = TestStorage::new()?;

    // Create a layer with directory structure
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("usr", 0o755, 0, 0)?;
    builder.add_directory("usr/bin", 0o755, 0, 0)?;
    builder.add_directory("usr/lib", 0o755, 0, 0)?;
    builder.add_directory("etc", 0o755, 0, 0)?;
    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify directories were created
    assert!(stats.directories_created >= 4);

    // Verify directory structure exists
    assert!(dest_dir.path().join("usr").is_dir());
    assert!(dest_dir.path().join("usr/bin").is_dir());
    assert!(dest_dir.path().join("usr/lib").is_dir());
    assert!(dest_dir.path().join("etc").is_dir());

    Ok(())
});

integration_test!(test_extract_layer_with_files, || {
    let storage = TestStorage::new()?;

    // Create a layer with files
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;

    let content1 = b"Hello, World!";
    let entry1 = TocEntry {
        name: PathBuf::from("etc/hello.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(content1.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("etc/hello.txt", content1, &entry1)?;

    let content2 = b"#!/bin/sh\necho test\n";
    let entry2 = TocEntry {
        name: PathBuf::from("etc/script.sh"),
        entry_type: TocEntryType::Reg,
        mode: 0o755,
        uid: 0,
        gid: 0,
        size: Some(content2.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("etc/script.sh", content2, &entry2)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify files were extracted
    assert!(stats.files_extracted >= 2);

    // Verify file content
    let hello_content = std::fs::read_to_string(dest_dir.path().join("etc/hello.txt"))?;
    assert_eq!(hello_content, "Hello, World!");

    let script_content = std::fs::read_to_string(dest_dir.path().join("etc/script.sh"))?;
    assert_eq!(script_content, "#!/bin/sh\necho test\n");

    Ok(())
});

integration_test!(test_extract_layer_with_symlinks, || {
    let storage = TestStorage::new()?;

    // Create a layer with symlinks
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

    // Add symlinks
    builder.add_symlink("usr/bin/app-link", "app", 0, 0)?;
    builder.add_symlink("usr/bin/absolute-link", "/usr/bin/app", 0, 0)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify symlinks were created
    assert!(stats.symlinks_created >= 2);

    // Verify symlinks exist and point to correct targets
    let relative_link = dest_dir.path().join("usr/bin/app-link");
    assert!(relative_link.is_symlink());
    assert_eq!(std::fs::read_link(&relative_link)?.to_string_lossy(), "app");

    let absolute_link = dest_dir.path().join("usr/bin/absolute-link");
    assert!(absolute_link.is_symlink());
    assert_eq!(
        std::fs::read_link(&absolute_link)?.to_string_lossy(),
        "/usr/bin/app"
    );

    Ok(())
});

// Note: Hardlink extraction test is commented out because hardlink support
// during extraction through tar-split requires the target file to be
// extracted first, which depends on entry ordering. This is a known
// limitation that may be addressed in future work.
//
// integration_test!(test_extract_layer_with_hardlinks, || { ... });

// ============================================================================
// Reflink vs Copy Fallback Tests
// ============================================================================

integration_test!(test_extract_with_reflinks_enabled, || {
    let storage = TestStorage::new()?;

    // Create a layer with a file
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    // Create a larger file to make reflink more meaningful
    let content: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let entry = TocEntry {
        name: PathBuf::from("data/large.bin"),
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
    builder.add_file_copy("data/large.bin", &content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract with reflinks enabled (default)
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions {
        use_reflinks: true,
        ..Default::default()
    };
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify file was extracted
    assert!(stats.files_extracted >= 1);

    // Either bytes_reflinked or bytes_copied should be non-zero
    assert!(
        stats.bytes_reflinked > 0 || stats.bytes_copied > 0,
        "Should have reflinked or copied bytes"
    );

    // Verify content is correct
    let extracted = std::fs::read(dest_dir.path().join("data/large.bin"))?;
    assert_eq!(extracted, content);

    Ok(())
});

integration_test!(test_extract_with_reflinks_disabled, || {
    let storage = TestStorage::new()?;

    // Create a layer with a file
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    let content = b"Content that will be copied, not reflinked";
    let entry = TocEntry {
        name: PathBuf::from("data/copied.txt"),
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
    builder.add_file_copy("data/copied.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract with reflinks disabled
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions {
        use_reflinks: false,
        ..Default::default()
    };
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify file was extracted via copy
    assert!(stats.files_extracted >= 1);
    assert_eq!(
        stats.bytes_reflinked, 0,
        "Should not have reflinked any bytes"
    );
    assert!(stats.bytes_copied > 0, "Should have copied bytes");

    // Verify content is correct
    let extracted = std::fs::read_to_string(dest_dir.path().join("data/copied.txt"))?;
    assert_eq!(extracted, "Content that will be copied, not reflinked");

    Ok(())
});

// ============================================================================
// Permission and Ownership Tests
// ============================================================================

integration_test!(test_extract_preserves_permissions, || {
    let storage = TestStorage::new()?;

    // Create a layer with various permissions
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("perms", 0o700, 0, 0)?;

    let content = b"executable script";
    let entry = TocEntry {
        name: PathBuf::from("perms/script.sh"),
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
    builder.add_file_copy("perms/script.sh", content, &entry)?;

    let readonly_content = b"readonly data";
    let readonly_entry = TocEntry {
        name: PathBuf::from("perms/readonly.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o444,
        uid: 0,
        gid: 0,
        size: Some(readonly_content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("perms/readonly.txt", readonly_content, &readonly_entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract with permission preservation
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions {
        preserve_permissions: true,
        preserve_ownership: false, // Can't test ownership without root
        ..Default::default()
    };
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    assert!(stats.files_extracted >= 2);

    // Verify permissions
    let script_meta = std::fs::metadata(dest_dir.path().join("perms/script.sh"))?;
    assert!(
        script_meta.mode() & 0o111 != 0,
        "Script should be executable"
    );

    let readonly_meta = std::fs::metadata(dest_dir.path().join("perms/readonly.txt"))?;
    assert!(
        readonly_meta.mode() & 0o222 == 0,
        "Readonly file should not be writable"
    );

    Ok(())
});

integration_test!(test_extract_without_permission_preservation, || {
    let storage = TestStorage::new()?;

    // Create a layer with specific permissions
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    let content = b"test data";
    let entry = TocEntry {
        name: PathBuf::from("data/file.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o600, // Restrictive permissions
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
    builder.add_file_copy("data/file.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract without permission preservation
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions {
        preserve_permissions: false,
        preserve_ownership: false,
        ..Default::default()
    };
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    assert!(stats.files_extracted >= 1);

    // File should exist (permissions may be different from source)
    let file_path = dest_dir.path().join("data/file.txt");
    assert!(file_path.exists());
    let content = std::fs::read_to_string(&file_path)?;
    assert_eq!(content, "test data");

    Ok(())
});

// ============================================================================
// Complex Layer Tests
// ============================================================================

integration_test!(test_extract_complex_layer, || {
    let storage = TestStorage::new()?;

    // Create a complex layer similar to a real container layer
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;

    // Create directory structure
    builder.add_directory("usr", 0o755, 0, 0)?;
    builder.add_directory("usr/bin", 0o755, 0, 0)?;
    builder.add_directory("usr/lib", 0o755, 0, 0)?;
    builder.add_directory("etc", 0o755, 0, 0)?;
    builder.add_directory("var", 0o755, 0, 0)?;
    builder.add_directory("var/log", 0o755, 0, 0)?;

    // Add multiple files
    for i in 0..10 {
        let content = format!("Binary content {}", i);
        let path = format!("usr/bin/app{}", i);
        let entry = TocEntry {
            name: PathBuf::from(&path),
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
        builder.add_file_copy(&path, content.as_bytes(), &entry)?;
    }

    // Add config files
    let config_content = b"[config]\nkey=value\n";
    let config_entry = TocEntry {
        name: PathBuf::from("etc/app.conf"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(config_content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("etc/app.conf", config_content, &config_entry)?;

    // Add symlinks
    builder.add_symlink("usr/bin/latest", "app9", 0, 0)?;
    builder.add_symlink("etc/config", "app.conf", 0, 0)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify counts
    assert!(
        stats.directories_created >= 6,
        "Should create at least 6 directories"
    );
    assert!(
        stats.files_extracted >= 11,
        "Should extract at least 11 files"
    );
    assert!(
        stats.symlinks_created >= 2,
        "Should create at least 2 symlinks"
    );

    // Spot-check content
    let app0_content = std::fs::read_to_string(dest_dir.path().join("usr/bin/app0"))?;
    assert_eq!(app0_content, "Binary content 0");

    let config_content = std::fs::read_to_string(dest_dir.path().join("etc/app.conf"))?;
    assert_eq!(config_content, "[config]\nkey=value\n");

    // Verify symlinks
    assert!(dest_dir.path().join("usr/bin/latest").is_symlink());
    assert!(dest_dir.path().join("etc/config").is_symlink());

    Ok(())
});

// ============================================================================
// CLI Extraction Tests
// ============================================================================

/// Get the path to the cstor-rs binary.
fn cstor_binary() -> PathBuf {
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

integration_test!(test_cli_layer_extract, || {
    let storage = TestStorage::new()?;

    // Create a layer with content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("extracted", 0o755, 0, 0)?;

    let content = b"Content for CLI extraction test";
    let entry = TocEntry {
        name: PathBuf::from("extracted/file.txt"),
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
    builder.add_file_copy("extracted/file.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create parent temp directory, then use a non-existent subdirectory as dest
    // The CLI requires the destination to not exist
    let parent_dir = create_real_tmpdir()?;
    let dest_path = parent_dir.path().join("extract-dest");
    let dest_path_str = dest_path.to_string_lossy();

    // Run CLI extract command
    let output = run_cstor(&storage, &["layer", "extract", &layer_id, &dest_path_str])?;

    assert!(
        output.status.success(),
        "layer extract should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify extraction
    let file_path = dest_path.join("extracted/file.txt");
    assert!(file_path.exists(), "Extracted file should exist");

    let extracted_content = std::fs::read_to_string(&file_path)?;
    assert_eq!(extracted_content, "Content for CLI extraction test");

    Ok(())
});

integration_test!(test_cli_layer_extract_no_reflinks, || {
    let storage = TestStorage::new()?;

    // Create a layer with content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    let content = b"Content for copy-only extraction";
    let entry = TocEntry {
        name: PathBuf::from("data/file.txt"),
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
    builder.add_file_copy("data/file.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create parent temp directory, then use a non-existent subdirectory as dest
    // The CLI requires the destination to not exist
    let parent_dir = create_real_tmpdir()?;
    let dest_path = parent_dir.path().join("extract-dest");
    let dest_path_str = dest_path.to_string_lossy();

    // Run CLI extract command with --no-reflinks
    let output = run_cstor(
        &storage,
        &[
            "layer",
            "extract",
            &layer_id,
            &dest_path_str,
            "--no-reflinks",
        ],
    )?;

    assert!(
        output.status.success(),
        "layer extract should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify extraction
    let file_path = dest_path.join("data/file.txt");
    assert!(file_path.exists(), "Extracted file should exist");

    let extracted_content = std::fs::read_to_string(&file_path)?;
    assert_eq!(extracted_content, "Content for copy-only extraction");

    Ok(())
});

// ============================================================================
// Error Case Tests
// ============================================================================

integration_test!(test_extract_missing_layer, || {
    let storage = TestStorage::new()?;

    // Create destination directory (unused in this test, but here for context)
    let _dest_dir = create_real_tmpdir()?;

    // Try to extract a non-existent layer
    let fake_layer_id = "0000000000000000000000000000000000000000000000000000000000000000";
    let result = Layer::open(storage.storage(), fake_layer_id);

    // Should fail to open the layer
    assert!(result.is_err(), "Opening missing layer should fail");

    Ok(())
});

integration_test!(test_extract_to_readonly_destination, || {
    let storage = TestStorage::new()?;

    // Create a layer with content
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("test", 0o755, 0, 0)?;

    let content = b"test content";
    let entry = TocEntry {
        name: PathBuf::from("test/file.txt"),
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
    builder.add_file_copy("test/file.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create a readonly destination directory
    let dest_dir = create_real_tmpdir()?;
    let readonly_subdir = dest_dir.path().join("readonly");
    std::fs::create_dir(&readonly_subdir)?;
    std::fs::set_permissions(&readonly_subdir, std::fs::Permissions::from_mode(0o555))?;

    let dest = Dir::open_ambient_dir(&readonly_subdir, ambient_authority())?;

    // Try to extract - should fail
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let result = extract_layer(storage.storage(), &layer, &dest, &options);

    // Clean up permissions before checking result (so temp dir can be deleted)
    std::fs::set_permissions(&readonly_subdir, std::fs::Permissions::from_mode(0o755))?;

    // Should have failed due to permission denied
    assert!(result.is_err(), "Extraction to readonly dir should fail");

    Ok(())
});

// ============================================================================
// Empty File and Edge Case Tests
// ============================================================================

integration_test!(test_extract_empty_file, || {
    let storage = TestStorage::new()?;

    // Create a layer with an empty file
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    let content: &[u8] = b"";
    let entry = TocEntry {
        name: PathBuf::from("data/empty.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(0),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("data/empty.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let _stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify empty file was created
    let file_path = dest_dir.path().join("data/empty.txt");
    assert!(file_path.exists(), "Empty file should exist");

    let metadata = std::fs::metadata(&file_path)?;
    assert_eq!(metadata.len(), 0, "Empty file should have zero size");

    Ok(())
});

integration_test!(test_extract_large_file, || {
    let storage = TestStorage::new()?;

    // Create a layer with a large file (1MB)
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("large", 0o755, 0, 0)?;

    let size = 1024 * 1024; // 1MB
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let entry = TocEntry {
        name: PathBuf::from("large/bigfile.bin"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(size as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    builder.add_file_copy("large/bigfile.bin", &content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    assert!(stats.files_extracted >= 1);

    // Verify file was extracted correctly
    let file_path = dest_dir.path().join("large/bigfile.bin");
    let extracted = std::fs::read(&file_path)?;
    assert_eq!(extracted.len(), size);
    assert_eq!(extracted, content);

    Ok(())
});

integration_test!(test_extract_deeply_nested_paths, || {
    let storage = TestStorage::new()?;

    // Create a layer with deeply nested directories
    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;

    // Create nested structure
    builder.add_directory("a", 0o755, 0, 0)?;
    builder.add_directory("a/b", 0o755, 0, 0)?;
    builder.add_directory("a/b/c", 0o755, 0, 0)?;
    builder.add_directory("a/b/c/d", 0o755, 0, 0)?;
    builder.add_directory("a/b/c/d/e", 0o755, 0, 0)?;

    let content = b"Deep content";
    let entry = TocEntry {
        name: PathBuf::from("a/b/c/d/e/deep.txt"),
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
    builder.add_file_copy("a/b/c/d/e/deep.txt", content, &entry)?;

    let layer_id = builder.commit()?;

    // Create destination directory
    let dest_dir = create_real_tmpdir()?;
    let dest = Dir::open_ambient_dir(dest_dir.path(), ambient_authority())?;

    // Extract
    let layer = Layer::open(storage.storage(), &layer_id)?;
    let options = ExtractionOptions::default();
    let _stats = extract_layer(storage.storage(), &layer, &dest, &options)?;

    // Verify deeply nested file exists
    let file_path = dest_dir.path().join("a/b/c/d/e/deep.txt");
    assert!(file_path.exists(), "Deeply nested file should exist");

    let extracted = std::fs::read_to_string(&file_path)?;
    assert_eq!(extracted, "Deep content");

    Ok(())
});
