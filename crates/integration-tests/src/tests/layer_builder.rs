//! Integration tests for LayerBuilder.

use std::path::PathBuf;

use crate::fixture::TestStorage;
use crate::integration_test;
use cstor_rs::{TocEntry, TocEntryType};

integration_test!(test_create_empty_layer, || {
    let storage = TestStorage::new()?;

    // Create an empty layer
    let builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    let layer_id = builder.commit()?;

    // Verify the layer was created
    assert!(!layer_id.is_empty());
    assert_eq!(layer_id.len(), 64); // 64 hex characters

    // Verify the layer directory exists
    let diff_path = storage.overlay_path().join(&layer_id).join("diff");
    assert!(diff_path.exists(), "diff directory should exist");

    Ok(())
});

integration_test!(test_create_layer_with_directory, || {
    let storage = TestStorage::new()?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;
    builder.add_directory("etc/subdir", 0o755, 0, 0)?;
    let layer_id = builder.commit()?;

    // Verify directories exist
    let diff_path = storage.overlay_path().join(&layer_id).join("diff");
    assert!(diff_path.join("etc").is_dir());
    assert!(diff_path.join("etc/subdir").is_dir());

    Ok(())
});

integration_test!(test_create_layer_with_file, || {
    let storage = TestStorage::new()?;

    let content = b"Hello, World!";

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;

    // Create TocEntry for the file
    let entry = TocEntry {
        name: PathBuf::from("etc/hello.txt"),
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

    builder.add_file_copy("etc/hello.txt", content, &entry)?;
    let layer_id = builder.commit()?;

    // Verify file exists and has correct content
    let file_path = storage
        .overlay_path()
        .join(&layer_id)
        .join("diff/etc/hello.txt");
    let read_content = std::fs::read_to_string(&file_path)?;
    assert_eq!(read_content, "Hello, World!");

    Ok(())
});

integration_test!(test_create_layer_with_symlink, || {
    let storage = TestStorage::new()?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;
    builder.add_symlink("etc/link", "/target/path", 0, 0)?;
    let layer_id = builder.commit()?;

    // Verify symlink exists
    let link_path = storage.overlay_path().join(&layer_id).join("diff/etc/link");
    assert!(link_path.is_symlink());
    assert_eq!(
        std::fs::read_link(&link_path)?,
        std::path::Path::new("/target/path")
    );

    Ok(())
});
