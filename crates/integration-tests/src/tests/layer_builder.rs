//! Integration tests for LayerBuilder.

use std::io::Read;
use std::os::unix::io::AsFd;
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

integration_test!(test_create_layer_with_hardlink, || {
    let storage = TestStorage::new()?;

    let content = b"Hardlink target content";

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("etc", 0o755, 0, 0)?;

    // Create target file first
    let entry = TocEntry {
        name: PathBuf::from("etc/original.txt"),
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
    builder.add_file_copy("etc/original.txt", content, &entry)?;

    // Create hardlink to the file
    builder.add_hardlink("etc/hardlink.txt", std::path::Path::new("etc/original.txt"))?;
    let layer_id = builder.commit()?;

    // Verify both files exist and have same content
    let diff_path = storage.overlay_path().join(&layer_id).join("diff");
    let original_content = std::fs::read_to_string(diff_path.join("etc/original.txt"))?;
    let hardlink_content = std::fs::read_to_string(diff_path.join("etc/hardlink.txt"))?;
    assert_eq!(original_content, hardlink_content);
    assert_eq!(original_content, "Hardlink target content");

    // Verify they share the same inode (are actually hardlinks)
    use std::os::unix::fs::MetadataExt;
    let original_meta = std::fs::metadata(diff_path.join("etc/original.txt"))?;
    let hardlink_meta = std::fs::metadata(diff_path.join("etc/hardlink.txt"))?;
    assert_eq!(original_meta.ino(), hardlink_meta.ino());

    Ok(())
});

integration_test!(test_create_child_layer, || {
    let storage = TestStorage::new()?;

    // Create parent layer with a file
    let mut parent_builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    parent_builder.add_directory("etc", 0o755, 0, 0)?;

    let parent_content = b"Parent file content";
    let parent_entry = TocEntry {
        name: PathBuf::from("etc/parent.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(parent_content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    parent_builder.add_file_copy("etc/parent.txt", parent_content, &parent_entry)?;
    let parent_id = parent_builder.commit()?;

    // Create child layer that references parent
    let mut child_builder = cstor_rs::LayerBuilder::new(storage.storage(), Some(&parent_id))?;
    child_builder.add_directory("var", 0o755, 0, 0)?;

    let child_content = b"Child file content";
    let child_entry = TocEntry {
        name: PathBuf::from("var/child.txt"),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: Some(child_content.len() as u64),
        modtime: None,
        link_name: None,
        user_name: None,
        group_name: None,
        dev_major: None,
        dev_minor: None,
        xattrs: None,
        digest: None,
    };
    child_builder.add_file_copy("var/child.txt", child_content, &child_entry)?;
    let child_id = child_builder.commit()?;

    // Verify parent layer exists with its file
    let parent_diff = storage.overlay_path().join(&parent_id).join("diff");
    assert!(parent_diff.join("etc/parent.txt").exists());

    // Verify child layer exists with its file
    let child_diff = storage.overlay_path().join(&child_id).join("diff");
    assert!(child_diff.join("var/child.txt").exists());

    // Verify child layer has a "lower" file pointing to parent
    let child_layer_dir = storage.overlay_path().join(&child_id);
    let lower_content = std::fs::read_to_string(child_layer_dir.join("lower"))?;
    assert!(!lower_content.is_empty(), "child should have lower file");

    Ok(())
});

integration_test!(test_tar_split_generated, || {
    let storage = TestStorage::new()?;

    let content = b"File for tar-split test";

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    let layer_id_preview = builder.layer_id().to_string();

    builder.add_directory("data", 0o755, 0, 0)?;

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

    assert_eq!(layer_id, layer_id_preview);

    // Verify tar-split file was created
    let tar_split_path = storage
        .root_path()
        .join("overlay-layers")
        .join(format!("{}.tar-split.gz", layer_id));
    assert!(tar_split_path.exists(), "tar-split file should exist");

    // Verify it's a valid gzip file by trying to decompress it
    let tar_split_file = std::fs::File::open(&tar_split_path)?;
    let mut decoder = flate2::read::GzDecoder::new(tar_split_file);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed)?;

    // Should be NDJSON format
    assert!(!decompressed.is_empty(), "tar-split should have content");
    // Each line should be valid JSON
    for line in decompressed.lines() {
        let _: serde_json::Value = serde_json::from_str(line)?;
    }

    Ok(())
});

integration_test!(test_layers_json_updated, || {
    let storage = TestStorage::new()?;

    // Read initial layers.json
    let layers_json_path = storage.root_path().join("overlay-layers/layers.json");
    let initial: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&layers_json_path)?)?;
    assert!(initial.is_empty(), "should start with empty layers");

    // Create first layer
    let mut builder1 = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder1.add_directory("layer1", 0o755, 0, 0)?;
    let layer1_id = builder1.commit()?;

    // Verify layers.json has one entry
    let after_first: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&layers_json_path)?)?;
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0]["id"].as_str(), Some(layer1_id.as_str()));

    // Create second layer
    let mut builder2 = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder2.add_directory("layer2", 0o755, 0, 0)?;
    let layer2_id = builder2.commit()?;

    // Verify layers.json has two entries
    let after_second: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&layers_json_path)?)?;
    assert_eq!(after_second.len(), 2);

    // Both layers should be present
    let ids: Vec<&str> = after_second
        .iter()
        .filter_map(|e| e["id"].as_str())
        .collect();
    assert!(ids.contains(&layer1_id.as_str()));
    assert!(ids.contains(&layer2_id.as_str()));

    Ok(())
});

integration_test!(test_link_symlink_created, || {
    let storage = TestStorage::new()?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    let link_id = builder.link_id().to_string();
    builder.add_directory("test", 0o755, 0, 0)?;
    let layer_id = builder.commit()?;

    // Verify the link file exists in the layer directory
    let link_file_path = storage.overlay_path().join(&layer_id).join("link");
    assert!(link_file_path.exists(), "link file should exist");
    let link_content = std::fs::read_to_string(&link_file_path)?;
    assert_eq!(link_content, link_id);

    // Verify the symlink exists in overlay/l/
    let symlink_path = storage.overlay_path().join("l").join(&link_id);
    assert!(
        symlink_path.is_symlink(),
        "l/{} should be a symlink",
        link_id
    );

    // Verify symlink points to the layer's diff directory
    let target = std::fs::read_link(&symlink_path)?;
    let expected_target = format!("../{}/diff", layer_id);
    assert_eq!(target.to_string_lossy(), expected_target);

    Ok(())
});

integration_test!(test_multiple_files_in_layer, || {
    let storage = TestStorage::new()?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;

    // Create a more complex layer structure
    builder.add_directory("usr", 0o755, 0, 0)?;
    builder.add_directory("usr/bin", 0o755, 0, 0)?;
    builder.add_directory("usr/lib", 0o755, 0, 0)?;
    builder.add_directory("etc", 0o755, 0, 0)?;

    // Add several files
    for i in 0..5 {
        let content = format!("File content {}", i);
        let path = format!("usr/bin/file{}", i);
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

    // Add a config file
    let config_content = b"[config]\nkey=value\n";
    let config_entry = TocEntry {
        name: PathBuf::from("etc/config.ini"),
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
    builder.add_file_copy("etc/config.ini", config_content, &config_entry)?;

    // Add a symlink
    builder.add_symlink("usr/bin/latest", "file4", 0, 0)?;

    let layer_id = builder.commit()?;

    // Verify all files exist
    let diff_path = storage.overlay_path().join(&layer_id).join("diff");
    for i in 0..5 {
        let file_path = diff_path.join(format!("usr/bin/file{}", i));
        assert!(file_path.exists(), "file{} should exist", i);
        let content = std::fs::read_to_string(&file_path)?;
        assert_eq!(content, format!("File content {}", i));
    }

    // Verify config file
    let config_path = diff_path.join("etc/config.ini");
    assert!(config_path.exists());
    assert_eq!(
        std::fs::read_to_string(&config_path)?,
        "[config]\nkey=value\n"
    );

    // Verify symlink
    let symlink_path = diff_path.join("usr/bin/latest");
    assert!(symlink_path.is_symlink());
    assert_eq!(
        std::fs::read_link(&symlink_path)?.to_string_lossy(),
        "file4"
    );

    Ok(())
});

integration_test!(test_add_file_reflink, || {
    let storage = TestStorage::new()?;

    // Create a source file in a temp directory
    let temp_dir = tempfile::tempdir()?;
    let source_path = temp_dir.path().join("source.txt");
    let content = b"This content will be reflinked (or copied as fallback)";
    std::fs::write(&source_path, content)?;

    // Open source file for reading
    let source_file = std::fs::File::open(&source_path)?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("data", 0o755, 0, 0)?;

    let entry = TocEntry {
        name: PathBuf::from("data/reflinked.txt"),
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

    // Use add_file_reflink - will use reflink if supported, else falls back to copy
    builder.add_file_reflink("data/reflinked.txt", source_file.as_fd(), &entry)?;
    let layer_id = builder.commit()?;

    // Verify file exists and has correct content
    let dest_path = storage
        .overlay_path()
        .join(&layer_id)
        .join("diff/data/reflinked.txt");
    let read_content = std::fs::read(&dest_path)?;
    assert_eq!(read_content, content);

    Ok(())
});

integration_test!(test_add_file_reflink_large_file, || {
    let storage = TestStorage::new()?;

    // Create a larger source file (1MB) to test reflink behavior
    let temp_dir = tempfile::tempdir()?;
    let source_path = temp_dir.path().join("large_source.bin");

    // Create 1MB of data
    let size = 1024 * 1024;
    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    std::fs::write(&source_path, &content)?;

    let source_file = std::fs::File::open(&source_path)?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    builder.add_directory("large", 0o755, 0, 0)?;

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

    builder.add_file_reflink("large/bigfile.bin", source_file.as_fd(), &entry)?;
    let layer_id = builder.commit()?;

    // Verify file exists and has correct content
    let dest_path = storage
        .overlay_path()
        .join(&layer_id)
        .join("diff/large/bigfile.bin");
    let read_content = std::fs::read(&dest_path)?;
    assert_eq!(read_content.len(), size);
    assert_eq!(read_content, content);

    Ok(())
});

integration_test!(test_entry_count, || {
    let storage = TestStorage::new()?;

    let mut builder = cstor_rs::LayerBuilder::new(storage.storage(), None)?;
    assert_eq!(builder.entry_count(), 0);

    builder.add_directory("dir1", 0o755, 0, 0)?;
    assert_eq!(builder.entry_count(), 1);

    builder.add_directory("dir2", 0o755, 0, 0)?;
    assert_eq!(builder.entry_count(), 2);

    builder.add_symlink("link", "/target", 0, 0)?;
    assert_eq!(builder.entry_count(), 3);

    let content = b"test";
    let entry = TocEntry {
        name: PathBuf::from("file.txt"),
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
    builder.add_file_copy("file.txt", content, &entry)?;
    assert_eq!(builder.entry_count(), 4);

    let _ = builder.commit()?;

    Ok(())
});
