//! Integration tests for LayerStore.

use crate::fixture::TestStorage;
use crate::integration_test;
use cstor_rs::LayerRecord;

integration_test!(test_create_empty_layer_via_store, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create an empty layer
    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Verify the layer was created
    assert!(!layer.id.is_empty());
    assert_eq!(layer.id.len(), 64);
    assert!(layer.parent.is_none());
    assert!(!layer.is_incomplete());
    assert!(layer.created.is_some());

    // Verify directory structure
    let layer_dir = storage.overlay_path().join(&layer.id);
    assert!(layer_dir.exists(), "layer directory should exist");
    assert!(
        layer_dir.join("diff").is_dir(),
        "diff directory should exist"
    );
    assert!(layer_dir.join("link").is_file(), "link file should exist");
    assert!(
        layer_dir.join("work").is_dir(),
        "work directory should exist"
    );
    assert!(
        layer_dir.join("merged").is_dir(),
        "merged directory should exist"
    );
    assert!(
        layer_dir.join("empty").is_dir(),
        "empty directory should exist for base layer"
    );

    // Verify link file content
    let link_content = std::fs::read_to_string(layer_dir.join("link"))?;
    assert_eq!(link_content.len(), 26);
    assert!(link_content.chars().all(|c| c.is_ascii_uppercase()));

    // Verify symlink in l/ directory
    let symlink_path = storage.overlay_path().join("l").join(&link_content);
    assert!(symlink_path.is_symlink());

    Ok(())
});

integration_test!(test_create_layer_with_parent, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create parent layer
    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Create child layer
    let child = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;

    // Verify parent relationship
    assert_eq!(child.parent, Some(parent.id.clone()));

    // Verify child has lower file
    let child_dir = storage.overlay_path().join(&child.id);
    let lower_content = std::fs::read_to_string(child_dir.join("lower"))?;
    assert!(!lower_content.is_empty());
    assert!(lower_content.starts_with("l/"));

    // Child should not have empty/ directory
    assert!(!child_dir.join("empty").exists());

    Ok(())
});

integration_test!(test_create_layer_with_names, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &["tag1", "tag2"], None::<std::io::Empty>)?;

    assert_eq!(
        layer.names,
        Some(vec!["tag1".to_string(), "tag2".to_string()])
    );

    Ok(())
});

integration_test!(test_create_layer_with_custom_id, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let custom_id = "a".repeat(64);
    let layer = layer_store.create_layer(Some(&custom_id), None, &[], None::<std::io::Empty>)?;

    assert_eq!(layer.id, custom_id);

    Ok(())
});

integration_test!(test_delete_layer, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a layer
    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let layer_id = layer.id.clone();

    // Verify it exists
    assert!(layer_store.exists(&layer_id)?);
    let layer_dir = storage.overlay_path().join(&layer_id);
    assert!(layer_dir.exists());

    // Delete it
    layer_store.delete_layer(&layer_id)?;

    // Verify it's gone
    assert!(!layer_store.exists(&layer_id)?);
    assert!(!layer_dir.exists());

    Ok(())
});

integration_test!(test_delete_layer_not_found, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let result = layer_store.delete_layer("nonexistent");
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(cstor_rs::StorageError::LayerNotFound(_))
    ));

    Ok(())
});

integration_test!(test_delete_layer_with_child_fails, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create parent and child
    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let _child = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;

    // Try to delete parent - should fail
    let result = layer_store.delete_layer(&parent.id);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(cstor_rs::StorageError::InvalidStorage(_))
    ));

    Ok(())
});

integration_test!(test_list_layers, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Initially empty
    let layers = layer_store.list_layers()?;
    assert!(layers.is_empty());

    // Create some layers
    let layer1 = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let layer2 = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let layer3 = layer_store.create_layer(None, Some(&layer1.id), &[], None::<std::io::Empty>)?;

    // List should show all three
    let layers = layer_store.list_layers()?;
    assert_eq!(layers.len(), 3);

    let ids: Vec<&str> = layers.iter().map(|l| l.id.as_str()).collect();
    assert!(ids.contains(&layer1.id.as_str()));
    assert!(ids.contains(&layer2.id.as_str()));
    assert!(ids.contains(&layer3.id.as_str()));

    Ok(())
});

integration_test!(test_get_layer, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let created = layer_store.create_layer(None, None, &["test"], None::<std::io::Empty>)?;

    let retrieved = layer_store.get_layer(&created.id)?;
    assert_eq!(retrieved.id, created.id);
    assert_eq!(retrieved.names, created.names);

    // Non-existent layer
    let result = layer_store.get_layer("nonexistent");
    assert!(result.is_err());

    Ok(())
});

integration_test!(test_get_children, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let child1 = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;
    let child2 = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;
    let _unrelated = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    let children = layer_store.get_children(&parent.id)?;
    assert_eq!(children.len(), 2);

    let child_ids: Vec<&str> = children.iter().map(|l| l.id.as_str()).collect();
    assert!(child_ids.contains(&child1.id.as_str()));
    assert!(child_ids.contains(&child2.id.as_str()));

    Ok(())
});

integration_test!(test_layer_validation, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a valid layer
    let _layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Validation should pass
    let errors = layer_store.validate()?;
    assert!(errors.is_empty(), "validation should pass: {:?}", errors);

    Ok(())
});

integration_test!(test_layer_parent_not_found, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Try to create a layer with non-existent parent
    let result = layer_store.create_layer(
        None,
        Some("nonexistent_parent"),
        &[],
        None::<std::io::Empty>,
    );
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(cstor_rs::StorageError::LayerNotFound(_))
    ));

    Ok(())
});

integration_test!(test_layer_record_serialization_roundtrip, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &["name1"], None::<std::io::Empty>)?;

    // Read layers.json directly and verify format
    let layers_json_path = storage.root_path().join("overlay-layers/layers.json");
    let content = std::fs::read_to_string(&layers_json_path)?;
    let parsed: Vec<LayerRecord> = serde_json::from_str(&content)?;

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].id, layer.id);
    assert_eq!(parsed[0].names, layer.names);
    assert!(!parsed[0].is_incomplete());

    Ok(())
});

integration_test!(test_three_layer_chain, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a chain: base -> middle -> top
    let base = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let middle = layer_store.create_layer(None, Some(&base.id), &[], None::<std::io::Empty>)?;
    let top = layer_store.create_layer(None, Some(&middle.id), &[], None::<std::io::Empty>)?;

    // Verify parent relationships
    assert!(base.parent.is_none());
    assert_eq!(middle.parent, Some(base.id.clone()));
    assert_eq!(top.parent, Some(middle.id.clone()));

    // Verify lower file for top layer contains full chain
    let top_dir = storage.overlay_path().join(&top.id);
    let lower_content = std::fs::read_to_string(top_dir.join("lower"))?;

    // Should have two entries: l/<middle-link>:l/<base-link>
    let parts: Vec<&str> = lower_content.split(':').collect();
    assert_eq!(parts.len(), 2);
    assert!(parts[0].starts_with("l/"));
    assert!(parts[1].starts_with("l/"));

    Ok(())
});

integration_test!(test_generate_unique_ids, || {
    // Test that ID generation produces valid and reasonably unique IDs
    use cstor_rs::{generate_layer_id, generate_link_id};

    // Generate multiple layer IDs
    let mut layer_ids = std::collections::HashSet::new();
    for _ in 0..100 {
        let id = generate_layer_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        layer_ids.insert(id);
        // Small delay to ensure time-based generation varies
        std::thread::sleep(std::time::Duration::from_micros(1));
    }

    // Generate multiple link IDs
    let mut link_ids = std::collections::HashSet::new();
    for _ in 0..100 {
        let id = generate_link_id();
        assert_eq!(id.len(), 26);
        assert!(id.chars().all(|c| c.is_ascii_uppercase()));
        link_ids.insert(id);
        std::thread::sleep(std::time::Duration::from_micros(1));
    }

    Ok(())
});

integration_test!(test_delete_removes_symlink, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Get the link ID
    let layer_dir = storage.overlay_path().join(&layer.id);
    let link_id = std::fs::read_to_string(layer_dir.join("link"))?;
    let link_id = link_id.trim();

    // Verify symlink exists
    let symlink_path = storage.overlay_path().join("l").join(link_id);
    assert!(symlink_path.is_symlink());

    // Delete the layer
    layer_store.delete_layer(&layer.id)?;

    // Verify symlink is removed
    assert!(!symlink_path.exists());

    Ok(())
});

integration_test!(test_create_layer_from_splitfdstream, || {
    use cstor_rs::ImportOptions;
    use cstor_rs::splitfdstream::SplitfdstreamWriter;
    use std::io::Write;
    use tempfile::NamedTempFile;

    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a simple tar archive as a splitfdstream
    // We'll create a tar with one directory and one file

    // First, create an external file to use for the file content
    let mut ext_file = NamedTempFile::new()?;
    ext_file.write_all(b"Hello from splitfdstream!")?;
    ext_file.flush()?;

    // Build a tar archive in memory
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);

        // Add a directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("testdir")?;
        header.set_mode(0o755);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, std::io::empty())?;

        // Add a file
        let content = b"Hello from splitfdstream!";
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("testdir/hello.txt")?;
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(content.len() as u64);
        header.set_cksum();
        builder.append(&header, content.as_slice())?;

        builder.finish()?;
    }

    // Wrap the tar as a splitfdstream (inline only for simplicity)
    let mut stream_buffer = Vec::new();
    {
        let mut writer = SplitfdstreamWriter::new(&mut stream_buffer);
        writer.write_inline(&tar_buffer)?;
        writer.finish()?;
    }

    // Open the external file for reading
    let ext_file_read = std::fs::File::open(ext_file.path())?;
    let files = vec![ext_file_read];

    // Import the layer
    let options = ImportOptions::default();
    let (layer, stats) = layer_store.create_layer_from_splitfdstream(
        None,
        None,
        &["splitfd-test"],
        stream_buffer.as_slice(),
        &files,
        &options,
    )?;

    // Verify layer was created
    assert!(!layer.id.is_empty());
    assert_eq!(layer.id.len(), 64);
    assert!(layer.created.is_some());
    assert!(!layer.is_incomplete());
    assert_eq!(layer.names, Some(vec!["splitfd-test".to_string()]));

    // Verify stats
    assert_eq!(stats.directories_created, 1);
    assert_eq!(stats.files_imported, 1);

    // Verify directory structure
    let layer_dir = storage.overlay_path().join(&layer.id);
    assert!(layer_dir.exists());
    assert!(layer_dir.join("diff").is_dir());
    assert!(layer_dir.join("link").is_file());

    // Verify extracted content
    let diff_dir = layer_dir.join("diff");
    assert!(diff_dir.join("testdir").is_dir());
    assert!(diff_dir.join("testdir/hello.txt").is_file());

    let content = std::fs::read_to_string(diff_dir.join("testdir/hello.txt"))?;
    assert_eq!(content, "Hello from splitfdstream!");

    // Verify tar-split was generated
    let tar_split_path = storage
        .root_path()
        .join("overlay-layers")
        .join(format!("{}.tar-split.gz", layer.id));
    assert!(tar_split_path.exists());

    Ok(())
});

integration_test!(test_create_layer_from_splitfdstream_with_parent, || {
    use cstor_rs::ImportOptions;
    use cstor_rs::splitfdstream::SplitfdstreamWriter;

    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a parent layer first
    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Create an empty tar
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);

        // Add a directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("childdir")?;
        header.set_mode(0o755);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, std::io::empty())?;

        builder.finish()?;
    }

    // Wrap as splitfdstream
    let mut stream_buffer = Vec::new();
    {
        let mut writer = SplitfdstreamWriter::new(&mut stream_buffer);
        writer.write_inline(&tar_buffer)?;
        writer.finish()?;
    }

    // Import the layer with parent
    let options = ImportOptions::default();
    let (layer, stats) = layer_store.create_layer_from_splitfdstream(
        None,
        Some(&parent.id),
        &[],
        stream_buffer.as_slice(),
        &[],
        &options,
    )?;

    // Verify parent relationship
    assert_eq!(layer.parent, Some(parent.id.clone()));
    assert_eq!(stats.directories_created, 1);

    // Verify lower file exists
    let layer_dir = storage.overlay_path().join(&layer.id);
    let lower_content = std::fs::read_to_string(layer_dir.join("lower"))?;
    assert!(lower_content.starts_with("l/"));

    Ok(())
});

integration_test!(test_create_layer_from_splitfdstream_symlink, || {
    use cstor_rs::ImportOptions;
    use cstor_rs::splitfdstream::SplitfdstreamWriter;

    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a tar with a symlink
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);

        // Add a regular file first
        let content = b"target content";
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("target.txt")?;
        header.set_mode(0o644);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(content.len() as u64);
        header.set_cksum();
        builder.append(&header, content.as_slice())?;

        // Add a symlink
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_path("link.txt")?;
        header.set_link_name("target.txt")?;
        header.set_mode(0o777);
        header.set_uid(1000);
        header.set_gid(1000);
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, std::io::empty())?;

        builder.finish()?;
    }

    // Wrap as splitfdstream
    let mut stream_buffer = Vec::new();
    {
        let mut writer = SplitfdstreamWriter::new(&mut stream_buffer);
        writer.write_inline(&tar_buffer)?;
        writer.finish()?;
    }

    // Import the layer
    let options = ImportOptions::default();
    let (layer, stats) = layer_store.create_layer_from_splitfdstream(
        None,
        None,
        &[],
        stream_buffer.as_slice(),
        &[],
        &options,
    )?;

    // Verify stats
    assert_eq!(stats.files_imported, 1);
    assert_eq!(stats.symlinks_created, 1);

    // Verify symlink
    let diff_dir = storage.overlay_path().join(&layer.id).join("diff");
    let link_path = diff_dir.join("link.txt");
    assert!(link_path.is_symlink());
    assert_eq!(
        std::fs::read_link(&link_path)?.to_str().unwrap(),
        "target.txt"
    );

    Ok(())
});
