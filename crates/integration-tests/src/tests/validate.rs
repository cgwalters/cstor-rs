//! Integration tests for storage validation (fsck).

use crate::fixture::TestStorage;
use crate::integration_test;
use cstor_rs::{ValidateOptions, ValidationError, ValidationWarning};

integration_test!(test_validate_clean_storage, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a layer with child to have some structure
    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let _child = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;

    // Validation should pass with no errors
    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(
        result.is_ok(),
        "clean storage should pass validation, got errors: {:?}",
        result.errors
    );
    assert_eq!(result.stats.layers_checked, 2);
    assert_eq!(result.stats.images_checked, 0);

    Ok(())
});

integration_test!(test_validate_empty_storage, || {
    let storage = TestStorage::new()?;

    // Empty storage should pass validation
    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.is_ok());
    assert_eq!(result.stats.layers_checked, 0);
    assert_eq!(result.stats.images_checked, 0);

    Ok(())
});

integration_test!(test_validate_missing_layer_dir, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a layer
    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let layer_dir = storage.overlay_path().join(&layer.id);

    // Remove the layer directory
    std::fs::remove_dir_all(&layer_dir)?;

    // Validation should detect the missing directory
    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_missing_dir = result.errors.iter().any(
        |e| matches!(e, ValidationError::MissingLayerDir { layer_id } if layer_id == &layer.id),
    );
    assert!(has_missing_dir, "should detect missing layer directory");

    Ok(())
});

integration_test!(test_validate_missing_diff_dir, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let diff_dir = storage.overlay_path().join(&layer.id).join("diff");

    // Remove the diff directory
    std::fs::remove_dir(&diff_dir)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_missing_diff = result.errors.iter().any(
        |e| matches!(e, ValidationError::MissingDiffDir { layer_id } if layer_id == &layer.id),
    );
    assert!(has_missing_diff, "should detect missing diff directory");

    Ok(())
});

integration_test!(test_validate_missing_link_file, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let link_file = storage.overlay_path().join(&layer.id).join("link");

    // Remove the link file
    std::fs::remove_file(&link_file)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_missing_link = result.errors.iter().any(
        |e| matches!(e, ValidationError::MissingLinkFile { layer_id } if layer_id == &layer.id),
    );
    assert!(has_missing_link, "should detect missing link file");

    Ok(())
});

integration_test!(test_validate_invalid_link_file, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let link_file = storage.overlay_path().join(&layer.id).join("link");

    // Corrupt the link file
    std::fs::write(&link_file, "invalid")?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_invalid_link = result.errors.iter().any(
        |e| matches!(e, ValidationError::InvalidLinkFile { layer_id, .. } if layer_id == &layer.id),
    );
    assert!(has_invalid_link, "should detect invalid link file");

    Ok(())
});

integration_test!(test_validate_missing_symlink, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Get the link ID
    let link_file = storage.overlay_path().join(&layer.id).join("link");
    let link_id = std::fs::read_to_string(&link_file)?;
    let link_id = link_id.trim();

    // Remove the symlink in overlay/l/
    let symlink_path = storage.overlay_path().join("l").join(link_id);
    std::fs::remove_file(&symlink_path)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_missing_symlink = result
        .errors
        .iter()
        .any(|e| matches!(e, ValidationError::MissingSymlink { link_id: l, .. } if l == link_id));
    assert!(has_missing_symlink, "should detect missing symlink");

    Ok(())
});

integration_test!(test_validate_broken_symlink, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Get the link ID
    let link_file = storage.overlay_path().join(&layer.id).join("link");
    let link_id = std::fs::read_to_string(&link_file)?;
    let link_id = link_id.trim();

    // Replace the symlink with one pointing to a non-existent target
    let symlink_path = storage.overlay_path().join("l").join(link_id);
    std::fs::remove_file(&symlink_path)?;
    std::os::unix::fs::symlink("../nonexistent/diff", &symlink_path)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    // Should detect either broken symlink or target mismatch
    let has_broken = result.errors.iter().any(|e| {
        matches!(
            e,
            ValidationError::BrokenSymlink { .. } | ValidationError::SymlinkTargetMismatch { .. }
        )
    });
    assert!(has_broken, "should detect broken symlink");

    Ok(())
});

integration_test!(test_validate_missing_tar_split, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create layer from tar to ensure tar-split is generated
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("test")?;
        header.set_mode(0o755);
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, std::io::empty())?;
        builder.finish()?;
    }

    let diff_digest: oci_spec::image::Digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".parse()?;
    let layer = layer_store.create_layer_from_tar(
        None,
        None,
        &[],
        tar_buffer.as_slice(),
        &diff_digest,
        &diff_digest,
        0,
    )?;

    // Remove the tar-split file
    let tar_split_path = storage
        .root_path()
        .join("overlay-layers")
        .join(format!("{}.tar-split.gz", layer.id));
    std::fs::remove_file(&tar_split_path)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_missing_tar_split = result.errors.iter().any(
        |e| matches!(e, ValidationError::MissingTarSplit { layer_id } if layer_id == &layer.id),
    );
    assert!(has_missing_tar_split, "should detect missing tar-split");

    Ok(())
});

integration_test!(test_validate_invalid_parent, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create parent and child
    let parent = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let child = layer_store.create_layer(None, Some(&parent.id), &[], None::<std::io::Empty>)?;

    // Manually corrupt layers.json to have invalid parent reference
    // We need to only modify the "parent" field, not the layer IDs
    let layers_json = storage.root_path().join("overlay-layers/layers.json");
    let content = std::fs::read_to_string(&layers_json)?;
    let mut parsed: Vec<cstor_rs::LayerRecord> = serde_json::from_str(&content)?;

    // Find the child and corrupt its parent reference
    for layer in &mut parsed {
        if layer.id == child.id {
            layer.parent =
                Some("nonexistent_parent_0000000000000000000000000000000000".to_string());
        }
    }
    std::fs::write(&layers_json, serde_json::to_string_pretty(&parsed)?)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_invalid_parent = result.errors.iter().any(
        |e| matches!(e, ValidationError::InvalidParent { layer_id, .. } if layer_id == &child.id),
    );
    assert!(has_invalid_parent, "should detect invalid parent reference");

    Ok(())
});

integration_test!(test_validate_orphaned_layer_dir, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a layer
    let _layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Create an orphaned directory (not in layers.json)
    let orphan_id = "deadbeef".repeat(8); // 64 chars
    let orphan_dir = storage.overlay_path().join(&orphan_id);
    std::fs::create_dir(&orphan_dir)?;

    let options = ValidateOptions {
        check_orphans: true,
        ..Default::default()
    };
    let result = storage.storage().validate(&options)?;

    assert!(result.has_warnings());
    let has_orphan = result.warnings.iter().any(
        |w| matches!(w, ValidationWarning::OrphanedLayerDir { dir_name } if dir_name == &orphan_id),
    );
    assert!(has_orphan, "should detect orphaned layer directory");
    assert_eq!(result.stats.orphaned_layer_dirs, 1);

    Ok(())
});

integration_test!(test_validate_orphan_detection_disabled, || {
    let storage = TestStorage::new()?;

    // Create an orphaned directory
    let orphan_id = "deadbeef".repeat(8);
    let orphan_dir = storage.overlay_path().join(&orphan_id);
    std::fs::create_dir(&orphan_dir)?;

    // Disable orphan checking
    let options = ValidateOptions {
        check_orphans: false,
        ..Default::default()
    };
    let result = storage.storage().validate(&options)?;

    // Should not report the orphan as a warning
    let has_orphan = result
        .warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::OrphanedLayerDir { .. }));
    assert!(
        !has_orphan,
        "orphan should not be reported when check_orphans is false"
    );

    Ok(())
});

integration_test!(test_validate_incomplete_layer_warning, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a layer
    let layer = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Manually mark it as incomplete in layers.json
    let layers_json = storage.root_path().join("overlay-layers/layers.json");
    let content = std::fs::read_to_string(&layers_json)?;
    let mut parsed: Vec<cstor_rs::LayerRecord> = serde_json::from_str(&content)?;
    parsed[0].set_incomplete(true);
    std::fs::write(&layers_json, serde_json::to_string_pretty(&parsed)?)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_warnings());
    let has_incomplete = result.warnings.iter().any(
        |w| matches!(w, ValidationWarning::IncompleteLayer { layer_id } if layer_id == &layer.id),
    );
    assert!(has_incomplete, "should warn about incomplete layer");

    Ok(())
});

integration_test!(test_validate_orphaned_symlink, || {
    let storage = TestStorage::new()?;

    // Create an orphaned symlink in overlay/l/ (no corresponding layer)
    let l_dir = storage.overlay_path().join("l");
    let orphan_link_id = "ORPHANEDLINKIDWITHTWENTY6";
    std::os::unix::fs::symlink("../nonexistent/diff", l_dir.join(orphan_link_id))?;

    let options = ValidateOptions {
        check_orphans: true,
        ..Default::default()
    };
    let result = storage.storage().validate(&options)?;

    assert!(result.has_warnings());
    let has_orphan_symlink = result.warnings.iter().any(|w| {
        matches!(w, ValidationWarning::OrphanedSymlink { link_id } if link_id == orphan_link_id)
    });
    assert!(has_orphan_symlink, "should detect orphaned symlink");

    Ok(())
});

integration_test!(test_validate_corrupt_tar_split, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create layer from tar
    let mut tar_buffer = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buffer);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("test")?;
        header.set_mode(0o755);
        header.set_size(0);
        header.set_cksum();
        builder.append(&header, std::io::empty())?;
        builder.finish()?;
    }

    let diff_digest: oci_spec::image::Digest =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".parse()?;
    let layer = layer_store.create_layer_from_tar(
        None,
        None,
        &[],
        tar_buffer.as_slice(),
        &diff_digest,
        &diff_digest,
        0,
    )?;

    // Corrupt the tar-split file
    let tar_split_path = storage
        .root_path()
        .join("overlay-layers")
        .join(format!("{}.tar-split.gz", layer.id));
    std::fs::write(&tar_split_path, b"not a gzip file")?;

    // Enable tar-split verification
    let options = ValidateOptions {
        verify_tar_split: true,
        ..Default::default()
    };
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    let has_corrupt = result.errors.iter().any(
        |e| matches!(e, ValidationError::CorruptTarSplit { layer_id, .. } if layer_id == &layer.id),
    );
    assert!(has_corrupt, "should detect corrupt tar-split");

    Ok(())
});

integration_test!(test_validate_multiple_errors, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create two layers
    let layer1 = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let layer2 = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;

    // Corrupt both
    let diff1 = storage.overlay_path().join(&layer1.id).join("diff");
    let link2 = storage.overlay_path().join(&layer2.id).join("link");
    std::fs::remove_dir(&diff1)?;
    std::fs::remove_file(&link2)?;

    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.has_errors());
    assert!(result.errors.len() >= 2, "should detect multiple errors");

    Ok(())
});

integration_test!(test_validate_layer_chain, || {
    let storage = TestStorage::new()?;
    let layer_store = storage.storage().layer_store();

    // Create a chain of layers
    let base = layer_store.create_layer(None, None, &[], None::<std::io::Empty>)?;
    let middle = layer_store.create_layer(None, Some(&base.id), &[], None::<std::io::Empty>)?;
    let _top = layer_store.create_layer(None, Some(&middle.id), &[], None::<std::io::Empty>)?;

    // Validation should pass for a valid chain
    let options = ValidateOptions::default();
    let result = storage.storage().validate(&options)?;

    assert!(result.is_ok(), "valid layer chain should pass validation");
    assert_eq!(result.stats.layers_checked, 3);

    Ok(())
});
