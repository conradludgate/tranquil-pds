use crate::repo_ops::{CommitError, delete_record_internal, put_record_internal};
use crate::state::AppState;
use crate::types::{Did, Nsid, Rkey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::Instrument;
use tranquil_config::GitOpsSourceConfig;
use tranquil_db_traits::{GitOpsRecord, GitOpsRepository, GitOpsSource};

#[derive(Debug)]
struct ScanError(String);

impl Display for ScanError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug)]
struct DesiredRecord {
    path: String,
    collection: Nsid,
    rkey: Rkey,
    value: serde_json::Value,
    content_hash: String,
}

pub fn start_service(state: AppState) -> Option<JoinHandle<()>> {
    let cfg = tranquil_config::get();
    let sources: Vec<GitOpsSourceConfig> = cfg
        .gitops
        .sources
        .iter()
        .filter_map(|spec| match GitOpsSourceConfig::parse(spec) {
            Ok(source) => Some(source),
            Err(error) => {
                tracing::error!(spec, error, "invalid GitOps source configuration");
                None
            }
        })
        .collect();

    if sources.is_empty() {
        return None;
    }

    let Some(repository) = state.repos.gitops.clone() else {
        tracing::warn!(
            "GitOps sources are configured but the active storage backend does not support GitOps ownership tracking"
        );
        return None;
    };

    let interval = Duration::from_secs(cfg.gitops.scan_interval_secs.max(1));
    Some(tokio::spawn(run_service(
        state, repository, sources, interval,
    )))
}

async fn run_service(
    state: AppState,
    repository: Arc<dyn GitOpsRepository>,
    sources: Vec<GitOpsSourceConfig>,
    interval: Duration,
) {
    tracing::info!(
        sources = sources.len(),
        interval_secs = interval.as_secs(),
        "GitOps reconciliation enabled"
    );

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => {
                tracing::info!("GitOps reconciliation shutting down");
                return;
            }
            _ = ticker.tick() => {
                // Keep source scans serialized. Besides avoiding unnecessary
                // SQLite write contention, this makes ownership claims for
                // multiple sources targeting the same DID deterministic.
                for source in &sources {
                    let span = tracing::info_span!(
                        "gitops.source_scan",
                        source = %source.name,
                        did = %source.did,
                    );
                    scan_source(state.clone(), repository.clone(), source.clone())
                        .instrument(span)
                        .await;
                }
            }
        }
    }
}

async fn scan_source(
    state: AppState,
    repository: Arc<dyn GitOpsRepository>,
    config: GitOpsSourceConfig,
) {
    let started = std::time::Instant::now();
    let did = match Did::new(config.did.clone()) {
        Ok(did) => did,
        Err(error) => {
            tracing::error!(source = %config.name, error = %error, "invalid GitOps source DID");
            crate::metrics::record_gitops_scan(
                &config.name,
                "invalid_config",
                0,
                started.elapsed().as_secs_f64(),
            );
            return;
        }
    };
    let source = match repository
        .ensure_source(&config.name, &config.path, &did)
        .await
    {
        Ok(source) => source,
        Err(error) => {
            tracing::error!(source = %config.name, error = %error, "failed to register GitOps source");
            crate::metrics::record_gitops_scan(
                &config.name,
                "registration_error",
                0,
                started.elapsed().as_secs_f64(),
            );
            return;
        }
    };

    let root = PathBuf::from(&config.path);
    let snapshot = match tokio::task::spawn_blocking(move || scan_directory(&root)).await {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(error)) => {
            record_scan_error(&repository, &source, &error.to_string()).await;
            crate::metrics::record_gitops_scan(
                &source.name,
                "scan_error",
                0,
                started.elapsed().as_secs_f64(),
            );
            return;
        }
        Err(error) => {
            record_scan_error(
                &repository,
                &source,
                &format!("scanner task failed: {error}"),
            )
            .await;
            crate::metrics::record_gitops_scan(
                &source.name,
                "scan_error",
                0,
                started.elapsed().as_secs_f64(),
            );
            return;
        }
    };

    let record_count = snapshot.len();
    if let Err(error) = reconcile_snapshot(&state, &repository, &source, snapshot).await {
        record_scan_error(&repository, &source, &error).await;
        crate::metrics::record_gitops_scan(
            &source.name,
            "reconcile_error",
            record_count,
            started.elapsed().as_secs_f64(),
        );
        return;
    }

    if let Err(error) = repository.mark_scan(source.id, None).await {
        tracing::error!(source = %source.name, error = %error, "failed to record successful GitOps scan");
    }
    crate::metrics::record_gitops_scan(
        &source.name,
        "success",
        record_count,
        started.elapsed().as_secs_f64(),
    );
}

async fn record_scan_error(
    repository: &Arc<dyn GitOpsRepository>,
    source: &GitOpsSource,
    error: &str,
) {
    tracing::error!(source = %source.name, error, "GitOps source scan failed");
    if let Err(mark_error) = repository.mark_scan(source.id, Some(error)).await {
        tracing::error!(source = %source.name, error = %mark_error, "failed to persist GitOps scan error");
    }
}

async fn reconcile_snapshot(
    state: &AppState,
    repository: &Arc<dyn GitOpsRepository>,
    source: &GitOpsSource,
    snapshot: BTreeMap<String, DesiredRecord>,
) -> Result<(), String> {
    let existing = repository
        .list_records(source.id)
        .await
        .map_err(|error| format!("load ownership records: {error}"))?;
    let existing_by_path: HashMap<&str, &GitOpsRecord> = existing
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect();

    if let Some(record) = existing.iter().find(|record| record.did != source.did) {
        return Err(format!(
            "source {:?} was previously bound to {}, refusing to rebind it to {} while it still owns {}",
            source.name, record.did, source.did, record.path
        ));
    }

    let mut seen_identities = HashSet::new();
    for desired in snapshot.values() {
        let identity = format!("{}\0{}\0{}", source.did, desired.collection, desired.rkey);
        if !seen_identities.insert(identity) {
            return Err(format!(
                "source contains multiple files for {}/{}",
                desired.collection, desired.rkey
            ));
        }

        if let Some(claim) = repository
            .find_claim(&source.did, &desired.collection, &desired.rkey)
            .await
            .map_err(|error| format!("check ownership for {}: {error}", desired.path))?
            && (claim.source_id != source.id || claim.path != desired.path)
        {
            return Err(format!(
                "record {}/{}/{} is already claimed by another GitOps source",
                source.did, desired.collection, desired.rkey
            ));
        }
    }

    let user_id = state
        .repos
        .user
        .get_id_by_did(&source.did)
        .await
        .map_err(|error| format!("resolve target account {}: {error}", source.did))?
        .ok_or_else(|| format!("target account {} does not exist", source.did))?;

    // Complete all read-only drift checks before applying the first record so
    // one bad file cannot leave an earlier part of the snapshot half-applied.
    for desired in snapshot.values() {
        let current_cid = state
            .repos
            .repo
            .get_record_cid(user_id, &desired.collection, &desired.rkey)
            .await
            .map_err(|error| format!("read current CID for {}: {error}", desired.path))?;
        let owned = existing_by_path.get(desired.path.as_str()).copied();

        if owned.is_none() && current_cid.is_some() {
            return Err(format!(
                "record {}/{}/{} exists but is not GitOps-owned",
                source.did, desired.collection, desired.rkey
            ));
        }

        if let Some(owned) = owned
            && let (Some(expected), Some(current)) =
                (owned.record_cid.as_deref(), current_cid.as_ref())
            && expected != current.as_str()
        {
            return Err(format!(
                "record {}/{}/{} changed outside GitOps; refusing to overwrite it",
                source.did, desired.collection, desired.rkey
            ));
        }
    }

    for desired in snapshot.values() {
        let current_cid = state
            .repos
            .repo
            .get_record_cid(user_id, &desired.collection, &desired.rkey)
            .await
            .map_err(|error| format!("read current CID for {}: {error}", desired.path))?;
        let owned = existing_by_path.get(desired.path.as_str()).copied();

        if owned.is_none() && current_cid.is_some() {
            return Err(format!(
                "record {}/{}/{} exists but is not GitOps-owned",
                source.did, desired.collection, desired.rkey
            ));
        }

        if let Some(owned) = owned
            && let (Some(expected), Some(current)) =
                (owned.record_cid.as_deref(), current_cid.as_ref())
            && expected != current.as_str()
        {
            return Err(format!(
                "record {}/{}/{} changed outside GitOps; refusing to overwrite it",
                source.did, desired.collection, desired.rkey
            ));
        }

        let unchanged = owned.is_some_and(|record| {
            record.content_hash == desired.content_hash
                && record.record_cid.as_deref() == current_cid.as_ref().map(|cid| cid.as_str())
        });
        if unchanged {
            continue;
        }

        let (_, record_cid) = put_record_internal(
            state,
            &source.did,
            &desired.collection,
            &desired.rkey,
            &desired.value,
        )
        .await
        .map_err(|error| format_commit_error(&desired.path, error))?;

        repository
            .upsert_record(&GitOpsRecord {
                source_id: source.id,
                path: desired.path.clone(),
                did: source.did.clone(),
                collection: desired.collection.clone(),
                rkey: desired.rkey.clone(),
                content_hash: desired.content_hash.clone(),
                record_cid: Some(record_cid.to_string()),
            })
            .await
            .map_err(|error| format!("record ownership for {}: {error}", desired.path))?;
    }

    for record in existing {
        if snapshot.contains_key(&record.path) {
            continue;
        }

        let current_cid = state
            .repos
            .repo
            .get_record_cid(user_id, &record.collection, &record.rkey)
            .await
            .map_err(|error| format!("read current CID for {}: {error}", record.path))?;

        if let Some(current_cid) = current_cid {
            let Some(expected_cid) = record.record_cid.as_deref() else {
                return Err(format!(
                    "record {} has no recorded CID; refusing to delete it",
                    record.path
                ));
            };
            if expected_cid != current_cid.as_str() {
                return Err(format!(
                    "record {} changed outside GitOps; refusing to delete it",
                    record.path
                ));
            }

            delete_record_internal(state, &record.did, &record.collection, &record.rkey)
                .await
                .map_err(|error| format_commit_error(&record.path, error))?;
        }

        repository
            .delete_record(source.id, &record.path)
            .await
            .map_err(|error| format!("delete ownership for {}: {error}", record.path))?;
    }

    Ok(())
}

fn format_commit_error(path: &str, error: CommitError) -> String {
    format!("apply record {path}: {error}")
}

fn scan_directory(root: &Path) -> Result<BTreeMap<String, DesiredRecord>, ScanError> {
    if !root.is_dir() {
        return Err(ScanError(format!(
            "source path {} is not a directory",
            root.display()
        )));
    }

    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    let mut records = BTreeMap::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|error| ScanError(format!("relative path: {error}")))?;
        if relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("json")
        {
            continue;
        }

        let components: Vec<_> = relative.components().collect();
        if components.len() != 2 {
            return Err(ScanError(format!(
                "record file {} must be exactly collection/rkey.json",
                relative.display()
            )));
        }
        let collection = components[0].as_os_str().to_str().ok_or_else(|| {
            ScanError(format!("non-UTF-8 collection path {}", relative.display()))
        })?;
        let rkey = relative
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ScanError(format!("invalid record filename {}", relative.display())))?;
        let collection = Nsid::new(collection.to_string())
            .map_err(|error| ScanError(format!("invalid collection {collection}: {error}")))?;
        let rkey = Rkey::new(rkey.to_string())
            .map_err(|error| ScanError(format!("invalid rkey {rkey}: {error}")))?;
        let bytes = std::fs::read(&path)
            .map_err(|error| ScanError(format!("read {}: {error}", relative.display())))?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|error| ScanError(format!("parse {}: {error}", relative.display())))?;
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let content_hash = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = relative.to_string_lossy().replace('\\', "/");
        records.insert(
            path.clone(),
            DesiredRecord {
                path,
                collection,
                rkey,
                value,
                content_hash,
            },
        );
    }
    Ok(records)
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), ScanError> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| ScanError(format!("read directory {}: {error}", directory.display())))?;
    for entry in entries {
        let entry = entry.map_err(|error| ScanError(format!("read directory entry: {error}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| ScanError(format!("inspect {}: {error}", path.display())))?;
        let is_directory = file_type.is_dir() || (file_type.is_symlink() && path.is_dir());
        if is_directory {
            // Hidden directories are implementation details rather than part
            // of the GitOps source layout. This also excludes the timestamped
            // directories and symlinks used by Kubernetes ConfigMap and Secret
            // volumes.
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            collect_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scan_directory;
    use std::fs;

    #[test]
    fn scans_collection_and_rkey_files() {
        let root = tempfile::tempdir().unwrap();
        let collection = root.path().join("app.example.record");
        fs::create_dir_all(&collection).unwrap();
        fs::write(
            collection.join("abc.json"),
            br#"{"$type":"app.example.record","value":"ok"}"#,
        )
        .unwrap();
        fs::write(root.path().join("README.md"), b"ignored").unwrap();

        let snapshot = scan_directory(root.path()).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key("app.example.record/abc.json"));
    }

    #[test]
    fn malformed_json_aborts_the_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let collection = root.path().join("app.example.record");
        fs::create_dir_all(&collection).unwrap();
        fs::write(collection.join("abc.json"), b"not json").unwrap();
        assert!(scan_directory(root.path()).is_err());
    }

    #[test]
    fn ignores_hidden_directories() {
        let root = tempfile::tempdir().unwrap();
        let collection = root.path().join("app.example.record");
        fs::create_dir_all(&collection).unwrap();
        fs::write(
            collection.join("abc.json"),
            br#"{"$type":"app.example.record","value":"ok"}"#,
        )
        .unwrap();

        for directory in [".git", "..2026_08_02_19_12_01.123456789"] {
            let hidden_collection = root.path().join(directory).join("app.example.record");
            fs::create_dir_all(&hidden_collection).unwrap();
            fs::write(hidden_collection.join("invalid.json"), b"not json").unwrap();
        }

        let snapshot = scan_directory(root.path()).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key("app.example.record/abc.json"));
    }

    #[cfg(unix)]
    #[test]
    fn follows_visible_directory_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let backing = tempfile::tempdir().unwrap();
        let collection = backing.path().join("app.example.record");
        fs::create_dir_all(&collection).unwrap();
        fs::write(
            collection.join("abc.json"),
            br#"{"$type":"app.example.record","value":"ok"}"#,
        )
        .unwrap();
        symlink(&collection, root.path().join("app.example.record")).unwrap();

        let snapshot = scan_directory(root.path()).unwrap();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.contains_key("app.example.record/abc.json"));
    }
}
