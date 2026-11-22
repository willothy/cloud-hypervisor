// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::{io, result};

use anyhow::anyhow;
use serde::de::DeserializeOwned;
use thiserror::Error;
use vm_migration::{MigratableError, Snapshot};

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
use crate::coredump::GuestDebuggableError;
use crate::vm::VmSnapshot;
use crate::vm_config::VmConfig;

pub(crate) mod transport;
pub(crate) mod worker;

pub const SNAPSHOT_STATE_FILE: &str = "state.json";
pub const SNAPSHOT_CONFIG_FILE: &str = "config.json";

pub fn url_to_path(url: &str) -> result::Result<PathBuf, MigratableError> {
    let path: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            MigratableError::MigrateSend(anyhow!("Could not extract path from URL: {url}"))
        })
        .map(|s| s.into())?;

    if !path.is_dir() {
        return Err(MigratableError::MigrateSend(anyhow!(
            "Destination is not a directory: {path:?}"
        )));
    }

    Ok(path)
}

#[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
pub fn url_to_file(url: &str) -> result::Result<PathBuf, GuestDebuggableError> {
    let file: PathBuf = url
        .strip_prefix("file://")
        .ok_or_else(|| {
            GuestDebuggableError::Coredump(anyhow!("Could not extract file from URL: {url}"))
        })
        .map(|s| s.into())?;

    Ok(file)
}

/// Why a snapshot's config, state, or the VM's section of its state
/// couldn't be read.
#[derive(Debug, Error)]
pub enum RecvError {
    #[error("Invalid snapshot source URL")]
    SourceUrl(#[source] MigratableError),
    #[error("Error opening snapshot file {}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Error reading snapshot file {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Error deserialising snapshot file {}", path.display())]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("Could not find VM config snapshot section")]
    MissingSection,
    #[error("Error deserialising VM config snapshot section")]
    DecodeSection(#[source] MigratableError),
}

/// Reads and decodes `file` in the snapshot directory `source_url` names.
fn recv_snapshot_file<T: DeserializeOwned>(
    source_url: &str,
    file: &str,
) -> result::Result<T, RecvError> {
    let mut path = url_to_path(source_url).map_err(RecvError::SourceUrl)?;
    path.push(file);

    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|source| RecvError::Open {
            path: path.clone(),
            source,
        })?
        .read_to_end(&mut bytes)
        .map_err(|source| RecvError::Read {
            path: path.clone(),
            source,
        })?;

    serde_json::from_slice(&bytes).map_err(|source| RecvError::Decode { path, source })
}

pub fn recv_vm_config(source_url: &str) -> result::Result<VmConfig, RecvError> {
    recv_snapshot_file(source_url, SNAPSHOT_CONFIG_FILE)
}

pub fn recv_vm_state(source_url: &str) -> result::Result<Snapshot, RecvError> {
    recv_snapshot_file(source_url, SNAPSHOT_STATE_FILE)
}

pub fn get_vm_snapshot(snapshot: &Snapshot) -> result::Result<VmSnapshot, RecvError> {
    snapshot
        .snapshot_data
        .as_ref()
        .ok_or(RecvError::MissingSection)?
        .to_state()
        .map_err(RecvError::DecodeSection)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    #[test]
    fn test_recv_vm_state_reports_each_failure_typed() {
        let dir = TempDir::new_with_prefix("/tmp/recv-snapshot-").unwrap();
        let url = format!("file://{}", dir.as_path().display());

        assert!(matches!(
            recv_vm_state("/not/a/file/url"),
            Err(RecvError::SourceUrl(_))
        ));
        assert!(matches!(
            recv_vm_state(&url),
            Err(RecvError::Open { source, .. }) if source.kind() == io::ErrorKind::NotFound
        ));

        let state = dir.as_path().join(SNAPSHOT_STATE_FILE);
        fs::create_dir(&state).unwrap();
        assert!(matches!(recv_vm_state(&url), Err(RecvError::Read { .. })));
        fs::remove_dir(&state).unwrap();

        fs::write(&state, b"{").unwrap();
        assert!(matches!(recv_vm_state(&url), Err(RecvError::Decode { .. })));

        fs::write(&state, br#"{"snapshot_data":null,"snapshots":{}}"#).unwrap();
        let snapshot = recv_vm_state(&url).unwrap();
        assert!(matches!(
            get_vm_snapshot(&snapshot),
            Err(RecvError::MissingSection)
        ));
    }
}
