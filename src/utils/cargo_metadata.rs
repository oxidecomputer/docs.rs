use crate::error::Result;
use anyhow::{anyhow, bail, Context};
use rustwide::{cmd::Command, Toolchain, Workspace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::trace;

pub(crate) struct CargoWorkspace {
    pub(crate) meta: DeserializedMetadata,
}

impl CargoWorkspace {
    pub(crate) fn load_from_rustwide(
        workspace: &Workspace,
        toolchain: &Toolchain,
        source_dir: &Path,
    ) -> Result<Self> {
        let res = Command::new(workspace, toolchain.cargo())
            .args(&["metadata", "--format-version", "1"])
            .cd(source_dir)
            .log_output(false)
            .run_capture()?;
        let [metadata] = res.stdout_lines() else {
            bail!("invalid output returned by `cargo metadata`")
        };

        Ok(Self {
            meta: serde_json::from_str::<DeserializedMetadata>(metadata)?,
        })
    }
}

pub(crate) struct CargoMetadata {
    root: Package,
}

impl CargoMetadata {
    pub(crate) fn load_from_rustwide(
        workspace: &Workspace,
        toolchain: &Toolchain,
        source_dir: &Path,
        root_name: Option<&str>,
    ) -> Result<Self> {
        let res = Command::new(workspace, toolchain.cargo())
            .args(&["metadata", "--format-version", "1"])
            .cd(source_dir)
            .log_output(false)
            .run_capture()?;
        let [metadata] = res.stdout_lines() else {
            bail!("invalid output returned by `cargo metadata`")
        };
        Self::load_from_metadata(metadata, root_name)
    }

    #[cfg(test)]
    pub(crate) fn load_from_host_path(source_dir: &Path, root_name: Option<&str>) -> Result<Self> {
        let res = std::process::Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--offline"])
            .current_dir(source_dir)
            .output()?;
        let status = res.status;
        if !status.success() {
            let stderr = std::str::from_utf8(&res.stderr).unwrap_or("");
            bail!("error returned by `cargo metadata`: {status}\n{stderr}")
        }
        Self::load_from_metadata(std::str::from_utf8(&res.stdout)?, root_name)
    }

    pub(crate) fn load_from_metadata(metadata: &str, root_name: Option<&str>) -> Result<Self> {
        let metadata = serde_json::from_str::<DeserializedMetadata>(metadata)?;
        let root = match root_name {
            Some(root_name) => metadata
                .workspace_members
                .iter()
                .find(|member| {
                    trace!(member = ?member.name(), ?root_name, "Test workspace member for root");
                    member.name() == Some(&root_name)
                })
                .ok_or_else(|| anyhow!("Failed to find workspace member for {}", root_name))?
                .value(),
            None => metadata
                .resolve
                .root
                .as_ref()
                .ok_or_else(|| anyhow!("Missing default root"))?,
        };

        let mut root_package = metadata
            .packages
            .into_iter()
            .find(|pkg| &pkg.id == root)
            .context("metadata.packages missing root package")?;

        // Reduce down the package targets to only the requested root
        if let Some(root_name) = root_name {
            root_package
                .targets
                .retain(|target| target.name == root_name);
        }

        Ok(CargoMetadata { root: root_package })
    }

    pub(crate) fn root(&self) -> &Package {
        &self.root
    }

    pub(crate) fn root_mut(&mut self) -> &mut Package {
        &mut self.root
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) license: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) homepage: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) documentation: Option<String>,
    pub(crate) dependencies: Vec<Dependency>,
    pub(crate) targets: Vec<Target>,
    pub(crate) readme: Option<String>,
    pub(crate) keywords: Vec<String>,
    pub(crate) features: HashMap<String, Vec<String>>,
}

impl Package {
    fn library_target(&self) -> Option<&Target> {
        self.targets
            .iter()
            .find(|target| target.crate_types.iter().any(|kind| kind != "bin"))
    }

    pub(crate) fn is_library(&self) -> bool {
        self.library_target().is_some()
    }

    fn normalize_package_name(&self, name: &str) -> String {
        name.replace('-', "_")
    }

    pub(crate) fn package_name(&self) -> String {
        self.library_name()
            .unwrap_or_else(|| self.normalize_package_name(&self.targets[0].name))
    }

    pub(crate) fn library_name(&self) -> Option<String> {
        self.library_target()
            .map(|target| self.normalize_package_name(&target.name))
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Target {
    pub(crate) name: String,
    #[cfg(not(test))]
    crate_types: Vec<String>,
    #[cfg(test)]
    pub(crate) crate_types: Vec<String>,
    pub(crate) src_path: Option<String>,
}

impl Target {
    #[cfg(test)]
    pub(crate) fn dummy_lib(name: String, src_path: Option<String>) -> Self {
        Target {
            name,
            crate_types: vec!["lib".into()],
            src_path,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Dependency {
    pub(crate) name: String,
    pub(crate) req: String,
    pub(crate) kind: Option<String>,
    pub(crate) rename: Option<String>,
    pub(crate) optional: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeserializedMetadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) resolve: DeserializedResolve,
    pub(crate) workspace_members: Vec<WorkspaceMember>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DeserializedResolve {
    pub(crate) root: Option<String>,
    pub(crate) nodes: Vec<DeserializedResolveNode>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DeserializedResolveNode {
    pub(crate) id: String,
    pub(crate) deps: Vec<DeserializedResolveDep>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct DeserializedResolveDep {
    pub(crate) pkg: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WorkspaceMember(String);

impl WorkspaceMember {
    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> Option<&str> {
        self.0.split(' ').nth(0)
    }
}
