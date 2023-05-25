use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use chrono::Utc;
use futures_util::{stream::FuturesUnordered, StreamExt, TryFutureExt};
use google_cloud_default::WithAuthExt;
use google_cloud_storage::{
    client::{Client, ClientConfig},
    http::objects::download::Range,
    http::objects::{
        delete::DeleteObjectRequest,
        get::GetObjectRequest,
        list::ListObjectsRequest,
        upload::{UploadObjectRequest, UploadType},
        Object,
    },
};
use std::io::Write;
use tokio::runtime::Runtime;
use tracing::{debug, instrument, trace, warn};

use crate::{Config, Metrics};

use super::{Blob, FileRange, StorageTransaction};

async fn client() -> Result<Client> {
    let config = ClientConfig::default().with_auth().await?;
    Ok(Client::new(config))
}

pub(super) struct GcsBackend {
    client: Client,
    runtime: Arc<Runtime>,
    bucket: String,
    metrics: Arc<Metrics>,
}

impl GcsBackend {
    pub(super) fn new(
        metrics: Arc<Metrics>,
        config: &Config,
        runtime: Arc<Runtime>,
    ) -> Result<Self> {
        Ok(Self {
            client: runtime.block_on(client())?,
            runtime,
            bucket: config
                .gcs_bucket
                .as_ref()
                .ok_or_else(|| anyhow!("GCS Bucket is not configured"))?
                .to_string(),
            metrics,
        })
    }

    #[instrument(skip(self))]
    fn meta(&self, path: &str) -> Result<Object> {
        self.runtime.block_on(async {
            debug!("Fetching meta for file");

            let response = self
                .client
                .get_object(&GetObjectRequest {
                    bucket: self.bucket.clone(),
                    object: path.to_string(),
                    ..Default::default()
                })
                .await;

            if let Err(err) = &response {
                warn!(?err, "Failed to fetch file meta");
            }

            Ok(response?)
        })
    }

    pub(super) fn exists(&self, path: &str) -> Result<bool> {
        self.meta(path).map(|_| true)
    }

    pub(super) fn get_public_access(&self, _path: &str) -> Result<bool> {
        Ok(false)
    }

    pub(super) fn set_public_access(&self, _path: &str, _public: bool) -> Result<()> {
        Ok(())
    }

    #[instrument(skip(self))]
    pub(super) fn get(
        &self,
        path: &str,
        max_size: usize,
        range: Option<FileRange>,
    ) -> Result<Blob> {
        let meta = self.meta(path)?;

        self.runtime.block_on(async {
            let request = GetObjectRequest {
                bucket: self.bucket.clone(),
                object: path.to_string(),
                ..Default::default()
            };

            trace!(?request, ?range, "Fetch file from GCS");

            let request_range = range
                .map(|range| {
                    Range(range.clone().min(), range.max())
                })
                .unwrap_or_else(Range::default);

            let mut chunks = self
                .client
                .download_streamed_object(&request, &request_range)
                .await
                .map_err(|err| {
                    warn!(?err, "Failed to start downloading streamed object");
                    err
                })?;

            let mut content = crate::utils::sized_buffer::SizedBuffer::new(max_size);

            while let Some(chunk) = chunks.next().await {
                trace!(ok = ?chunk.is_ok(), "Received chunk");
                content.write_all(&chunk?)?;
            }

            let data = content.into_inner();

            let compression = meta.metadata.as_ref().and_then(|m| m.get("CompressionAlg").and_then(|s| s.parse().ok()));
            debug!(len = ?data.len(), ?meta.content_type, ?meta.metadata, ?compression, "Downloaded data");

            Ok(Blob {
                path: path.into(),
                mime: meta.content_type.unwrap(),
                date_updated: Utc::now(),
                content: data,
                compression,
            })
        })
    }

    pub(super) fn start_storage_transaction(&self) -> GcsStorageTransaction {
        GcsStorageTransaction { gcs: self }
    }
}

pub struct GcsStorageTransaction<'a> {
    gcs: &'a GcsBackend,
}

impl<'a> StorageTransaction for GcsStorageTransaction<'a> {
    fn store_batch(&mut self, mut batch: Vec<Blob>) -> Result<()> {
        self.gcs.runtime.block_on(async {
            let requests = batch
                .iter()
                .map(|blob| {
                    let mut meta = HashMap::new();

                    if let Some(compression) = blob.compression.map(|alg| alg.to_string()) {
                        meta.insert("CompressionAlg".to_string(), compression);
                    }

                    let upload_type = UploadType::Multipart(Box::new(Object {
                        name: blob.path.clone(),
                        content_type: Some(blob.mime.clone()),
                        metadata: Some(meta),
                        ..Default::default()
                    }));
                    let req = UploadObjectRequest {
                        bucket: self.gcs.bucket.clone(),
                        ..Default::default()
                    };

                    (req, upload_type)
                })
                .collect::<Vec<_>>();

            for _ in 0..3 {
                let mut futures = FuturesUnordered::new();

                for (i, blob) in batch.drain(..).enumerate() {
                    let (req, upload_type) = requests.get(i).unwrap();

                    futures.push(
                        self.gcs
                            .client
                            .upload_object(req, blob.content.clone(), upload_type)
                            .map_ok(|_| {
                                debug!("Uploaded to GCS");
                                self.gcs.metrics.uploaded_files_total.inc();
                            })
                            .map_err(|err| {
                                warn!("Failed to upload blob to GCS: {:?}", err);
                                // Reintroduce failed blobs for a retry
                                blob
                            }),
                    );
                }

                while let Some(result) = futures.next().await {
                    // Push each failed blob back into the batch
                    if let Err(blob) = result {
                        batch.push(blob);
                    }
                }

                // If we uploaded everything in the batch, we're done
                if batch.is_empty() {
                    return Ok(());
                }
            }

            panic!("failed to upload 3 times, exiting");
        })
    }

    fn delete_prefix(&mut self, prefix: &str) -> Result<()> {
        self.gcs.runtime.block_on(async {
            let mut continuation_token = None;
            loop {
                let list = self
                    .gcs
                    .client
                    .list_objects(&ListObjectsRequest {
                        bucket: self.gcs.bucket.to_string(),
                        prefix: Some(prefix.to_string()),
                        page_token: continuation_token.take(),
                        ..Default::default()
                    })
                    .await?;

                if let Some(items) = list.items {
                    if !items.is_empty() {
                        for item in items {
                            self.gcs
                                .client
                                .delete_object(&DeleteObjectRequest {
                                    bucket: self.gcs.bucket.to_string(),
                                    object: item.name,
                                    ..Default::default()
                                })
                                .await?;
                        }
                    }
                }

                continuation_token = list.next_page_token;

                if continuation_token.is_none() {
                    return Ok(());
                }
            }
        })
    }

    fn complete(self: Box<Self>) -> Result<()> {
        Ok(())
    }
}
