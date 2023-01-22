#[macro_use]
mod macros;

use self::macros::MetricFromOpts;
use crate::{cdn, db::Pool, target::TargetAtom, BuildQueue, Config};
use anyhow::Error;
use dashmap::DashMap;
use prometheus::proto::MetricFamily;
use std::time::{Duration, Instant};

load_metric_type!(IntGauge as single);
load_metric_type!(IntCounter as single);
load_metric_type!(IntCounterVec as vec);
load_metric_type!(IntGaugeVec as vec);
load_metric_type!(HistogramVec as vec);

/// the measured times from cdn invalidations, meaning:
/// * how long an invalidation took, or
/// * how long the invalidation was queued
/// will be put into these buckets (seconds,
/// each entry is the upper bound).
/// Prometheus only gets the counts per bucket in a certain
/// time range, no exact durations.
pub const CDN_INVALIDATION_HISTOGRAM_BUCKETS: &[f64; 11] = &[
    60.0,    // 1
    120.0,   // 2
    300.0,   // 5
    600.0,   // 10
    900.0,   // 15
    1200.0,  // 20
    1800.0,  // 30
    2700.0,  // 45
    6000.0,  // 60
    12000.0, // 120
    24000.0, // 240
];

metrics! {
    pub struct Metrics {
        /// Number of crates in the build queue
        queued_crates_count: IntGauge,
        /// Number of crates in the build queue that have a positive priority
        prioritized_crates_count: IntGauge,
        /// Number of crates that failed to build
        failed_crates_count: IntGauge,
        /// Whether the build queue is locked
        queue_is_locked: IntGauge,
        /// queued crates by priority
        queued_crates_count_by_priority: IntGaugeVec["priority"],

        /// queued CDN invalidations
        queued_cdn_invalidations_by_distribution: IntGaugeVec["distribution"],

        /// The number of idle database connections
        idle_db_connections: IntGauge,
        /// The number of used database connections
        used_db_connections: IntGauge,
        /// The maximum number of database connections
        max_db_connections: IntGauge,
        /// Number of attempted and failed connections to the database
        pub(crate) failed_db_connections: IntCounter,

        /// The number of currently opened file descriptors
        #[cfg(target_os = "linux")]
        open_file_descriptors: IntGauge,
        /// The number of threads being used by docs.rs
        #[cfg(target_os = "linux")]
        running_threads: IntGauge,

        /// The traffic of various docs.rs routes
        pub(crate) routes_visited: IntCounterVec["route"],
        /// The response times of various docs.rs routes
        pub(crate) response_time: HistogramVec["route"],
        /// The time it takes to render a rustdoc page
        pub(crate) rustdoc_rendering_times: HistogramVec["step"],
        /// The time it takes to render a rustdoc redirect page
        pub(crate) rustdoc_redirect_rendering_times: HistogramVec["step"],

        /// Count of recently accessed crates
        pub(crate) recent_crates: IntGaugeVec["duration"],
        /// Count of recently accessed versions of crates
        pub(crate) recent_versions: IntGaugeVec["duration"],
        /// Count of recently accessed platforms of versions of crates
        pub(crate) recent_platforms: IntGaugeVec["duration"],

        /// Number of crates built
        pub(crate) total_builds: IntCounter,
        /// Number of builds that successfully generated docs
        pub(crate) successful_builds: IntCounter,
        /// Number of builds that generated a compiler error
        pub(crate) failed_builds: IntCounter,
        /// Number of builds that did not complete due to not being a library
        pub(crate) non_library_builds: IntCounter,

        /// Number of files uploaded to the storage backend
        pub(crate) uploaded_files_total: IntCounter,

        /// The number of attempted files that failed due to a memory limit
        pub(crate) html_rewrite_ooms: IntCounter,

        /// the number of "I'm feeling lucky" searches for crates
        pub(crate) im_feeling_lucky_searches: IntCounter,
    }

    // The Rust prometheus library treats the namespace as the "prefix" of the metric name: a
    // metric named `foo` with a prefix of `docsrs` will expose a metric called `docsrs_foo`.
    //
    // https://docs.rs/prometheus/0.9.0/prometheus/struct.Opts.html#structfield.namespace
    namespace: "docsrs",
}

/// Converts a `Duration` to seconds, used by prometheus internally
#[inline]
pub(crate) fn duration_to_seconds(d: Duration) -> f64 {
    let nanos = f64::from(d.subsec_nanos()) / 1e9;
    d.as_secs() as f64 + nanos
}

#[derive(Debug, Default)]
pub(crate) struct RecentlyAccessedReleases {
    crates: DashMap<i32, Instant>,
    versions: DashMap<i32, Instant>,
    platforms: DashMap<(i32, TargetAtom), Instant>,
}

impl RecentlyAccessedReleases {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record(&self, krate: i32, version: i32, target: &str) {
        if self.platforms.len() > 100_000 {
            // Avoid filling the maps _too_ much, we should never get anywhere near this limit
            return;
        }

        let now = Instant::now();
        self.crates.insert(krate, now);
        self.versions.insert(version, now);
        self.platforms
            .insert((version, TargetAtom::from(target)), now);
    }

    pub(crate) fn gather(&self, metrics: &Metrics) {
        fn inner<K: std::hash::Hash + Eq>(map: &DashMap<K, Instant>, metric: &IntGaugeVec) {
            let mut hour_count = 0;
            let mut half_hour_count = 0;
            let mut five_minute_count = 0;
            map.retain(|_, instant| {
                let elapsed = instant.elapsed();

                if elapsed < Duration::from_secs(60 * 60) {
                    hour_count += 1;
                }
                if elapsed < Duration::from_secs(30 * 60) {
                    half_hour_count += 1;
                }
                if elapsed < Duration::from_secs(5 * 60) {
                    five_minute_count += 1;
                }

                // Only retain items accessed within the last hour
                elapsed < Duration::from_secs(60 * 60)
            });

            metric.with_label_values(&["one hour"]).set(hour_count);

            metric
                .with_label_values(&["half hour"])
                .set(half_hour_count);

            metric
                .with_label_values(&["five minutes"])
                .set(five_minute_count);
        }

        inner(&self.crates, &metrics.recent_crates);
        inner(&self.versions, &metrics.recent_versions);
        inner(&self.platforms, &metrics.recent_platforms);
    }
}

impl Metrics {
    pub(crate) fn gather(
        &self,
        pool: &Pool,
        queue: &BuildQueue,
        config: &Config,
    ) -> Result<Vec<MetricFamily>, Error> {
        self.idle_db_connections.set(pool.idle_connections() as i64);
        self.used_db_connections.set(pool.used_connections() as i64);
        self.max_db_connections.set(pool.max_size() as i64);
        self.queue_is_locked.set(queue.is_locked()? as i64);

        self.queued_crates_count.set(queue.pending_count()? as i64);
        self.prioritized_crates_count
            .set(queue.prioritized_count()? as i64);

        let queue_pending_count = queue.pending_count_by_priority()?;

        for (priority, count) in queue_pending_count.iter() {
            self.queued_crates_count_by_priority
                .with_label_values(&[&priority.to_string()])
                .set(*count as i64);
        }

        let mut conn = pool.get()?;
        for (distribution_id, count) in
            cdn::queued_or_active_crate_invalidation_count_by_distribution(&mut *conn, config)?
        {
            self.queued_cdn_invalidations_by_distribution
                .with_label_values(&[&distribution_id])
                .set(count);
        }

        self.failed_crates_count.set(queue.failed_count()? as i64);

        self.recently_accessed_releases.gather(self);
        self.gather_system_performance();
        Ok(self.registry.gather())
    }

    #[cfg(not(target_os = "linux"))]
    fn gather_system_performance(&self) {}

    #[cfg(target_os = "linux")]
    fn gather_system_performance(&self) {
        use procfs::process::Process;

        let process = Process::myself().unwrap();
        self.open_file_descriptors
            .set(process.fd_count().unwrap() as i64);
        self.running_threads
            .set(process.stat().unwrap().num_threads);
    }
}
