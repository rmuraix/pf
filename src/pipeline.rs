//! Worker threads: `capture → (parser + aggregator) → shared state → UI`.
//!
//! * The capture thread only reads packets and hands them over through a
//!   bounded channel. It never touches the UI, so a slow terminal cannot make
//!   it lose packets. If the processing thread falls behind, the channel
//!   fills, capture blocks, and the loss shows up as kernel drops in
//!   libpcap's statistics ([`CaptureInfo::kernel_dropped`]); nothing is
//!   discarded in user space.
//! * The processing thread parses frames (a cheap, stateless step that needs
//!   no thread of its own) and aggregates them into [`Aggregator`] in
//!   batches. It also expires idle flows when no packets arrive.
//! * The UI reads the aggregator through [`Shared`], holding its lock only
//!   long enough to copy a snapshot.

use std::any::Any;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crate::aggregate::{Aggregator, Limits, Snapshot};
use crate::capture::{Capture, StopHandle};
use crate::flow::{FlowDetail, FlowId};
use crate::frame::CapturedFrame;
use crate::parser::Parser;

/// Frames buffered between capture and processing. Bounds memory to a few
/// MB for typical frames (loopback can deliver 64 KiB frames).
const CHANNEL_CAPACITY: usize = 512;
/// Most frames aggregated under a single lock acquisition.
const BATCH: usize = 256;
/// How long the processing thread waits for a frame before doing housekeeping.
const IDLE_POLL: Duration = Duration::from_millis(250);
const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
const STATS_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureStatus {
    Running,
    /// Capture ended without an error.
    Stopped,
    Failed(String),
}

impl fmt::Display for CaptureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("capturing"),
            Self::Stopped => f.write_str("stopped"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

/// State of the capture side, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInfo {
    pub interface: Arc<str>,
    pub status: CaptureStatus,
    /// Packets libpcap dropped because this program was too slow.
    pub kernel_dropped: u64,
    /// Packets dropped by the interface or driver.
    pub interface_dropped: u64,
}

/// Everything the UI shows, taken at one moment.
#[derive(Debug, Clone)]
pub struct LiveData {
    pub snapshot: Snapshot,
    pub capture: CaptureInfo,
}

/// State shared between the workers and the UI.
pub struct Shared {
    interface: Arc<str>,
    aggregator: Mutex<Aggregator>,
    status: Mutex<CaptureStatus>,
    kernel_dropped: AtomicU64,
    interface_dropped: AtomicU64,
    shutdown: AtomicBool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A worker that panicked mid-update is reported through the capture
    // status; the data is still the best thing to show.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    pub fn new(interface: &str, limits: Limits) -> Self {
        Self {
            interface: Arc::from(interface),
            aggregator: Mutex::new(Aggregator::new(limits)),
            status: Mutex::new(CaptureStatus::Running),
            kernel_dropped: AtomicU64::new(0),
            interface_dropped: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn live(&self) -> LiveData {
        let snapshot = lock(&self.aggregator).snapshot(SystemTime::now());
        LiveData {
            snapshot,
            capture: self.capture_info(),
        }
    }

    pub fn capture_info(&self) -> CaptureInfo {
        CaptureInfo {
            interface: Arc::clone(&self.interface),
            status: lock(&self.status).clone(),
            kernel_dropped: self.kernel_dropped.load(Ordering::Relaxed),
            interface_dropped: self.interface_dropped.load(Ordering::Relaxed),
        }
    }

    /// `None` if the flow has expired or been evicted.
    pub fn flow_detail(&self, id: FlowId) -> Option<FlowDetail> {
        lock(&self.aggregator).flow_detail(id, SystemTime::now())
    }

    /// Runs `f` on the aggregator, e.g. to feed it directly in tests.
    pub fn with_aggregator<R>(&self, f: impl FnOnce(&mut Aggregator) -> R) -> R {
        f(&mut lock(&self.aggregator))
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    fn set_status(&self, status: CaptureStatus) {
        *lock(&self.status) = status;
    }

    #[cfg(test)]
    pub(crate) fn set_dropped(&self, kernel: u64, interface: u64) {
        self.kernel_dropped.store(kernel, Ordering::Relaxed);
        self.interface_dropped.store(interface, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn fail(&self, reason: &str) {
        self.set_status(CaptureStatus::Failed(reason.into()));
    }
}

/// Asks the pipeline to stop from any thread, e.g. a signal handler. It also
/// wakes the capture thread if it is blocked on an idle interface.
#[derive(Clone)]
pub struct Stopper {
    shared: Arc<Shared>,
    capture: Arc<StopHandle>,
}

impl Stopper {
    pub fn stop(&self) {
        self.shared.request_shutdown();
        self.capture.stop();
    }
}

pub struct Pipeline {
    shared: Arc<Shared>,
    stopper: Stopper,
    capture: Option<JoinHandle<()>>,
    processor: Option<JoinHandle<()>>,
}

impl Pipeline {
    pub fn spawn(mut cap: Capture, parser: Parser, limits: Limits) -> std::io::Result<Self> {
        let shared = Arc::new(Shared::new(cap.interface_name(), limits));
        let stopper = Stopper {
            shared: Arc::clone(&shared),
            capture: Arc::new(cap.stop_handle()),
        };
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);

        let processor = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("pf-process".into())
                .spawn(move || guarded(&shared, || process(&rx, &parser, &shared)))?
        };
        let capture = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("pf-capture".into())
                .spawn(move || guarded(&shared, || capture_loop(&mut cap, &tx, &shared)))
        };
        let capture = match capture {
            Ok(handle) => handle,
            Err(err) => {
                // The processing thread ends once `tx` is dropped with the
                // failed closure; nothing else to clean up.
                shared.request_shutdown();
                return Err(err);
            }
        };

        Ok(Self {
            shared,
            stopper,
            capture: Some(capture),
            processor: Some(processor),
        })
    }

    pub fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }

    pub fn stopper(&self) -> Stopper {
        self.stopper.clone()
    }

    /// Stops the workers, waits for them, and reports why capture failed, if
    /// it did.
    pub fn shutdown(mut self) -> anyhow::Result<()> {
        self.stopper.stop();
        for handle in [self.capture.take(), self.processor.take()]
            .into_iter()
            .flatten()
        {
            // Panics are caught inside the workers; a join error is not
            // expected, and the status below carries the failure anyway.
            let _ = handle.join();
        }
        match self.shared.capture_info().status {
            CaptureStatus::Failed(reason) => Err(anyhow::anyhow!(reason)),
            CaptureStatus::Running | CaptureStatus::Stopped => Ok(()),
        }
    }
}

impl Drop for Pipeline {
    /// Makes sure the threads wind down when `shutdown` was not reached
    /// (early return, unwinding). They are detached, not joined.
    fn drop(&mut self) {
        self.stopper.stop();
    }
}

/// Runs a worker body, turning a panic into a [`CaptureStatus::Failed`]
/// instead of tearing down the terminal UI from a background thread.
fn guarded(shared: &Shared, body: impl FnOnce()) {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(body)) {
        shared.set_status(CaptureStatus::Failed(format!(
            "internal error: {}",
            panic_message(&*payload)
        )));
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("worker panicked")
}

fn capture_loop(cap: &mut Capture, tx: &SyncSender<CapturedFrame>, shared: &Shared) {
    let mut next_stats = Instant::now();
    let result = loop {
        if shared.shutdown_requested() {
            break Ok(());
        }
        match cap.next_frame() {
            // Blocks while the processing thread is behind; see module docs.
            Ok(Some(frame)) => {
                if tx.send(frame).is_err() {
                    break Err(anyhow::anyhow!("processing thread terminated"));
                }
            }
            Ok(None) => {}
            Err(err) => break Err(err),
        }
        if Instant::now() >= next_stats {
            next_stats = Instant::now() + STATS_INTERVAL;
            if let Some(stats) = cap.stats() {
                shared
                    .kernel_dropped
                    .store(stats.dropped, Ordering::Relaxed);
                shared
                    .interface_dropped
                    .store(stats.if_dropped, Ordering::Relaxed);
            }
        }
    };
    shared.set_status(match result {
        Ok(()) => CaptureStatus::Stopped,
        Err(err) => CaptureStatus::Failed(format!("{err:#}")),
    });
}

/// Parses frames and aggregates them until the capture side hangs up.
fn process(rx: &Receiver<CapturedFrame>, parser: &Parser, shared: &Shared) {
    let mut batch = Vec::with_capacity(BATCH);
    let mut next_expire = Instant::now() + EXPIRE_INTERVAL;
    loop {
        match rx.recv_timeout(IDLE_POLL) {
            Ok(frame) => {
                batch.push(parser.observe(&frame));
                batch.extend(rx.try_iter().take(BATCH - 1).map(|f| parser.observe(&f)));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let expire = Instant::now() >= next_expire;
        if batch.is_empty() && !expire {
            continue;
        }
        shared.with_aggregator(|agg| {
            for obs in batch.drain(..) {
                agg.ingest(obs);
            }
            if expire {
                agg.expire(SystemTime::now());
            }
        });
        if expire {
            next_expire = Instant::now() + EXPIRE_INTERVAL;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::LinkType;
    use std::collections::HashSet;

    const HOST: ([u8; 4], u16) = ([10, 0, 0, 2], 40000);
    const PEER: ([u8; 4], u16) = ([1, 1, 1, 1], 53);

    /// Raw IPv4/UDP datagram from `src` to `dst` (address, port).
    fn udp_frame(src: ([u8; 4], u16), dst: ([u8; 4], u16), wire_len: usize) -> CapturedFrame {
        let mut ip = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
        ip.extend(src.0);
        ip.extend(dst.0);
        ip.extend(src.1.to_be_bytes());
        ip.extend(dst.1.to_be_bytes());
        ip.extend([0, 8, 0, 0]);
        CapturedFrame {
            timestamp: SystemTime::now(),
            interface: Arc::from("eth0"),
            link_type: LinkType::RawIp,
            original_len: wire_len,
            data: ip,
        }
    }

    fn parser() -> Parser {
        Parser::new(HashSet::from(["10.0.0.2".parse().unwrap()]), false)
    }

    #[test]
    fn processor_aggregates_until_the_sender_hangs_up() {
        let shared = Arc::new(Shared::new("eth0", Limits::default()));
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let worker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || process(&rx, &parser(), &shared))
        };

        for _ in 0..1000 {
            tx.send(udp_frame(HOST, PEER, 100)).unwrap();
            tx.send(udp_frame(PEER, HOST, 60)).unwrap();
        }
        drop(tx);
        worker.join().unwrap();

        let live = shared.live();
        assert_eq!(live.snapshot.counters.packets, 2000);
        assert_eq!(live.snapshot.counters.bytes, 1000 * 160);
        let [flow] = live.snapshot.flows.as_slice() else {
            panic!("expected one bidirectional flow");
        };
        assert_eq!(flow.bytes.outbound, 1000 * 100);
        assert_eq!(flow.bytes.inbound, 1000 * 60);
    }

    #[test]
    fn processing_does_not_depend_on_the_reader() {
        // Nobody reads snapshots while traffic flows; counters stay exact.
        let shared = Arc::new(Shared::new("eth0", Limits::default()));
        let (tx, rx) = mpsc::sync_channel(4);
        let worker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || process(&rx, &parser(), &shared))
        };
        // More frames than the channel holds: send blocks until drained.
        for _ in 0..10_000 {
            tx.send(udp_frame(HOST, PEER, 1)).unwrap();
        }
        drop(tx);
        worker.join().unwrap();
        assert_eq!(shared.live().snapshot.counters.packets, 10_000);
    }

    #[test]
    fn worker_panic_becomes_a_failed_status() {
        let shared = Shared::new("eth0", Limits::default());
        guarded(&shared, || panic!("boom"));
        assert_eq!(
            shared.capture_info().status,
            CaptureStatus::Failed("internal error: boom".into())
        );
    }

    #[test]
    fn shutdown_flag_is_sticky() {
        let shared = Shared::new("eth0", Limits::default());
        assert!(!shared.shutdown_requested());
        shared.request_shutdown();
        assert!(shared.shutdown_requested());
    }

    #[test]
    fn capture_status_text() {
        assert_eq!(CaptureStatus::Running.to_string(), "capturing");
        assert_eq!(CaptureStatus::Stopped.to_string(), "stopped");
        assert_eq!(
            CaptureStatus::Failed("no device".into()).to_string(),
            "failed: no device"
        );
    }
}
