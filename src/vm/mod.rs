// SPDX-License-Identifier: GPL-3.0-only
//! Safe Rust VM Core for Kilox (`j2me-vm`).
//!
//! Owns all recoverable execution state inside isolated `VmContext` instances
//! under `#![forbid(unsafe_code)]`: edition contracts (`CLDC 1.0/1.1`,
//! `MIDP 1.0/2.0/2.1`), legacy `StackMap` verification, context-local class
//! loading, generational handle heap + GC, preemptive virtual threads +
//! monitors, and atomic cross-process snapshots.

pub mod heap;
pub mod interpreter;
pub mod loader;
pub mod profile;
pub mod scheduler;
pub mod snapshot;
pub mod value;
pub mod verifier;

use crate::archive::{ArchiveError, PackageArchive};

pub use heap::{ArrayKind, ArrayStorage, GcStats, Heap, HeapError};
pub use loader::{ClassInitState, ClassLoader, LoaderError};
pub use profile::{CldcVersion, HeapBudget, MidpVersion, ProfileContract};
pub use scheduler::{Frame, MonitorError, Scheduler, SchedulerError, ThreadState, VirtualThread};
pub use snapshot::SnapshotError;
pub use value::{ClassId, FieldType, Handle, MethodDescriptor, Slot, ThreadId, Value};
pub use verifier::{DecodedMethod, StackMapFrame, VerificationType, VerifyError, VerifyErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    Loader(LoaderError),
    Heap(HeapError),
    Scheduler(SchedulerError),
    Snapshot(SnapshotError),
    Archive(ArchiveError),
    StackOverflow,
    StaleTimelineEpoch { expected: u64, got: u64 },
    InternalState(&'static str),
}

impl From<LoaderError> for VmError {
    fn from(e: LoaderError) -> Self {
        Self::Loader(e)
    }
}

impl From<HeapError> for VmError {
    fn from(e: HeapError) -> Self {
        Self::Heap(e)
    }
}

impl From<SchedulerError> for VmError {
    fn from(e: SchedulerError) -> Self {
        Self::Scheduler(e)
    }
}

impl From<SnapshotError> for VmError {
    fn from(e: SnapshotError) -> Self {
        Self::Snapshot(e)
    }
}

impl From<ArchiveError> for VmError {
    fn from(e: ArchiveError) -> Self {
        Self::Archive(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmStep {
    Advanced {
        thread: ThreadId,
        pc: u16,
    },
    Blocked {
        thread: ThreadId,
    },
    ThreadReturned {
        thread: ThreadId,
        value: Option<Value>,
    },
    UncaughtException {
        thread: ThreadId,
        exception: Handle,
    },
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmStatus {
    pub loaded_classes: usize,
    pub live_objects: usize,
    pub active_thread: Option<ThreadId>,
    pub virtual_time_ms: u64,
    pub total_instructions: u64,
    pub timeline_epoch: u64,
}

/// Self-contained, host-neutral Safe Rust JVM instance.
/// No process-global state is shared across `VmContext` instances.
#[derive(Debug, Clone)]
pub struct VmContext {
    pub profile: ProfileContract,
    pub loader: ClassLoader,
    pub heap: Heap,
    pub scheduler: Scheduler,
    pub timeline_epoch: u64,
    pub next_host_request_id: u64,
}

impl VmContext {
    pub fn new(profile: ProfileContract) -> Self {
        let loader = ClassLoader::new(&profile);
        let heap = Heap::new(profile.budget);
        let scheduler = Scheduler::new(
            profile.budget.max_threads,
            profile.budget.instruction_quantum,
        );
        Self {
            profile,
            loader,
            heap,
            scheduler,
            timeline_epoch: 1,
            next_host_request_id: 1,
        }
    }

    pub fn status(&self) -> VmStatus {
        VmStatus {
            loaded_classes: self.loader.class_count(),
            live_objects: self.heap.live_objects(),
            active_thread: self.scheduler.active_thread(),
            virtual_time_ms: self.scheduler.virtual_time_ms(),
            total_instructions: self.scheduler.total_instructions(),
            timeline_epoch: self.timeline_epoch,
        }
    }

    /// Loads, verifies, and prepares a single `.class` binary under this VM's `ProfileContract`.
    pub fn load_class(&mut self, class_bytes: &[u8]) -> Result<ClassId, VmError> {
        Ok(self
            .loader
            .load_class_bytes(class_bytes, &self.profile, &mut self.heap)?)
    }

    /// Loads all `.class` entries from a validated `PackageArchive` (JAR).
    pub fn load_archive(&mut self, archive: &PackageArchive<'_>) -> Result<Vec<ClassId>, VmError> {
        let mut loaded = Vec::new();
        for name in archive.names() {
            if name.ends_with(".class") {
                if let Some(bytes) = archive.read(name)? {
                    loaded.push(self.load_class(bytes.as_ref())?);
                }
            }
        }
        Ok(loaded)
    }

    /// Spawns a new virtual thread invoking a static method (`class_name.method_name(descriptor)`).
    pub fn spawn_static(
        &mut self,
        thread_name: &str,
        priority: u8,
        class_name: &str,
        method_name: &str,
        descriptor: &str,
        args: &[Value],
    ) -> Result<ThreadId, VmError> {
        let class_id = self
            .loader
            .find_class(class_name)
            .ok_or_else(|| LoaderError::NoClassDefFound(class_name.to_string()))?;
        let (resolved_cls, method_idx) = self
            .loader
            .resolve_method(class_id, method_name, descriptor)
            .ok_or_else(|| LoaderError::NoSuchMethod {
                class: class_name.to_string(),
                name: method_name.to_string(),
                descriptor: descriptor.to_string(),
            })?;

        let (max_locals, max_stack, params) = {
            let cls = self
                .loader
                .class(resolved_cls)
                .ok_or(VmError::InternalState("missing resolved class"))?;
            let m = &cls.methods[method_idx];
            if !m.is_static() {
                return Err(VmError::Loader(LoaderError::IncompatibleClassChange(
                    "entry method must be static",
                )));
            }
            let code = m
                .code
                .as_ref()
                .ok_or(VmError::InternalState("entry method has no code"))?;
            (
                code.max_locals as usize,
                code.max_stack as usize,
                m.parsed_descriptor.params.clone(),
            )
        };

        if args.len() != params.len() {
            return Err(VmError::InternalState("entry argument count mismatch"));
        }

        let mut frame = Frame::new(resolved_cls, method_idx, max_locals, max_stack, None);
        let mut slot = 0usize;
        for (ty, &val) in params.iter().zip(args.iter()) {
            frame.set_local_value(slot, val);
            slot += if ty.is_category2() { 2 } else { 1 };
        }
        Ok(self
            .scheduler
            .spawn(thread_name.to_string(), priority, frame)?)
    }

    /// Executes one guest bytecode instruction on the next scheduled virtual thread.
    pub fn step(&mut self) -> Result<VmStep, VmError> {
        let Some(tid) = self.scheduler.select_runnable() else {
            return Ok(VmStep::Idle);
        };
        interpreter::step_thread(self, tid)
    }

    /// Executes up to `instruction_budget` guest instructions across all runnable threads.
    pub fn run(&mut self, instruction_budget: usize) -> Result<VmStep, VmError> {
        let mut last = VmStep::Idle;
        for _ in 0..instruction_budget {
            last = self.step()?;
            match last {
                VmStep::Idle | VmStep::UncaughtException { .. } => return Ok(last),
                VmStep::ThreadReturned { .. } => {
                    if self.scheduler.select_runnable().is_none() {
                        return Ok(last);
                    }
                }
                VmStep::Advanced { .. } | VmStep::Blocked { .. } => {}
            }
        }
        Ok(last)
    }

    /// Advances the VM's deterministic virtual clock and wakes due timers/sleepers.
    pub fn advance_time_ms(&mut self, delta_ms: u64) {
        self.scheduler.advance_virtual_time(delta_ms);
    }

    /// Validates a host completion's timeline epoch before resuming a host-blocked thread.
    pub fn complete_host_request(
        &mut self,
        tid: ThreadId,
        request_id: u64,
        epoch: u64,
        result: Option<Value>,
    ) -> Result<(), VmError> {
        if epoch != self.timeline_epoch {
            return Err(VmError::StaleTimelineEpoch {
                expected: self.timeline_epoch,
                got: epoch,
            });
        }
        let thread = self
            .scheduler
            .thread_mut(tid)
            .ok_or(SchedulerError::ThreadNotFound)?;
        match thread.state {
            ThreadState::BlockedOnHost {
                request_id: expected_id,
                epoch: expected_epoch,
            } if expected_id == request_id && expected_epoch == epoch => {
                if let Some(val) = result {
                    if let Some(frame) = thread.frames.last_mut() {
                        frame.push_value(val);
                    }
                }
                thread.state = ThreadState::Runnable;
                self.scheduler.run_queue.push_back(tid);
                Ok(())
            }
            _ => Err(VmError::InternalState(
                "thread not waiting for this host request",
            )),
        }
    }

    /// Runs stop-the-world Mark-Sweep GC at the current global safepoint.
    pub fn collect_garbage(&mut self) -> (usize, usize) {
        let mut roots = Vec::new();
        self.loader.collect_gc_roots(&mut roots);
        self.scheduler.collect_gc_roots(&mut roots);
        self.heap.collect_garbage(&roots)
    }

    /// Captures a bounded, versioned snapshot of all VM-owned execution state.
    pub fn checkpoint(&self) -> Vec<u8> {
        snapshot::encode_snapshot(self)
    }

    /// Atomically validates and restores a snapshot into this `VmContext`.
    pub fn restore(&mut self, bytes: &[u8]) -> Result<(), VmError> {
        snapshot::restore_snapshot(self, bytes)?;
        Ok(())
    }
}
