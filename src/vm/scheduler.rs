// SPDX-License-Identifier: GPL-3.0-only
//! Preemptive virtual thread scheduler, VM-owned invocation frames,
//! monitor table (reentrant locks + wait/notify queues), and virtual clock.

use std::collections::{BTreeMap, VecDeque};

use super::value::{ClassId, Handle, Slot, ThreadId, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub class_id: ClassId,
    pub method_index: usize,
    /// Instruction index inside `DecodedMethod::instructions`.
    pub ip: usize,
    /// Exact bytecode PC corresponding to `ip` for exceptions and inspection.
    pub pc: u16,
    pub locals: Vec<Slot>,
    pub stack: Vec<Slot>,
    /// Monitor automatically acquired by a `synchronized` method frame.
    pub synchronized_monitor: Option<Handle>,
}

impl Frame {
    pub fn new(
        class_id: ClassId,
        method_index: usize,
        max_locals: usize,
        max_stack: usize,
        synchronized_monitor: Option<Handle>,
    ) -> Self {
        Self {
            class_id,
            method_index,
            ip: 0,
            pc: 0,
            locals: vec![Slot::Empty; max_locals],
            stack: Vec::with_capacity(max_stack.min(64)),
            synchronized_monitor,
        }
    }

    pub fn push_value(&mut self, value: Value) {
        match value {
            Value::Long(v) => {
                self.stack.push(Slot::Long(v));
                self.stack.push(Slot::Top);
            }
            Value::Double(v) => {
                self.stack.push(Slot::Double(v));
                self.stack.push(Slot::Top);
            }
            other => self.stack.push(Slot::from_value(other)),
        }
    }

    pub fn pop_slot(&mut self) -> Option<Slot> {
        self.stack.pop()
    }

    pub fn pop_int(&mut self) -> Option<i32> {
        match self.stack.pop() {
            Some(Slot::Int(v)) => Some(v),
            _ => None,
        }
    }

    pub fn pop_long(&mut self) -> Option<i64> {
        if !matches!(self.stack.pop(), Some(Slot::Top)) {
            return None;
        }
        match self.stack.pop() {
            Some(Slot::Long(v)) => Some(v),
            _ => None,
        }
    }

    pub fn pop_float(&mut self) -> Option<u32> {
        match self.stack.pop() {
            Some(Slot::Float(bits)) => Some(bits),
            _ => None,
        }
    }

    pub fn pop_double(&mut self) -> Option<u64> {
        if !matches!(self.stack.pop(), Some(Slot::Top)) {
            return None;
        }
        match self.stack.pop() {
            Some(Slot::Double(bits)) => Some(bits),
            _ => None,
        }
    }

    pub fn pop_ref(&mut self) -> Option<Option<Handle>> {
        match self.stack.pop() {
            Some(Slot::Ref(h)) => Some(h),
            _ => None,
        }
    }

    pub fn pop_value(&mut self) -> Option<Value> {
        match self.stack.pop()? {
            Slot::Top => match self.stack.pop()? {
                Slot::Long(v) => Some(Value::Long(v)),
                Slot::Double(v) => Some(Value::Double(v)),
                _ => None,
            },
            other => other.to_value(),
        }
    }

    pub fn set_local_value(&mut self, index: usize, value: Value) -> bool {
        match value {
            Value::Long(v) => {
                if index + 1 >= self.locals.len() {
                    return false;
                }
                self.locals[index] = Slot::Long(v);
                self.locals[index + 1] = Slot::Top;
                true
            }
            Value::Double(v) => {
                if index + 1 >= self.locals.len() {
                    return false;
                }
                self.locals[index] = Slot::Double(v);
                self.locals[index + 1] = Slot::Top;
                true
            }
            other => {
                if index >= self.locals.len() {
                    return false;
                }
                self.locals[index] = Slot::from_value(other);
                true
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadState {
    Runnable,
    BlockedOnMonitor(Handle),
    WaitingOnMonitor {
        handle: Handle,
        saved_recursion: u32,
        deadline_ms: Option<u64>,
    },
    Sleeping {
        deadline_ms: u64,
    },
    BlockedOnHost {
        request_id: u64,
        epoch: u64,
    },
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualThread {
    pub id: ThreadId,
    pub name: String,
    /// CLDC thread priority in `1..=10` (default `5`).
    pub priority: u8,
    pub state: ThreadState,
    pub frames: Vec<Frame>,
    pub interrupted: bool,
    pub pending_exception: Option<Handle>,
    pub last_return: Option<Value>,
    pub quantum_remaining: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorState {
    pub owner: Option<ThreadId>,
    pub recursion: u32,
    pub entry_queue: VecDeque<ThreadId>,
    pub wait_queue: VecDeque<ThreadId>,
}

impl MonitorState {
    pub fn new() -> Self {
        Self {
            owner: None,
            recursion: 0,
            entry_queue: VecDeque::new(),
            wait_queue: VecDeque::new(),
        }
    }

    pub fn is_idle(&self) -> bool {
        self.owner.is_none() && self.entry_queue.is_empty() && self.wait_queue.is_empty()
    }
}

impl Default for MonitorState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorError {
    IllegalMonitorState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    ThreadLimitExceeded,
    ThreadNotFound,
}

/// Deterministic VM-owned scheduler managing virtual threads, monitors, and
/// virtual time without OS threads or host locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scheduler {
    pub(crate) max_threads: usize,
    pub(crate) default_quantum: u32,
    pub(crate) next_thread_id: u32,
    pub(crate) threads: BTreeMap<ThreadId, VirtualThread>,
    pub(crate) run_queue: VecDeque<ThreadId>,
    pub(crate) active_thread: Option<ThreadId>,
    pub(crate) monitors: BTreeMap<Handle, MonitorState>,
    pub(crate) virtual_time_ms: u64,
    pub(crate) total_instructions: u64,
}

impl Scheduler {
    pub fn new(max_threads: usize, default_quantum: u32) -> Self {
        Self {
            max_threads,
            default_quantum: default_quantum.max(1),
            next_thread_id: 1,
            threads: BTreeMap::new(),
            run_queue: VecDeque::new(),
            active_thread: None,
            monitors: BTreeMap::new(),
            virtual_time_ms: 0,
            total_instructions: 0,
        }
    }

    pub fn virtual_time_ms(&self) -> u64 {
        self.virtual_time_ms
    }

    pub fn total_instructions(&self) -> u64 {
        self.total_instructions
    }

    pub fn active_thread(&self) -> Option<ThreadId> {
        self.active_thread
    }

    pub fn thread(&self, id: ThreadId) -> Option<&VirtualThread> {
        self.threads.get(&id)
    }

    pub fn thread_mut(&mut self, id: ThreadId) -> Option<&mut VirtualThread> {
        self.threads.get_mut(&id)
    }

    pub fn spawn(
        &mut self,
        name: String,
        priority: u8,
        initial_frame: Frame,
    ) -> Result<ThreadId, SchedulerError> {
        let live_count = self
            .threads
            .values()
            .filter(|t| t.state != ThreadState::Terminated)
            .count();
        if live_count >= self.max_threads {
            return Err(SchedulerError::ThreadLimitExceeded);
        }
        let id = ThreadId(self.next_thread_id);
        self.next_thread_id = self.next_thread_id.wrapping_add(1).max(1);
        let clamped_priority = priority.clamp(1, 10);
        let thread = VirtualThread {
            id,
            name,
            priority: clamped_priority,
            state: ThreadState::Runnable,
            frames: vec![initial_frame],
            interrupted: false,
            pending_exception: None,
            last_return: None,
            quantum_remaining: self.default_quantum,
        };
        self.threads.insert(id, thread);
        self.run_queue.push_back(id);
        Ok(id)
    }

    /// Selects the highest-priority runnable thread, applying preemptive
    /// round-robin rotation when the active thread's quantum reaches zero.
    pub fn select_runnable(&mut self) -> Option<ThreadId> {
        if let Some(active) = self.active_thread {
            if let Some(t) = self.threads.get_mut(&active) {
                if t.state == ThreadState::Runnable && t.quantum_remaining > 0 {
                    return Some(active);
                }
                if t.state == ThreadState::Runnable {
                    t.quantum_remaining = self.default_quantum;
                    self.run_queue.push_back(active);
                }
            }
            self.active_thread = None;
        }

        // Pick highest priority among runnable threads in FIFO order.
        let mut best_pos: Option<usize> = None;
        let mut best_prio: u8 = 0;
        for (idx, &tid) in self.run_queue.iter().enumerate() {
            if let Some(t) = self.threads.get(&tid) {
                if t.state == ThreadState::Runnable && t.priority > best_prio {
                    best_prio = t.priority;
                    best_pos = Some(idx);
                }
            }
        }
        let pos = best_pos?;
        let tid = self.run_queue.remove(pos)?;
        if let Some(t) = self.threads.get_mut(&tid) {
            t.quantum_remaining = self.default_quantum;
        }
        self.active_thread = Some(tid);
        Some(tid)
    }

    pub fn consume_quantum(&mut self, tid: ThreadId) {
        self.total_instructions = self.total_instructions.saturating_add(1);
        if let Some(t) = self.threads.get_mut(&tid) {
            t.quantum_remaining = t.quantum_remaining.saturating_sub(1);
        }
    }

    pub fn yield_thread(&mut self, tid: ThreadId) {
        if let Some(t) = self.threads.get_mut(&tid) {
            t.quantum_remaining = 0;
        }
    }

    pub fn sleep_thread(&mut self, tid: ThreadId, duration_ms: u64) {
        let deadline_ms = self.virtual_time_ms.saturating_add(duration_ms);
        if let Some(t) = self.threads.get_mut(&tid) {
            t.state = ThreadState::Sleeping { deadline_ms };
            t.quantum_remaining = 0;
        }
        if self.active_thread == Some(tid) {
            self.active_thread = None;
        }
    }

    pub fn advance_virtual_time(&mut self, delta_ms: u64) {
        self.virtual_time_ms = self.virtual_time_ms.saturating_add(delta_ms);
        let now = self.virtual_time_ms;
        let mut to_wake_sleep = Vec::new();
        let mut to_wake_wait = Vec::new();

        for (&tid, t) in &self.threads {
            match t.state {
                ThreadState::Sleeping { deadline_ms } if now >= deadline_ms => {
                    to_wake_sleep.push(tid);
                }
                ThreadState::WaitingOnMonitor {
                    handle,
                    saved_recursion,
                    deadline_ms: Some(deadline_ms),
                } if now >= deadline_ms => {
                    to_wake_wait.push((tid, handle, saved_recursion));
                }
                _ => {}
            }
        }

        for tid in to_wake_sleep {
            if let Some(t) = self.threads.get_mut(&tid) {
                t.state = ThreadState::Runnable;
                self.run_queue.push_back(tid);
            }
        }

        for (tid, handle, saved_recursion) in to_wake_wait {
            self.reacquire_after_wait(tid, handle, saved_recursion);
        }
    }

    /// Acquires a reentrant object monitor; returns `true` if acquired now,
    /// or `false` if the thread was blocked on the monitor's entry queue.
    pub fn monitor_enter(&mut self, tid: ThreadId, handle: Handle) -> bool {
        let entry = self.monitors.entry(handle).or_default();
        match entry.owner {
            None => {
                entry.owner = Some(tid);
                entry.recursion = 1;
                true
            }
            Some(owner) if owner == tid => {
                entry.recursion = entry.recursion.saturating_add(1);
                true
            }
            Some(_) => {
                if !entry.entry_queue.contains(&tid) {
                    entry.entry_queue.push_back(tid);
                }
                if let Some(t) = self.threads.get_mut(&tid) {
                    t.state = ThreadState::BlockedOnMonitor(handle);
                    t.quantum_remaining = 0;
                }
                if self.active_thread == Some(tid) {
                    self.active_thread = None;
                }
                false
            }
        }
    }

    /// Releases one reentrancy level of an object monitor.
    pub fn monitor_exit(&mut self, tid: ThreadId, handle: Handle) -> Result<(), MonitorError> {
        let Some(entry) = self.monitors.get_mut(&handle) else {
            return Err(MonitorError::IllegalMonitorState);
        };
        if entry.owner != Some(tid) || entry.recursion == 0 {
            return Err(MonitorError::IllegalMonitorState);
        }
        entry.recursion -= 1;
        if entry.recursion == 0 {
            entry.owner = None;
            if let Some(next_tid) = entry.entry_queue.pop_front() {
                entry.owner = Some(next_tid);
                entry.recursion = 1;
                if let Some(t) = self.threads.get_mut(&next_tid) {
                    t.state = ThreadState::Runnable;
                    self.run_queue.push_back(next_tid);
                }
            }
        }
        if self.monitors.get(&handle).is_some_and(MonitorState::is_idle) {
            self.monitors.remove(&handle);
        }
        Ok(())
    }

    /// Implements `Object.wait(timeout_ms)` semantics: releases full reentrancy
    /// and parks thread in the monitor's wait queue.
    pub fn monitor_wait(
        &mut self,
        tid: ThreadId,
        handle: Handle,
        timeout_ms: u64,
    ) -> Result<(), MonitorError> {
        let saved_recursion = {
            let Some(entry) = self.monitors.get_mut(&handle) else {
                return Err(MonitorError::IllegalMonitorState);
            };
            if entry.owner != Some(tid) || entry.recursion == 0 {
                return Err(MonitorError::IllegalMonitorState);
            }
            let saved = entry.recursion;
            entry.owner = None;
            entry.recursion = 0;
            entry.wait_queue.push_back(tid);
            if let Some(next_tid) = entry.entry_queue.pop_front() {
                entry.owner = Some(next_tid);
                entry.recursion = 1;
                if let Some(t) = self.threads.get_mut(&next_tid) {
                    t.state = ThreadState::Runnable;
                    self.run_queue.push_back(next_tid);
                }
            }
            saved
        };

        let deadline_ms = if timeout_ms > 0 {
            Some(self.virtual_time_ms.saturating_add(timeout_ms))
        } else {
            None
        };
        if let Some(t) = self.threads.get_mut(&tid) {
            t.state = ThreadState::WaitingOnMonitor {
                handle,
                saved_recursion,
                deadline_ms,
            };
            t.quantum_remaining = 0;
        }
        if self.active_thread == Some(tid) {
            self.active_thread = None;
        }
        Ok(())
    }

    pub fn monitor_notify(
        &mut self,
        tid: ThreadId,
        handle: Handle,
        all: bool,
    ) -> Result<(), MonitorError> {
        let woken: Vec<ThreadId> = {
            let Some(entry) = self.monitors.get_mut(&handle) else {
                return Err(MonitorError::IllegalMonitorState);
            };
            if entry.owner != Some(tid) {
                return Err(MonitorError::IllegalMonitorState);
            }
            if all {
                entry.wait_queue.drain(..).collect()
            } else {
                entry.wait_queue.pop_front().into_iter().collect()
            }
        };

        for wait_tid in woken {
            let saved = match self.threads.get(&wait_tid).map(|t| &t.state) {
                Some(ThreadState::WaitingOnMonitor {
                    saved_recursion, ..
                }) => *saved_recursion,
                _ => 1,
            };
            self.reacquire_after_wait(wait_tid, handle, saved);
        }
        Ok(())
    }

    fn reacquire_after_wait(&mut self, tid: ThreadId, handle: Handle, saved_recursion: u32) {
        let entry = self.monitors.entry(handle).or_default();
        entry.wait_queue.retain(|&w| w != tid);
        if entry.owner.is_none() {
            entry.owner = Some(tid);
            entry.recursion = saved_recursion.max(1);
            if let Some(t) = self.threads.get_mut(&tid) {
                t.state = ThreadState::Runnable;
                self.run_queue.push_back(tid);
            }
        } else {
            if !entry.entry_queue.contains(&tid) {
                entry.entry_queue.push_back(tid);
            }
            if let Some(t) = self.threads.get_mut(&tid) {
                t.state = ThreadState::BlockedOnMonitor(handle);
            }
        }
    }

    /// Collects all strong heap roots referenced by frames, exceptions, and monitors.
    pub fn collect_gc_roots(&self, out: &mut Vec<Handle>) {
        for thread in self.threads.values() {
            if thread.state == ThreadState::Terminated {
                continue;
            }
            if let Some(exc) = thread.pending_exception {
                out.push(exc);
            }
            if let Some(Value::Ref(Some(ret))) = thread.last_return {
                out.push(ret);
            }
            for frame in &thread.frames {
                if let Some(mon) = frame.synchronized_monitor {
                    out.push(mon);
                }
                for slot in &frame.locals {
                    if let Slot::Ref(Some(h)) = *slot {
                        out.push(h);
                    }
                }
                for slot in &frame.stack {
                    if let Slot::Ref(Some(h)) = *slot {
                        out.push(h);
                    }
                }
            }
        }
        for (&mon_handle, mon) in &self.monitors {
            if !mon.is_idle() {
                out.push(mon_handle);
            }
        }
    }
}
