// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, explicit, versioned VM snapshot encoder and atomic validator/restorer.
//!
//! Never performs raw binary dumps of Rust memory layouts. Every field uses
//! little-endian explicit framing, integrity verification, destination budget
//! enforcement, and compatibility checks BEFORE mutating any active `VmContext`.

use std::collections::VecDeque;

use super::heap::{ArrayStorage, GcStats, Heap, HeapEntry, HeapPayload};
use super::loader::{fnv1a64, ClassInitState};
use super::profile::{CldcVersion, HeapBudget, MidpVersion};
use super::scheduler::{Frame, MonitorState, Scheduler, ThreadState, VirtualThread};
use super::value::{ClassId, Handle, Slot, ThreadId, Value};
use super::VmContext;

const MAGIC: &[u8; 4] = b"KLOX";
const FORMAT_VERSION: u16 = 1;
const VM_SEMANTICS_VERSION: u16 = 1;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    InputTooLarge,
    BadMagic,
    UnsupportedFormatVersion(u16),
    IncompatibleSemanticsVersion(u16),
    ChecksumMismatch,
    ProfileMismatch,
    CodeHashMismatch,
    BudgetExceeded(&'static str),
    Malformed(&'static str),
}

/// Encodes a complete, self-contained VM state snapshot at a global safepoint.
pub fn encode_snapshot(vm: &VmContext) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    buf.extend_from_slice(MAGIC);
    put_u16(&mut buf, FORMAT_VERSION);
    put_u16(&mut buf, VM_SEMANTICS_VERSION);
    buf.push(vm.profile.cldc.to_u8());
    buf.push(vm.profile.midp.to_u8());
    put_u64(&mut buf, vm.loader.combined_code_hash());
    put_u64(&mut buf, vm.timeline_epoch);
    put_u64(&mut buf, vm.next_host_request_id);

    // 1. Class initialization states and static fields.
    put_u32(&mut buf, vm.loader.classes.len() as u32);
    for cls in &vm.loader.classes {
        let (state_tag, owner_tid) = match cls.init_state {
            ClassInitState::Prepared => (0u8, 0u32),
            ClassInitState::Initializing(tid) => (1u8, tid.0),
            ClassInitState::Initialized => (2u8, 0u32),
            ClassInitState::Failed => (3u8, 0u32),
        };
        buf.push(state_tag);
        put_u32(&mut buf, owner_tid);
        put_u32(&mut buf, cls.static_fields.len() as u32);
        for &val in &cls.static_fields {
            encode_value(&mut buf, val);
        }
    }

    // 2. Managed heap (generations, entries, interned strings, GC stats).
    put_u32(&mut buf, vm.heap.slots.len() as u32);
    put_u32(&mut buf, vm.heap.next_identity_hash);
    put_u64(&mut buf, vm.heap.stats.collections);
    put_u64(&mut buf, vm.heap.stats.reclaimed_objects);
    put_u64(&mut buf, vm.heap.stats.cleared_weak_refs);
    for (idx, slot) in vm.heap.slots.iter().enumerate() {
        put_u32(&mut buf, vm.heap.generations[idx]);
        match slot {
            None => buf.push(0),
            Some(entry) => {
                buf.push(1);
                put_u32(&mut buf, entry.gen);
                put_u32(&mut buf, entry.class_id.0);
                put_i32(&mut buf, entry.identity_hash);
                encode_payload(&mut buf, &entry.payload);
            }
        }
    }
    put_u32(&mut buf, vm.heap.interned_strings.len() as u32);
    for (chars, &handle) in &vm.heap.interned_strings {
        put_u32(&mut buf, chars.len() as u32);
        for &u in chars {
            put_u16(&mut buf, u);
        }
        encode_handle(&mut buf, handle);
    }

    // 3. Virtual scheduler, threads, frames, and monitors.
    put_u32(&mut buf, vm.scheduler.next_thread_id);
    put_u64(&mut buf, vm.scheduler.virtual_time_ms);
    put_u64(&mut buf, vm.scheduler.total_instructions);
    encode_opt_u32(&mut buf, vm.scheduler.active_thread.map(|t| t.0));
    put_u32(&mut buf, vm.scheduler.run_queue.len() as u32);
    for &tid in &vm.scheduler.run_queue {
        put_u32(&mut buf, tid.0);
    }
    put_u32(&mut buf, vm.scheduler.threads.len() as u32);
    for thread in vm.scheduler.threads.values() {
        encode_thread(&mut buf, thread);
    }
    put_u32(&mut buf, vm.scheduler.monitors.len() as u32);
    for (&handle, mon) in &vm.scheduler.monitors {
        encode_handle(&mut buf, handle);
        encode_opt_u32(&mut buf, mon.owner.map(|t| t.0));
        put_u32(&mut buf, mon.recursion);
        put_u32(&mut buf, mon.entry_queue.len() as u32);
        for &tid in &mon.entry_queue {
            put_u32(&mut buf, tid.0);
        }
        put_u32(&mut buf, mon.wait_queue.len() as u32);
        for &tid in &mon.wait_queue {
            put_u32(&mut buf, tid.0);
        }
    }

    // Trailing integrity checksum over entire preceding payload.
    let checksum = fnv1a64(&buf);
    put_u64(&mut buf, checksum);
    buf
}

/// Atomically validates and stages a snapshot before mutating `vm`.
/// Rejects snapshots that violate integrity, profile, code-hash, or destination
/// `HeapBudget` limits without modifying `vm`.
pub fn restore_snapshot(vm: &mut VmContext, data: &[u8]) -> Result<(), SnapshotError> {
    if data.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::InputTooLarge);
    }
    if data.len() < 16 {
        return Err(SnapshotError::Malformed("snapshot too short"));
    }
    let payload_len = data.len() - 8;
    let stored_checksum = u64::from_le_bytes([
        data[payload_len],
        data[payload_len + 1],
        data[payload_len + 2],
        data[payload_len + 3],
        data[payload_len + 4],
        data[payload_len + 5],
        data[payload_len + 6],
        data[payload_len + 7],
    ]);
    if fnv1a64(&data[..payload_len]) != stored_checksum {
        return Err(SnapshotError::ChecksumMismatch);
    }

    let mut r = Reader::new(&data[..payload_len]);
    if r.take_slice(4)? != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let fmt = r.u16()?;
    if fmt != FORMAT_VERSION {
        return Err(SnapshotError::UnsupportedFormatVersion(fmt));
    }
    let sem = r.u16()?;
    if sem != VM_SEMANTICS_VERSION {
        return Err(SnapshotError::IncompatibleSemanticsVersion(sem));
    }
    let cldc = CldcVersion::from_u8(r.u8()?).ok_or(SnapshotError::ProfileMismatch)?;
    let midp = MidpVersion::from_u8(r.u8()?).ok_or(SnapshotError::ProfileMismatch)?;
    if cldc != vm.profile.cldc || midp != vm.profile.midp {
        return Err(SnapshotError::ProfileMismatch);
    }
    let code_hash = r.u64()?;
    if code_hash != vm.loader.combined_code_hash() {
        return Err(SnapshotError::CodeHashMismatch);
    }
    let snapshot_epoch = r.u64()?;
    let next_host_request_id = r.u64()?;
    let budget = vm.profile.budget;

    // Stage 1: Class states & statics.
    let class_count = r.u32()? as usize;
    if class_count != vm.loader.classes.len() {
        return Err(SnapshotError::CodeHashMismatch);
    }
    let mut staged_classes = Vec::with_capacity(class_count);
    for cls in &vm.loader.classes {
        let state_tag = r.u8()?;
        let owner_tid = r.u32()?;
        let init_state = match state_tag {
            0 => ClassInitState::Prepared,
            1 => ClassInitState::Initializing(ThreadId(owner_tid)),
            2 => ClassInitState::Initialized,
            3 => ClassInitState::Failed,
            _ => return Err(SnapshotError::Malformed("invalid class init state")),
        };
        let statics_len = r.u32()? as usize;
        if statics_len != cls.static_fields.len() {
            return Err(SnapshotError::Malformed("static field count mismatch"));
        }
        let mut statics = Vec::with_capacity(statics_len);
        for _ in 0..statics_len {
            statics.push(decode_value(&mut r)?);
        }
        staged_classes.push((init_state, statics));
    }

    // Stage 2: Heap with strict destination budget enforcement.
    let slot_count = r.u32()? as usize;
    if slot_count > budget.max_objects.saturating_mul(4).max(4096) {
        return Err(SnapshotError::BudgetExceeded("heap slot table"));
    }
    let next_identity_hash = r.u32()?;
    let stats = GcStats {
        collections: r.u64()?,
        reclaimed_objects: r.u64()?,
        cleared_weak_refs: r.u64()?,
    };
    let mut staged_heap = Heap::new(budget);
    staged_heap.next_identity_hash = next_identity_hash;
    staged_heap.stats = stats;

    for idx in 0..slot_count {
        let gen = r.u32()?;
        staged_heap.generations.push(gen);
        let present = r.u8()?;
        match present {
            0 => {
                staged_heap.slots.push(None);
                staged_heap.free_list.push(idx as u32);
            }
            1 => {
                if staged_heap.live_objects >= budget.max_objects {
                    return Err(SnapshotError::BudgetExceeded("max_objects"));
                }
                let entry_gen = r.u32()?;
                let class_id = ClassId(r.u32()?);
                if (class_id.0 as usize) >= class_count {
                    return Err(SnapshotError::Malformed("heap class_id out of bounds"));
                }
                let identity_hash = r.i32()?;
                let payload = decode_payload(
                    &mut r,
                    budget,
                    staged_heap.live_field_slots,
                    staged_heap.live_array_bytes,
                )?;
                match &payload {
                    HeapPayload::Instance { fields, .. } => {
                        let next_fields = staged_heap
                            .live_field_slots
                            .checked_add(fields.len())
                            .ok_or(SnapshotError::BudgetExceeded("max_field_slots"))?;
                        if next_fields > budget.max_field_slots {
                            return Err(SnapshotError::BudgetExceeded("max_field_slots"));
                        }
                        staged_heap.live_field_slots = next_fields;
                    }
                    HeapPayload::Array(storage) => {
                        let next_bytes = staged_heap
                            .live_array_bytes
                            .checked_add(storage.byte_footprint())
                            .ok_or(SnapshotError::BudgetExceeded("max_array_bytes"))?;
                        if next_bytes > budget.max_array_bytes {
                            return Err(SnapshotError::BudgetExceeded("max_array_bytes"));
                        }
                        staged_heap.live_array_bytes = next_bytes;
                    }
                    HeapPayload::StringObject { chars } => {
                        let next_bytes = staged_heap
                            .live_array_bytes
                            .checked_add(chars.len().saturating_mul(2))
                            .ok_or(SnapshotError::BudgetExceeded("max_array_bytes"))?;
                        if next_bytes > budget.max_array_bytes {
                            return Err(SnapshotError::BudgetExceeded("max_array_bytes"));
                        }
                        staged_heap.live_array_bytes = next_bytes;
                    }
                }
                staged_heap.live_objects += 1;
                staged_heap.slots.push(Some(HeapEntry {
                    gen: entry_gen,
                    class_id,
                    identity_hash,
                    payload,
                }));
            }
            _ => return Err(SnapshotError::Malformed("invalid heap presence tag")),
        }
    }
    let intern_count = r.u32()? as usize;
    if intern_count > budget.max_objects {
        return Err(SnapshotError::BudgetExceeded("interned_strings"));
    }
    for _ in 0..intern_count {
        let len = r.u32()? as usize;
        if len.saturating_mul(2) > budget.max_array_bytes {
            return Err(SnapshotError::BudgetExceeded("max_array_bytes"));
        }
        let mut chars = Vec::with_capacity(len.min(4096));
        for _ in 0..len {
            chars.push(r.u16()?);
        }
        let handle = decode_handle(&mut r)?;
        staged_heap.interned_strings.insert(chars, handle);
    }

    // Stage 3: Scheduler with thread and frame-depth budget enforcement.
    let mut staged_sched = Scheduler::new(budget.max_threads, budget.instruction_quantum);
    staged_sched.next_thread_id = r.u32()?;
    staged_sched.virtual_time_ms = r.u64()?;
    staged_sched.total_instructions = r.u64()?;
    staged_sched.active_thread = decode_opt_u32(&mut r)?.map(ThreadId);
    let rq_len = r.u32()? as usize;
    if rq_len > budget.max_threads.saturating_mul(4).max(64) {
        return Err(SnapshotError::BudgetExceeded("run_queue"));
    }
    for _ in 0..rq_len {
        staged_sched.run_queue.push_back(ThreadId(r.u32()?));
    }
    let thread_count = r.u32()? as usize;
    if thread_count > budget.max_threads.saturating_mul(4).max(64) {
        return Err(SnapshotError::BudgetExceeded("max_threads"));
    }
    let mut live_threads = 0usize;
    for _ in 0..thread_count {
        let t = decode_thread(&mut r, budget.max_frames_per_thread)?;
        if t.state != ThreadState::Terminated {
            live_threads += 1;
            if live_threads > budget.max_threads {
                return Err(SnapshotError::BudgetExceeded("max_threads"));
            }
        }
        staged_sched.threads.insert(t.id, t);
    }
    let mon_count = r.u32()? as usize;
    if mon_count > budget.max_objects {
        return Err(SnapshotError::BudgetExceeded("monitors"));
    }
    for _ in 0..mon_count {
        let handle = decode_handle(&mut r)?;
        let owner = decode_opt_u32(&mut r)?.map(ThreadId);
        let recursion = r.u32()?;
        let eq_len = r.u32()? as usize;
        if eq_len > budget.max_threads {
            return Err(SnapshotError::BudgetExceeded("monitor_entry_queue"));
        }
        let mut entry_queue = VecDeque::with_capacity(eq_len.min(64));
        for _ in 0..eq_len {
            entry_queue.push_back(ThreadId(r.u32()?));
        }
        let wq_len = r.u32()? as usize;
        if wq_len > budget.max_threads {
            return Err(SnapshotError::BudgetExceeded("monitor_wait_queue"));
        }
        let mut wait_queue = VecDeque::with_capacity(wq_len.min(64));
        for _ in 0..wq_len {
            wait_queue.push_back(ThreadId(r.u32()?));
        }
        staged_sched.monitors.insert(
            handle,
            MonitorState {
                owner,
                recursion,
                entry_queue,
                wait_queue,
            },
        );
    }

    if !r.is_eof() {
        return Err(SnapshotError::Malformed("trailing bytes in snapshot"));
    }

    // Atomic commit: publish staged state and advance timeline epoch so any
    // in-flight host callbacks from the discarded timeline are rejected.
    for (cls, (init_state, statics)) in vm.loader.classes.iter_mut().zip(staged_classes) {
        cls.init_state = init_state;
        cls.static_fields = statics;
    }
    vm.heap = staged_heap;
    vm.scheduler = staged_sched;
    vm.timeline_epoch = vm.timeline_epoch.max(snapshot_epoch).wrapping_add(1).max(1);
    vm.next_host_request_id = next_host_request_id;
    Ok(())
}

fn encode_handle(buf: &mut Vec<u8>, h: Handle) {
    put_u32(buf, h.id);
    put_u32(buf, h.gen);
}

fn decode_handle(r: &mut Reader<'_>) -> Result<Handle, SnapshotError> {
    Ok(Handle::new(r.u32()?, r.u32()?))
}

fn encode_opt_handle(buf: &mut Vec<u8>, h: Option<Handle>) {
    match h {
        None => buf.push(0),
        Some(h) => {
            buf.push(1);
            encode_handle(buf, h);
        }
    }
}

fn decode_opt_handle(r: &mut Reader<'_>) -> Result<Option<Handle>, SnapshotError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode_handle(r)?)),
        _ => Err(SnapshotError::Malformed("invalid option handle tag")),
    }
}

fn encode_opt_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => buf.push(0),
        Some(x) => {
            buf.push(1);
            put_u32(buf, x);
        }
    }
}

fn decode_opt_u32(r: &mut Reader<'_>) -> Result<Option<u32>, SnapshotError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.u32()?)),
        _ => Err(SnapshotError::Malformed("invalid option u32 tag")),
    }
}

fn encode_value(buf: &mut Vec<u8>, v: Value) {
    match v {
        Value::Int(x) => {
            buf.push(1);
            put_i32(buf, x);
        }
        Value::Long(x) => {
            buf.push(2);
            put_i64(buf, x);
        }
        Value::Float(bits) => {
            buf.push(3);
            put_u32(buf, bits);
        }
        Value::Double(bits) => {
            buf.push(4);
            put_u64(buf, bits);
        }
        Value::Ref(h) => {
            buf.push(5);
            encode_opt_handle(buf, h);
        }
    }
}

fn decode_value(r: &mut Reader<'_>) -> Result<Value, SnapshotError> {
    match r.u8()? {
        1 => Ok(Value::Int(r.i32()?)),
        2 => Ok(Value::Long(r.i64()?)),
        3 => Ok(Value::Float(r.u32()?)),
        4 => Ok(Value::Double(r.u64()?)),
        5 => Ok(Value::Ref(decode_opt_handle(r)?)),
        _ => Err(SnapshotError::Malformed("invalid value tag")),
    }
}

fn encode_slot(buf: &mut Vec<u8>, s: Slot) {
    match s {
        Slot::Empty => buf.push(0),
        Slot::Int(x) => {
            buf.push(1);
            put_i32(buf, x);
        }
        Slot::Long(x) => {
            buf.push(2);
            put_i64(buf, x);
        }
        Slot::Float(bits) => {
            buf.push(3);
            put_u32(buf, bits);
        }
        Slot::Double(bits) => {
            buf.push(4);
            put_u64(buf, bits);
        }
        Slot::Ref(h) => {
            buf.push(5);
            encode_opt_handle(buf, h);
        }
        Slot::Top => buf.push(6),
    }
}

fn decode_slot(r: &mut Reader<'_>) -> Result<Slot, SnapshotError> {
    match r.u8()? {
        0 => Ok(Slot::Empty),
        1 => Ok(Slot::Int(r.i32()?)),
        2 => Ok(Slot::Long(r.i64()?)),
        3 => Ok(Slot::Float(r.u32()?)),
        4 => Ok(Slot::Double(r.u64()?)),
        5 => Ok(Slot::Ref(decode_opt_handle(r)?)),
        6 => Ok(Slot::Top),
        _ => Err(SnapshotError::Malformed("invalid slot tag")),
    }
}

fn encode_payload(buf: &mut Vec<u8>, payload: &HeapPayload) {
    match payload {
        HeapPayload::Instance {
            fields,
            weak_referent,
        } => {
            buf.push(1);
            put_u32(buf, fields.len() as u32);
            for &v in fields {
                encode_value(buf, v);
            }
            match weak_referent {
                None => buf.push(0),
                Some(r) => {
                    buf.push(1);
                    encode_opt_handle(buf, *r);
                }
            }
        }
        HeapPayload::Array(storage) => {
            buf.push(2);
            match storage {
                ArrayStorage::Boolean(v) => {
                    buf.push(1);
                    put_u32(buf, v.len() as u32);
                    buf.extend_from_slice(v);
                }
                ArrayStorage::Byte(v) => {
                    buf.push(2);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        buf.push(x as u8);
                    }
                }
                ArrayStorage::Char(v) => {
                    buf.push(3);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_u16(buf, x);
                    }
                }
                ArrayStorage::Short(v) => {
                    buf.push(4);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_u16(buf, x as u16);
                    }
                }
                ArrayStorage::Int(v) => {
                    buf.push(5);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_i32(buf, x);
                    }
                }
                ArrayStorage::Long(v) => {
                    buf.push(6);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_i64(buf, x);
                    }
                }
                ArrayStorage::Float(v) => {
                    buf.push(7);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_u32(buf, x);
                    }
                }
                ArrayStorage::Double(v) => {
                    buf.push(8);
                    put_u32(buf, v.len() as u32);
                    for &x in v {
                        put_u64(buf, x);
                    }
                }
                ArrayStorage::Reference {
                    element_class,
                    elements,
                } => {
                    buf.push(9);
                    put_u32(buf, element_class.0);
                    put_u32(buf, elements.len() as u32);
                    for &h in elements {
                        encode_opt_handle(buf, h);
                    }
                }
            }
        }
        HeapPayload::StringObject { chars } => {
            buf.push(3);
            put_u32(buf, chars.len() as u32);
            for &u in chars {
                put_u16(buf, u);
            }
        }
    }
}

fn check_array_bytes(
    budget: HeapBudget,
    live_array_bytes: usize,
    len: usize,
    elem_size: usize,
) -> Result<(), SnapshotError> {
    let bytes = len
        .checked_mul(elem_size)
        .ok_or(SnapshotError::BudgetExceeded("max_array_bytes"))?;
    let next = live_array_bytes
        .checked_add(bytes)
        .ok_or(SnapshotError::BudgetExceeded("max_array_bytes"))?;
    if next > budget.max_array_bytes {
        return Err(SnapshotError::BudgetExceeded("max_array_bytes"));
    }
    Ok(())
}

fn decode_payload(
    r: &mut Reader<'_>,
    budget: HeapBudget,
    live_field_slots: usize,
    live_array_bytes: usize,
) -> Result<HeapPayload, SnapshotError> {
    match r.u8()? {
        1 => {
            let len = r.u32()? as usize;
            let next_fields = live_field_slots
                .checked_add(len)
                .ok_or(SnapshotError::BudgetExceeded("max_field_slots"))?;
            if next_fields > budget.max_field_slots {
                return Err(SnapshotError::BudgetExceeded("max_field_slots"));
            }
            let mut fields = Vec::with_capacity(len.min(256));
            for _ in 0..len {
                fields.push(decode_value(r)?);
            }
            let weak_referent = match r.u8()? {
                0 => None,
                1 => Some(decode_opt_handle(r)?),
                _ => return Err(SnapshotError::Malformed("invalid weak_ref tag")),
            };
            Ok(HeapPayload::Instance {
                fields,
                weak_referent,
            })
        }
        2 => {
            let kind = r.u8()?;
            let storage = match kind {
                1 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 1)?;
                    ArrayStorage::Boolean(r.take_slice(len)?.to_vec())
                }
                2 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 1)?;
                    ArrayStorage::Byte(r.take_slice(len)?.iter().map(|&b| b as i8).collect())
                }
                3 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 2)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.u16()?);
                    }
                    ArrayStorage::Char(v)
                }
                4 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 2)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.u16()? as i16);
                    }
                    ArrayStorage::Short(v)
                }
                5 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 4)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.i32()?);
                    }
                    ArrayStorage::Int(v)
                }
                6 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 8)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.i64()?);
                    }
                    ArrayStorage::Long(v)
                }
                7 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 4)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.u32()?);
                    }
                    ArrayStorage::Float(v)
                }
                8 => {
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 8)?;
                    let mut v = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        v.push(r.u64()?);
                    }
                    ArrayStorage::Double(v)
                }
                9 => {
                    let element_class = ClassId(r.u32()?);
                    let len = r.u32()? as usize;
                    check_array_bytes(budget, live_array_bytes, len, 8)?;
                    let mut elements = Vec::with_capacity(len.min(4096));
                    for _ in 0..len {
                        elements.push(decode_opt_handle(r)?);
                    }
                    ArrayStorage::Reference {
                        element_class,
                        elements,
                    }
                }
                _ => return Err(SnapshotError::Malformed("invalid array kind tag")),
            };
            Ok(HeapPayload::Array(storage))
        }
        3 => {
            let len = r.u32()? as usize;
            check_array_bytes(budget, live_array_bytes, len, 2)?;
            let mut chars = Vec::with_capacity(len.min(4096));
            for _ in 0..len {
                chars.push(r.u16()?);
            }
            Ok(HeapPayload::StringObject { chars })
        }
        _ => Err(SnapshotError::Malformed("invalid heap payload tag")),
    }
}

fn encode_thread(buf: &mut Vec<u8>, t: &VirtualThread) {
    put_u32(buf, t.id.0);
    let name_bytes = t.name.as_bytes();
    put_u32(buf, name_bytes.len() as u32);
    buf.extend_from_slice(name_bytes);
    buf.push(t.priority);
    match t.state {
        ThreadState::Runnable => buf.push(0),
        ThreadState::BlockedOnMonitor(h) => {
            buf.push(1);
            encode_handle(buf, h);
        }
        ThreadState::WaitingOnMonitor {
            handle,
            saved_recursion,
            deadline_ms,
        } => {
            buf.push(2);
            encode_handle(buf, handle);
            put_u32(buf, saved_recursion);
            match deadline_ms {
                None => buf.push(0),
                Some(d) => {
                    buf.push(1);
                    put_u64(buf, d);
                }
            }
        }
        ThreadState::Sleeping { deadline_ms } => {
            buf.push(3);
            put_u64(buf, deadline_ms);
        }
        ThreadState::BlockedOnHost { request_id, epoch } => {
            buf.push(4);
            put_u64(buf, request_id);
            put_u64(buf, epoch);
        }
        ThreadState::Terminated => buf.push(5),
    }
    buf.push(u8::from(t.interrupted));
    encode_opt_handle(buf, t.pending_exception);
    match t.last_return {
        None => buf.push(0),
        Some(v) => {
            buf.push(1);
            encode_value(buf, v);
        }
    }
    put_u32(buf, t.quantum_remaining);
    put_u32(buf, t.frames.len() as u32);
    for f in &t.frames {
        put_u32(buf, f.class_id.0);
        put_u32(buf, f.method_index as u32);
        put_u32(buf, f.ip as u32);
        put_u16(buf, f.pc);
        encode_opt_handle(buf, f.synchronized_monitor);
        put_u32(buf, f.locals.len() as u32);
        for &s in &f.locals {
            encode_slot(buf, s);
        }
        put_u32(buf, f.stack.len() as u32);
        for &s in &f.stack {
            encode_slot(buf, s);
        }
    }
}

fn decode_thread(
    r: &mut Reader<'_>,
    max_frames_per_thread: usize,
) -> Result<VirtualThread, SnapshotError> {
    let id = ThreadId(r.u32()?);
    let name_len = r.u32()? as usize;
    if name_len > 1024 {
        return Err(SnapshotError::Malformed("thread name too long"));
    }
    let name = std::str::from_utf8(r.take_slice(name_len)?)
        .map_err(|_| SnapshotError::Malformed("invalid thread name utf8"))?
        .to_string();
    let priority = r.u8()?.clamp(1, 10);
    let state = match r.u8()? {
        0 => ThreadState::Runnable,
        1 => ThreadState::BlockedOnMonitor(decode_handle(r)?),
        2 => {
            let handle = decode_handle(r)?;
            let saved_recursion = r.u32()?;
            let deadline_ms = match r.u8()? {
                0 => None,
                1 => Some(r.u64()?),
                _ => return Err(SnapshotError::Malformed("invalid deadline tag")),
            };
            ThreadState::WaitingOnMonitor {
                handle,
                saved_recursion,
                deadline_ms,
            }
        }
        3 => ThreadState::Sleeping {
            deadline_ms: r.u64()?,
        },
        4 => ThreadState::BlockedOnHost {
            request_id: r.u64()?,
            epoch: r.u64()?,
        },
        5 => ThreadState::Terminated,
        _ => return Err(SnapshotError::Malformed("invalid thread state tag")),
    };
    let interrupted = r.u8()? != 0;
    let pending_exception = decode_opt_handle(r)?;
    let last_return = match r.u8()? {
        0 => None,
        1 => Some(decode_value(r)?),
        _ => return Err(SnapshotError::Malformed("invalid last_return tag")),
    };
    let quantum_remaining = r.u32()?;
    let frame_count = r.u32()? as usize;
    if frame_count > max_frames_per_thread {
        return Err(SnapshotError::BudgetExceeded("max_frames_per_thread"));
    }
    let mut frames = Vec::with_capacity(frame_count.min(128));
    for _ in 0..frame_count {
        let class_id = ClassId(r.u32()?);
        let method_index = r.u32()? as usize;
        let ip = r.u32()? as usize;
        let pc = r.u16()?;
        let synchronized_monitor = decode_opt_handle(r)?;
        let locals_len = r.u32()? as usize;
        if locals_len > 65_535 {
            return Err(SnapshotError::Malformed("frame locals exceed u16"));
        }
        let mut locals = Vec::with_capacity(locals_len.min(128));
        for _ in 0..locals_len {
            locals.push(decode_slot(r)?);
        }
        let stack_len = r.u32()? as usize;
        if stack_len > 65_535 {
            return Err(SnapshotError::Malformed("frame stack exceeds u16"));
        }
        let mut stack = Vec::with_capacity(stack_len.min(128));
        for _ in 0..stack_len {
            stack.push(decode_slot(r)?);
        }
        frames.push(Frame {
            class_id,
            method_index,
            ip,
            pc,
            locals,
            stack,
            synchronized_monitor,
        });
    }
    Ok(VirtualThread {
        id,
        name,
        priority,
        state,
        frames,
        interrupted,
        pending_exception,
        last_return,
        quantum_remaining,
    })
}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.data.len()
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SnapshotError::Malformed("length overflow"))?;
        if end > self.data.len() {
            return Err(SnapshotError::Malformed("unexpected eof"));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take_slice(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SnapshotError> {
        let s = self.take_slice(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, SnapshotError> {
        let s = self.take_slice(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn i32(&mut self) -> Result<i32, SnapshotError> {
        let s = self.take_slice(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, SnapshotError> {
        let s = self.take_slice(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
    fn i64(&mut self) -> Result<i64, SnapshotError> {
        let s = self.take_slice(8)?;
        Ok(i64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }
}
