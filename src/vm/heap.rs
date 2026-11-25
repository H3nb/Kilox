// SPDX-License-Identifier: GPL-3.0-only
//! Safe-Rust handle-based managed heap with bounded resource budgets,
//! stable identity hash codes, mark-sweep GC, and CLDC 1.1 WeakReference clearing.

use std::collections::{BTreeMap, BTreeSet};

use super::profile::HeapBudget;
use super::value::{ClassId, Handle, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    OutOfMemory,
    InvalidHandle,
    NullPointer,
    ArrayIndexOutOfBounds { index: i32, len: usize },
    NegativeArraySize(i32),
    ArrayStoreTypeMismatch,
    FieldOutOfBounds,
    NotAnObject,
    NotAnArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayKind {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Reference,
}

impl ArrayKind {
    pub const fn from_atype(atype: u8) -> Option<Self> {
        match atype {
            4 => Some(Self::Boolean),
            5 => Some(Self::Char),
            6 => Some(Self::Float),
            7 => Some(Self::Double),
            8 => Some(Self::Byte),
            9 => Some(Self::Short),
            10 => Some(Self::Int),
            11 => Some(Self::Long),
            _ => None,
        }
    }

    pub const fn element_byte_size(self) -> usize {
        match self {
            Self::Boolean | Self::Byte => 1,
            Self::Char | Self::Short => 2,
            Self::Int | Self::Float => 4,
            Self::Long | Self::Double | Self::Reference => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArrayStorage {
    Boolean(Vec<u8>),
    Byte(Vec<i8>),
    Char(Vec<u16>),
    Short(Vec<i16>),
    Int(Vec<i32>),
    Long(Vec<i64>),
    Float(Vec<u32>),
    Double(Vec<u64>),
    Reference {
        element_class: ClassId,
        elements: Vec<Option<Handle>>,
    },
}

impl ArrayStorage {
    pub fn len(&self) -> usize {
        match self {
            Self::Boolean(v) => v.len(),
            Self::Byte(v) => v.len(),
            Self::Char(v) => v.len(),
            Self::Short(v) => v.len(),
            Self::Int(v) => v.len(),
            Self::Long(v) => v.len(),
            Self::Float(v) => v.len(),
            Self::Double(v) => v.len(),
            Self::Reference { elements, .. } => elements.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn kind(&self) -> ArrayKind {
        match self {
            Self::Boolean(_) => ArrayKind::Boolean,
            Self::Byte(_) => ArrayKind::Byte,
            Self::Char(_) => ArrayKind::Char,
            Self::Short(_) => ArrayKind::Short,
            Self::Int(_) => ArrayKind::Int,
            Self::Long(_) => ArrayKind::Long,
            Self::Float(_) => ArrayKind::Float,
            Self::Double(_) => ArrayKind::Double,
            Self::Reference { .. } => ArrayKind::Reference,
        }
    }

    pub fn byte_footprint(&self) -> usize {
        self.len().saturating_mul(self.kind().element_byte_size())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeapPayload {
    Instance {
        fields: Vec<Value>,
        /// Optional CLDC 1.1 `java.lang.ref.WeakReference` referent slot.
        /// Traced specially during GC: cleared if not strongly reachable.
        weak_referent: Option<Option<Handle>>,
    },
    Array(ArrayStorage),
    /// Interned or runtime UTF-16 string payload backing `java.lang.String`.
    StringObject {
        chars: Vec<u16>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeapEntry {
    pub gen: u32,
    pub class_id: ClassId,
    pub identity_hash: i32,
    pub payload: HeapPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcStats {
    pub collections: u64,
    pub reclaimed_objects: u64,
    pub cleared_weak_refs: u64,
}

/// Handle-indexed managed heap with zero unsafe code and deterministic budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heap {
    pub(crate) budget: HeapBudget,
    pub(crate) slots: Vec<Option<HeapEntry>>,
    pub(crate) generations: Vec<u32>,
    pub(crate) free_list: Vec<u32>,
    pub(crate) live_objects: usize,
    pub(crate) live_field_slots: usize,
    pub(crate) live_array_bytes: usize,
    pub(crate) next_identity_hash: u32,
    pub(crate) interned_strings: BTreeMap<Vec<u16>, Handle>,
    pub(crate) stats: GcStats,
}

impl Heap {
    pub fn new(budget: HeapBudget) -> Self {
        Self {
            budget,
            slots: Vec::new(),
            generations: Vec::new(),
            free_list: Vec::new(),
            live_objects: 0,
            live_field_slots: 0,
            live_array_bytes: 0,
            next_identity_hash: 0x1001,
            interned_strings: BTreeMap::new(),
            stats: GcStats {
                collections: 0,
                reclaimed_objects: 0,
                cleared_weak_refs: 0,
            },
        }
    }

    pub fn live_objects(&self) -> usize {
        self.live_objects
    }

    pub fn live_field_slots(&self) -> usize {
        self.live_field_slots
    }

    pub fn live_array_bytes(&self) -> usize {
        self.live_array_bytes
    }

    pub fn stats(&self) -> &GcStats {
        &self.stats
    }

    fn next_hash(&mut self) -> i32 {
        // Deterministic xorshift32 for stable cross-process identity hashes.
        let mut x = self.next_identity_hash;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        if x == 0 {
            x = 1;
        }
        self.next_identity_hash = x;
        (x & 0x7fff_ffff) as i32
    }

    fn insert_entry(
        &mut self,
        class_id: ClassId,
        payload: HeapPayload,
    ) -> Result<Handle, HeapError> {
        if self.live_objects >= self.budget.max_objects {
            return Err(HeapError::OutOfMemory);
        }
        let identity_hash = self.next_hash();
        let id = if let Some(reused) = self.free_list.pop() {
            let idx = reused as usize;
            self.generations[idx] = self.generations[idx].wrapping_add(1).max(1);
            let gen = self.generations[idx];
            self.slots[idx] = Some(HeapEntry {
                gen,
                class_id,
                identity_hash,
                payload,
            });
            reused
        } else {
            let id = u32::try_from(self.slots.len()).map_err(|_| HeapError::OutOfMemory)?;
            self.generations.push(1);
            self.slots.push(Some(HeapEntry {
                gen: 1,
                class_id,
                identity_hash,
                payload,
            }));
            id
        };
        self.live_objects += 1;
        Ok(Handle::new(id, self.generations[id as usize]))
    }

    pub fn alloc_instance(
        &mut self,
        class_id: ClassId,
        fields: Vec<Value>,
        is_weak_ref: bool,
    ) -> Result<Handle, HeapError> {
        let count = fields.len();
        if self.live_field_slots.saturating_add(count) > self.budget.max_field_slots {
            return Err(HeapError::OutOfMemory);
        }
        let weak_referent = if is_weak_ref { Some(None) } else { None };
        let handle = self.insert_entry(
            class_id,
            HeapPayload::Instance {
                fields,
                weak_referent,
            },
        )?;
        self.live_field_slots += count;
        Ok(handle)
    }

    pub fn alloc_primitive_array(
        &mut self,
        class_id: ClassId,
        kind: ArrayKind,
        len: i32,
    ) -> Result<Handle, HeapError> {
        if len < 0 {
            return Err(HeapError::NegativeArraySize(len));
        }
        let ulen = len as usize;
        let bytes = ulen
            .checked_mul(kind.element_byte_size())
            .ok_or(HeapError::OutOfMemory)?;
        if self.live_array_bytes.saturating_add(bytes) > self.budget.max_array_bytes {
            return Err(HeapError::OutOfMemory);
        }
        let storage = match kind {
            ArrayKind::Boolean => ArrayStorage::Boolean(vec![0; ulen]),
            ArrayKind::Byte => ArrayStorage::Byte(vec![0; ulen]),
            ArrayKind::Char => ArrayStorage::Char(vec![0; ulen]),
            ArrayKind::Short => ArrayStorage::Short(vec![0; ulen]),
            ArrayKind::Int => ArrayStorage::Int(vec![0; ulen]),
            ArrayKind::Long => ArrayStorage::Long(vec![0; ulen]),
            ArrayKind::Float => ArrayStorage::Float(vec![0; ulen]),
            ArrayKind::Double => ArrayStorage::Double(vec![0; ulen]),
            ArrayKind::Reference => return Err(HeapError::ArrayStoreTypeMismatch),
        };
        let handle = self.insert_entry(class_id, HeapPayload::Array(storage))?;
        self.live_array_bytes += bytes;
        Ok(handle)
    }

    pub fn alloc_ref_array(
        &mut self,
        array_class_id: ClassId,
        element_class: ClassId,
        len: i32,
    ) -> Result<Handle, HeapError> {
        if len < 0 {
            return Err(HeapError::NegativeArraySize(len));
        }
        let ulen = len as usize;
        let bytes = ulen
            .checked_mul(ArrayKind::Reference.element_byte_size())
            .ok_or(HeapError::OutOfMemory)?;
        if self.live_array_bytes.saturating_add(bytes) > self.budget.max_array_bytes {
            return Err(HeapError::OutOfMemory);
        }
        let storage = ArrayStorage::Reference {
            element_class,
            elements: vec![None; ulen],
        };
        let handle = self.insert_entry(array_class_id, HeapPayload::Array(storage))?;
        self.live_array_bytes += bytes;
        Ok(handle)
    }

    pub fn intern_string(
        &mut self,
        string_class_id: ClassId,
        text: &str,
    ) -> Result<Handle, HeapError> {
        let chars: Vec<u16> = text.encode_utf16().collect();
        if let Some(&existing) = self.interned_strings.get(&chars) {
            if self.get(existing).is_ok() {
                return Ok(existing);
            }
        }
        let bytes = chars.len().saturating_mul(2);
        if self.live_array_bytes.saturating_add(bytes) > self.budget.max_array_bytes {
            return Err(HeapError::OutOfMemory);
        }
        let handle = self.insert_entry(
            string_class_id,
            HeapPayload::StringObject {
                chars: chars.clone(),
            },
        )?;
        self.live_array_bytes += bytes;
        self.interned_strings.insert(chars, handle);
        Ok(handle)
    }

    pub fn get(&self, handle: Handle) -> Result<&HeapEntry, HeapError> {
        let entry = self
            .slots
            .get(handle.id as usize)
            .and_then(|s| s.as_ref())
            .ok_or(HeapError::InvalidHandle)?;
        if entry.gen != handle.gen {
            return Err(HeapError::InvalidHandle);
        }
        Ok(entry)
    }

    pub fn get_mut(&mut self, handle: Handle) -> Result<&mut HeapEntry, HeapError> {
        let entry = self
            .slots
            .get_mut(handle.id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(HeapError::InvalidHandle)?;
        if entry.gen != handle.gen {
            return Err(HeapError::InvalidHandle);
        }
        Ok(entry)
    }

    pub fn identity_hash(&self, handle: Handle) -> Result<i32, HeapError> {
        Ok(self.get(handle)?.identity_hash)
    }

    pub fn class_of(&self, handle: Handle) -> Result<ClassId, HeapError> {
        Ok(self.get(handle)?.class_id)
    }

    pub fn get_field(&self, handle: Handle, index: usize) -> Result<Value, HeapError> {
        match &self.get(handle)?.payload {
            HeapPayload::Instance { fields, .. } => fields
                .get(index)
                .copied()
                .ok_or(HeapError::FieldOutOfBounds),
            _ => Err(HeapError::NotAnObject),
        }
    }

    pub fn put_field(
        &mut self,
        handle: Handle,
        index: usize,
        value: Value,
    ) -> Result<(), HeapError> {
        match &mut self.get_mut(handle)?.payload {
            HeapPayload::Instance { fields, .. } => {
                let slot = fields.get_mut(index).ok_or(HeapError::FieldOutOfBounds)?;
                *slot = value;
                Ok(())
            }
            _ => Err(HeapError::NotAnObject),
        }
    }

    pub fn set_weak_referent(
        &mut self,
        weak_handle: Handle,
        referent: Option<Handle>,
    ) -> Result<(), HeapError> {
        match &mut self.get_mut(weak_handle)?.payload {
            HeapPayload::Instance {
                weak_referent: Some(slot),
                ..
            } => {
                *slot = referent;
                Ok(())
            }
            _ => Err(HeapError::NotAnObject),
        }
    }

    pub fn get_weak_referent(&self, weak_handle: Handle) -> Result<Option<Handle>, HeapError> {
        match &self.get(weak_handle)?.payload {
            HeapPayload::Instance {
                weak_referent: Some(slot),
                ..
            } => Ok(*slot),
            _ => Err(HeapError::NotAnObject),
        }
    }

    pub fn array_len(&self, handle: Handle) -> Result<usize, HeapError> {
        match &self.get(handle)?.payload {
            HeapPayload::Array(storage) => Ok(storage.len()),
            _ => Err(HeapError::NotAnArray),
        }
    }

    pub fn array_storage(&self, handle: Handle) -> Result<&ArrayStorage, HeapError> {
        match &self.get(handle)?.payload {
            HeapPayload::Array(storage) => Ok(storage),
            _ => Err(HeapError::NotAnArray),
        }
    }

    pub fn array_storage_mut(&mut self, handle: Handle) -> Result<&mut ArrayStorage, HeapError> {
        match &mut self.get_mut(handle)?.payload {
            HeapPayload::Array(storage) => Ok(storage),
            _ => Err(HeapError::NotAnArray),
        }
    }

    /// Stop-the-world Mark-Sweep GC executed at a global VM safepoint.
    /// Strong roots include frames, statics, monitors, and interned strings.
    /// WeakReference referents are cleared atomically if not strongly reachable.
    pub fn collect_garbage(&mut self, external_roots: &[Handle]) -> (usize, usize) {
        let mut marked: BTreeSet<u32> = BTreeSet::new();
        let mut worklist: Vec<Handle> = Vec::new();

        for &h in external_roots {
            if self.get(h).is_ok() && marked.insert(h.id) {
                worklist.push(h);
            }
        }
        for &h in self.interned_strings.values() {
            if self.get(h).is_ok() && marked.insert(h.id) {
                worklist.push(h);
            }
        }

        // Phase 1: Strong reachability mark pass.
        while let Some(h) = worklist.pop() {
            let Ok(entry) = self.get(h) else {
                continue;
            };
            match &entry.payload {
                HeapPayload::Instance { fields, .. } => {
                    for &val in fields {
                        if let Value::Ref(Some(child)) = val {
                            if self.get(child).is_ok() && marked.insert(child.id) {
                                worklist.push(child);
                            }
                        }
                    }
                }
                HeapPayload::Array(ArrayStorage::Reference { elements, .. }) => {
                    for elem in elements {
                        if let Some(child) = *elem {
                            if self.get(child).is_ok() && marked.insert(child.id) {
                                worklist.push(child);
                            }
                        }
                    }
                }
                HeapPayload::Array(_) | HeapPayload::StringObject { .. } => {}
            }
        }

        // Phase 2: Clear weakly-only reachable referents atomically.
        let mut cleared_weaks = 0usize;
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if !marked.contains(&(idx as u32)) {
                continue;
            }
            if let Some(entry) = slot.as_mut() {
                if let HeapPayload::Instance {
                    weak_referent: Some(ref mut referent),
                    ..
                } = entry.payload
                {
                    if let Some(target) = *referent {
                        if !marked.contains(&target.id) {
                            *referent = None;
                            cleared_weaks += 1;
                        }
                    }
                }
            }
        }

        // Phase 3: Sweep unmarked objects and reclaim budgets.
        let mut reclaimed = 0usize;
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            let id = idx as u32;
            if marked.contains(&id) {
                continue;
            }
            if let Some(entry) = slot.take() {
                match &entry.payload {
                    HeapPayload::Instance { fields, .. } => {
                        self.live_field_slots = self.live_field_slots.saturating_sub(fields.len());
                    }
                    HeapPayload::Array(storage) => {
                        self.live_array_bytes = self
                            .live_array_bytes
                            .saturating_sub(storage.byte_footprint());
                    }
                    HeapPayload::StringObject { chars } => {
                        self.live_array_bytes = self
                            .live_array_bytes
                            .saturating_sub(chars.len().saturating_mul(2));
                    }
                }
                self.live_objects = self.live_objects.saturating_sub(1);
                self.free_list.push(id);
                reclaimed += 1;
            }
        }

        self.stats.collections += 1;
        self.stats.reclaimed_objects += reclaimed as u64;
        self.stats.cleared_weak_refs += cleared_weaks as u64;
        (reclaimed, cleared_weaks)
    }
}
