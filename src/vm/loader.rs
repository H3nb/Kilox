// SPDX-License-Identifier: GPL-3.0-only
//! Context-owned class loader, hierarchy/assignability resolver, static field
//! preparation (`ConstantValue`), and lazy symbolic resolution.

use std::collections::BTreeMap;

use crate::classfile::{parse_class, ClassFile, Constant, ParseError};

use super::heap::{Heap, HeapError};
use super::profile::ProfileContract;
use super::value::{
    parse_field_descriptor, parse_method_descriptor, ClassId, FieldType, MethodDescriptor,
    ThreadId, Value,
};
use super::verifier::{decode_and_verify, DecodedMethod, VerifyError};

pub const ACC_PUBLIC: u16 = 0x0001;
pub const ACC_PRIVATE: u16 = 0x0002;
pub const ACC_PROTECTED: u16 = 0x0004;
pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_FINAL: u16 = 0x0010;
pub const ACC_SYNCHRONIZED: u16 = 0x0020;
pub const ACC_INTERFACE: u16 = 0x0200;
pub const ACC_ABSTRACT: u16 = 0x0400;
pub const ACC_NATIVE: u16 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    ClassFormat(ParseError),
    UnsupportedClassVersion {
        major: u16,
        minor: u16,
    },
    Verify(VerifyError),
    InvalidDescriptor(String),
    FloatingPointForbiddenInCldc10(String),
    NoClassDefFound(String),
    NoSuchMethod {
        class: String,
        name: String,
        descriptor: String,
    },
    NoSuchField {
        class: String,
        name: String,
    },
    IncompatibleClassChange(&'static str),
    Heap(HeapError),
}

impl From<ParseError> for LoaderError {
    fn from(e: ParseError) -> Self {
        Self::ClassFormat(e)
    }
}

impl From<VerifyError> for LoaderError {
    fn from(e: VerifyError) -> Self {
        Self::Verify(e)
    }
}

impl From<HeapError> for LoaderError {
    fn from(e: HeapError) -> Self {
        Self::Heap(e)
    }
}

/// Owned constant pool entry decoupled from the source `.class` byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpEntry {
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(u32),
    Long(i64),
    Double(u64),
    Class(String),
    StringLiteral(String),
    Fieldref {
        class: String,
        name: String,
        descriptor: String,
    },
    Methodref {
        class: String,
        name: String,
        descriptor: String,
    },
    InterfaceMethodref {
        class: String,
        name: String,
        descriptor: String,
    },
    NameAndType {
        name: String,
        descriptor: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub field_type: FieldType,
    pub access_flags: u16,
    /// Slot index inside either `LoadedClass::static_fields` or an instance's `fields`.
    pub slot_index: usize,
}

impl FieldInfo {
    pub const fn is_static(&self) -> bool {
        (self.access_flags & ACC_STATIC) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub parsed_descriptor: MethodDescriptor,
    pub access_flags: u16,
    pub code: Option<DecodedMethod>,
}

impl MethodInfo {
    pub const fn is_static(&self) -> bool {
        (self.access_flags & ACC_STATIC) != 0
    }

    pub const fn is_synchronized(&self) -> bool {
        (self.access_flags & ACC_SYNCHRONIZED) != 0
    }

    pub const fn is_native(&self) -> bool {
        (self.access_flags & ACC_NATIVE) != 0
    }

    pub const fn is_abstract(&self) -> bool {
        (self.access_flags & ACC_ABSTRACT) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassInitState {
    Prepared,
    Initializing(ThreadId),
    Initialized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedClass {
    pub id: ClassId,
    pub name: String,
    pub super_name: Option<String>,
    pub super_id: Option<ClassId>,
    pub interfaces: Vec<String>,
    pub access_flags: u16,
    pub init_state: ClassInitState,
    pub constant_pool: Vec<CpEntry>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub instance_field_count: usize,
    pub instance_field_defaults: Vec<Value>,
    pub static_fields: Vec<Value>,
    pub is_weak_reference: bool,
    pub source_hash: u64,
}

impl LoadedClass {
    pub const fn is_interface(&self) -> bool {
        (self.access_flags & ACC_INTERFACE) != 0
    }

    pub fn find_method(&self, name: &str, descriptor: &str) -> Option<usize> {
        self.methods
            .iter()
            .position(|m| m.name == name && m.descriptor == descriptor)
    }

    pub fn find_static_field(&self, name: &str, descriptor: &str) -> Option<&FieldInfo> {
        self.fields
            .iter()
            .find(|f| f.is_static() && f.name == name && f.descriptor == descriptor)
    }

    pub fn find_instance_field(&self, name: &str, descriptor: &str) -> Option<&FieldInfo> {
        self.fields
            .iter()
            .find(|f| !f.is_static() && f.name == name && f.descriptor == descriptor)
    }
}

/// Well-known bootstrap class IDs always present in a `VmContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WellKnownClasses {
    pub object: ClassId,
    pub string: ClassId,
    pub throwable: ClassId,
    pub null_pointer_exception: ClassId,
    pub arithmetic_exception: ClassId,
    pub array_index_out_of_bounds: ClassId,
    pub negative_array_size: ClassId,
    pub array_store_exception: ClassId,
    pub class_cast_exception: ClassId,
    pub illegal_monitor_state: ClassId,
    pub no_class_def_found_error: ClassId,
    pub out_of_memory_error: ClassId,
    pub weak_reference: Option<ClassId>,
}

/// Context-owned class loader: never relies on process-global static tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassLoader {
    pub(crate) classes: Vec<LoadedClass>,
    pub(crate) by_name: BTreeMap<String, ClassId>,
    pub(crate) well_known: WellKnownClasses,
}

impl ClassLoader {
    pub fn new(profile: &ProfileContract) -> Self {
        let mut loader = Self {
            classes: Vec::new(),
            by_name: BTreeMap::new(),
            well_known: WellKnownClasses {
                object: ClassId(0),
                string: ClassId(0),
                throwable: ClassId(0),
                null_pointer_exception: ClassId(0),
                arithmetic_exception: ClassId(0),
                array_index_out_of_bounds: ClassId(0),
                negative_array_size: ClassId(0),
                array_store_exception: ClassId(0),
                class_cast_exception: ClassId(0),
                illegal_monitor_state: ClassId(0),
                no_class_def_found_error: ClassId(0),
                out_of_memory_error: ClassId(0),
                weak_reference: None,
            },
        };

        let object = loader.register_bootstrap_class("java/lang/Object", None, ACC_PUBLIC, false);
        let string = loader.register_bootstrap_class(
            "java/lang/String",
            Some(object),
            ACC_PUBLIC | ACC_FINAL,
            false,
        );
        let throwable =
            loader.register_bootstrap_class("java/lang/Throwable", Some(object), ACC_PUBLIC, false);
        let exception = loader.register_bootstrap_class(
            "java/lang/Exception",
            Some(throwable),
            ACC_PUBLIC,
            false,
        );
        let runtime_ex = loader.register_bootstrap_class(
            "java/lang/RuntimeException",
            Some(exception),
            ACC_PUBLIC,
            false,
        );
        let error =
            loader.register_bootstrap_class("java/lang/Error", Some(throwable), ACC_PUBLIC, false);
        let vm_error = loader.register_bootstrap_class(
            "java/lang/VirtualMachineError",
            Some(error),
            ACC_PUBLIC | ACC_ABSTRACT,
            false,
        );

        let npe = loader.register_bootstrap_class(
            "java/lang/NullPointerException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let arith = loader.register_bootstrap_class(
            "java/lang/ArithmeticException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let aioobe = loader.register_bootstrap_class(
            "java/lang/ArrayIndexOutOfBoundsException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let neg_arr = loader.register_bootstrap_class(
            "java/lang/NegativeArraySizeException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let arr_store = loader.register_bootstrap_class(
            "java/lang/ArrayStoreException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let cce = loader.register_bootstrap_class(
            "java/lang/ClassCastException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let imse = loader.register_bootstrap_class(
            "java/lang/IllegalMonitorStateException",
            Some(runtime_ex),
            ACC_PUBLIC,
            false,
        );
        let ncdfe = loader.register_bootstrap_class(
            "java/lang/NoClassDefFoundError",
            Some(error),
            ACC_PUBLIC,
            false,
        );
        let oom = loader.register_bootstrap_class(
            "java/lang/OutOfMemoryError",
            Some(vm_error),
            ACC_PUBLIC,
            false,
        );

        // Register CLDC 1.1 weak references only when permitted by ProfileContract.
        let weak_reference = if profile.cldc.allows_weak_references() {
            let reference = loader.register_bootstrap_class(
                "java/lang/ref/Reference",
                Some(object),
                ACC_PUBLIC | ACC_ABSTRACT,
                true,
            );
            Some(loader.register_bootstrap_class(
                "java/lang/ref/WeakReference",
                Some(reference),
                ACC_PUBLIC,
                true,
            ))
        } else {
            None
        };

        loader.well_known = WellKnownClasses {
            object,
            string,
            throwable,
            null_pointer_exception: npe,
            arithmetic_exception: arith,
            array_index_out_of_bounds: aioobe,
            negative_array_size: neg_arr,
            array_store_exception: arr_store,
            class_cast_exception: cce,
            illegal_monitor_state: imse,
            no_class_def_found_error: ncdfe,
            out_of_memory_error: oom,
            weak_reference,
        };
        loader
    }

    pub fn well_known(&self) -> WellKnownClasses {
        self.well_known
    }

    pub fn class(&self, id: ClassId) -> Option<&LoadedClass> {
        self.classes.get(id.0 as usize)
    }

    pub fn class_mut(&mut self, id: ClassId) -> Option<&mut LoadedClass> {
        self.classes.get_mut(id.0 as usize)
    }

    pub fn find_class(&self, name: &str) -> Option<ClassId> {
        self.by_name.get(name).copied()
    }

    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    pub fn classes(&self) -> &[LoadedClass] {
        &self.classes
    }

    /// Computes a deterministic combined FNV-1a 64-bit hash over all loaded classes.
    pub fn combined_code_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for c in &self.classes {
            for b in c.source_hash.to_le_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
        }
        h
    }

    fn register_bootstrap_class(
        &mut self,
        name: &str,
        super_id: Option<ClassId>,
        access_flags: u16,
        is_weak_reference: bool,
    ) -> ClassId {
        let id = ClassId(self.classes.len() as u32);
        let super_name =
            super_id.and_then(|sid| self.classes.get(sid.0 as usize).map(|c| c.name.clone()));
        let class = LoadedClass {
            id,
            name: name.to_string(),
            super_name,
            super_id,
            interfaces: Vec::new(),
            access_flags,
            init_state: ClassInitState::Initialized,
            constant_pool: vec![CpEntry::Unusable],
            fields: Vec::new(),
            methods: Vec::new(),
            instance_field_count: 0,
            instance_field_defaults: Vec::new(),
            static_fields: Vec::new(),
            is_weak_reference,
            source_hash: fnv1a64(name.as_bytes()),
        };
        self.by_name.insert(name.to_string(), id);
        self.classes.push(class);
        id
    }

    /// Loads, structurally parses, verifies (with `ProfileContract`), and prepares
    /// a `.class` binary into this `VmContext`.
    pub fn load_class_bytes(
        &mut self,
        bytes: &[u8],
        profile: &ProfileContract,
        heap: &mut Heap,
    ) -> Result<ClassId, LoaderError> {
        let cf = parse_class(bytes)?;
        if !profile.admits_class_version(cf.major_version, cf.minor_version) {
            return Err(LoaderError::UnsupportedClassVersion {
                major: cf.major_version,
                minor: cf.minor_version,
            });
        }
        if (cf.access_flags & ACC_FINAL) != 0 && (cf.access_flags & ACC_ABSTRACT) != 0 {
            return Err(LoaderError::IncompatibleClassChange(
                "class cannot be both final and abstract",
            ));
        }

        let cp = resolve_constant_pool(&cf)?;
        let name = match cp.get(cf.this_class as usize) {
            Some(CpEntry::Class(n)) => n.clone(),
            _ => return Err(LoaderError::IncompatibleClassChange("invalid this_class")),
        };
        if let Some(existing) = self.by_name.get(&name) {
            return Ok(*existing);
        }

        let super_name = if cf.super_class == 0 {
            None
        } else {
            match cp.get(cf.super_class as usize) {
                Some(CpEntry::Class(n)) => Some(n.clone()),
                _ => return Err(LoaderError::IncompatibleClassChange("invalid super_class")),
            }
        };
        let super_id = super_name
            .as_deref()
            .and_then(|sn| self.by_name.get(sn).copied());

        let mut interfaces = Vec::with_capacity(cf.interfaces.len());
        for &iface_idx in &cf.interfaces {
            match cp.get(iface_idx as usize) {
                Some(CpEntry::Class(n)) => interfaces.push(n.clone()),
                _ => return Err(LoaderError::IncompatibleClassChange("invalid interface")),
            }
        }

        // Inherit instance field layout from superclass if already loaded.
        let mut instance_field_defaults = super_id
            .and_then(|sid| self.classes.get(sid.0 as usize))
            .map(|sc| sc.instance_field_defaults.clone())
            .unwrap_or_default();
        let mut is_weak_reference = super_id
            .and_then(|sid| self.classes.get(sid.0 as usize))
            .is_some_and(|sc| sc.is_weak_reference);
        if name == "java/lang/ref/WeakReference" || name == "java/lang/ref/Reference" {
            is_weak_reference = true;
        }

        let mut static_fields = Vec::new();
        let mut fields = Vec::with_capacity(cf.fields.len());

        for f in &cf.fields {
            let fname = cp_utf8(&cp, f.name_index)?;
            let fdesc = cp_utf8(&cp, f.descriptor_index)?;
            let ftype = parse_field_descriptor(&fdesc)
                .map_err(|_| LoaderError::InvalidDescriptor(fdesc.clone()))?;
            if !profile.cldc.allows_floating_point() && ftype.uses_floating_point() {
                return Err(LoaderError::FloatingPointForbiddenInCldc10(format!(
                    "{name}.{fname}:{fdesc}"
                )));
            }
            let is_static = (f.access_flags & ACC_STATIC) != 0;
            let slot_index = if is_static {
                let idx = static_fields.len();
                let mut val = Value::default_for(&ftype);
                // Initialize ConstantValue attribute (including interned String literals).
                for attr in &f.attributes {
                    if cf.utf8_bytes(attr.name_index) == Some(b"ConstantValue")
                        && attr.info.len() == 2
                    {
                        let cv_idx = u16::from_be_bytes([attr.info[0], attr.info[1]]);
                        val = match cp.get(cv_idx as usize) {
                            Some(CpEntry::Integer(i)) => Value::Int(*i),
                            Some(CpEntry::Long(l)) => Value::Long(*l),
                            Some(CpEntry::Float(bits)) => Value::Float(*bits),
                            Some(CpEntry::Double(bits)) => Value::Double(*bits),
                            Some(CpEntry::StringLiteral(s)) => {
                                let h = heap.intern_string(self.well_known.string, s)?;
                                Value::Ref(Some(h))
                            }
                            _ => val,
                        };
                    }
                }
                static_fields.push(val);
                idx
            } else {
                let idx = instance_field_defaults.len();
                instance_field_defaults.push(Value::default_for(&ftype));
                idx
            };

            fields.push(FieldInfo {
                name: fname,
                descriptor: fdesc,
                field_type: ftype,
                access_flags: f.access_flags,
                slot_index,
            });
        }

        let mut methods = Vec::with_capacity(cf.methods.len());
        for m in &cf.methods {
            let mname = cp_utf8(&cp, m.name_index)?;
            let mdesc = cp_utf8(&cp, m.descriptor_index)?;
            let parsed_descriptor = parse_method_descriptor(&mdesc)
                .map_err(|_| LoaderError::InvalidDescriptor(mdesc.clone()))?;
            if !profile.cldc.allows_floating_point() && parsed_descriptor.uses_floating_point() {
                return Err(LoaderError::FloatingPointForbiddenInCldc10(format!(
                    "{name}.{mname}{mdesc}"
                )));
            }
            let decoded = match &m.code {
                Some(code) => Some(decode_and_verify(&cf, code, profile)?),
                None => None,
            };
            methods.push(MethodInfo {
                name: mname,
                descriptor: mdesc,
                parsed_descriptor,
                access_flags: m.access_flags,
                code: decoded,
            });
        }

        let has_clinit = methods
            .iter()
            .any(|m| m.name == "<clinit>" && m.descriptor == "()V" && m.is_static());
        let id = ClassId(self.classes.len() as u32);
        let instance_field_count = instance_field_defaults.len();
        let loaded = LoadedClass {
            id,
            name: name.clone(),
            super_name,
            super_id,
            interfaces,
            access_flags: cf.access_flags,
            init_state: if has_clinit {
                ClassInitState::Prepared
            } else {
                ClassInitState::Initialized
            },
            constant_pool: cp,
            fields,
            methods,
            instance_field_count,
            instance_field_defaults,
            static_fields,
            is_weak_reference,
            source_hash: fnv1a64(bytes),
        };
        self.by_name.insert(name, id);
        self.classes.push(loaded);
        Ok(id)
    }

    /// Resolves a method walking up the superclass chain.
    pub fn resolve_method(
        &self,
        class_id: ClassId,
        name: &str,
        descriptor: &str,
    ) -> Option<(ClassId, usize)> {
        let mut cursor = Some(class_id);
        while let Some(cid) = cursor {
            let cls = self.classes.get(cid.0 as usize)?;
            if let Some(midx) = cls.find_method(name, descriptor) {
                return Some((cid, midx));
            }
            cursor = cls.super_id.or_else(|| {
                cls.super_name
                    .as_deref()
                    .and_then(|sn| self.by_name.get(sn).copied())
            });
        }
        None
    }

    /// Resolves an instance field walking up the superclass chain.
    pub fn resolve_instance_field(
        &self,
        class_id: ClassId,
        name: &str,
        descriptor: &str,
    ) -> Option<usize> {
        let mut cursor = Some(class_id);
        while let Some(cid) = cursor {
            let cls = self.classes.get(cid.0 as usize)?;
            if let Some(f) = cls.find_instance_field(name, descriptor) {
                return Some(f.slot_index);
            }
            cursor = cls.super_id.or_else(|| {
                cls.super_name
                    .as_deref()
                    .and_then(|sn| self.by_name.get(sn).copied())
            });
        }
        None
    }

    /// Resolves a static field walking up the superclass chain.
    pub fn resolve_static_field(
        &self,
        class_id: ClassId,
        name: &str,
        descriptor: &str,
    ) -> Option<(ClassId, usize)> {
        let mut cursor = Some(class_id);
        while let Some(cid) = cursor {
            let cls = self.classes.get(cid.0 as usize)?;
            if let Some(f) = cls.find_static_field(name, descriptor) {
                return Some((cid, f.slot_index));
            }
            cursor = cls.super_id.or_else(|| {
                cls.super_name
                    .as_deref()
                    .and_then(|sn| self.by_name.get(sn).copied())
            });
        }
        None
    }

    /// Checks Java assignability (`source instanceof target`), traversing superclasses
    /// and implemented interfaces.
    pub fn is_assignable_to(&self, source: ClassId, target: ClassId) -> bool {
        if source == target || target == self.well_known.object {
            return true;
        }
        let Some(target_cls) = self.classes.get(target.0 as usize) else {
            return false;
        };
        let target_name = target_cls.name.as_str();
        let mut cursor = Some(source);
        while let Some(cid) = cursor {
            if cid == target {
                return true;
            }
            let Some(cls) = self.classes.get(cid.0 as usize) else {
                break;
            };
            if cls.interfaces.iter().any(|iface| iface == target_name) {
                return true;
            }
            cursor = cls.super_id.or_else(|| {
                cls.super_name
                    .as_deref()
                    .and_then(|sn| self.by_name.get(sn).copied())
            });
        }
        false
    }

    /// Collects all strong heap handles stored inside class static fields.
    pub fn collect_gc_roots(&self, out: &mut Vec<super::value::Handle>) {
        for cls in &self.classes {
            for &val in &cls.static_fields {
                if let Value::Ref(Some(h)) = val {
                    out.push(h);
                }
            }
        }
    }
}

fn cp_utf8(cp: &[CpEntry], idx: u16) -> Result<String, LoaderError> {
    match cp.get(idx as usize) {
        Some(CpEntry::Utf8(s)) => Ok(s.clone()),
        _ => Err(LoaderError::IncompatibleClassChange(
            "expected Utf8 constant",
        )),
    }
}

fn resolve_constant_pool(cf: &ClassFile<'_>) -> Result<Vec<CpEntry>, LoaderError> {
    let utf8_at = |idx: u16| -> Result<String, LoaderError> {
        let raw = cf
            .utf8_bytes(idx)
            .ok_or(LoaderError::IncompatibleClassChange("bad utf8 index"))?;
        Ok(decode_modified_utf8(raw))
    };

    let class_name_at = |idx: u16| -> Result<String, LoaderError> {
        match cf.constant_pool.get(idx as usize) {
            Some(Constant::Class { name_index }) => utf8_at(*name_index),
            _ => Err(LoaderError::IncompatibleClassChange("bad class index")),
        }
    };

    let nat_at = |idx: u16| -> Result<(String, String), LoaderError> {
        match cf.constant_pool.get(idx as usize) {
            Some(Constant::NameAndType {
                name_index,
                descriptor_index,
            }) => Ok((utf8_at(*name_index)?, utf8_at(*descriptor_index)?)),
            _ => Err(LoaderError::IncompatibleClassChange(
                "bad NameAndType index",
            )),
        }
    };

    let mut out = Vec::with_capacity(cf.constant_pool.len());
    for entry in &cf.constant_pool {
        let resolved = match *entry {
            Constant::Unusable => CpEntry::Unusable,
            Constant::Utf8(raw) => CpEntry::Utf8(decode_modified_utf8(raw)),
            Constant::Integer(v) => CpEntry::Integer(v),
            Constant::Float(bits) => CpEntry::Float(bits),
            Constant::Long(v) => CpEntry::Long(v),
            Constant::Double(bits) => CpEntry::Double(bits),
            Constant::Class { name_index } => CpEntry::Class(utf8_at(name_index)?),
            Constant::String { string_index } => CpEntry::StringLiteral(utf8_at(string_index)?),
            Constant::Fieldref {
                class_index,
                name_and_type_index,
            } => {
                let class = class_name_at(class_index)?;
                let (name, descriptor) = nat_at(name_and_type_index)?;
                CpEntry::Fieldref {
                    class,
                    name,
                    descriptor,
                }
            }
            Constant::Methodref {
                class_index,
                name_and_type_index,
            } => {
                let class = class_name_at(class_index)?;
                let (name, descriptor) = nat_at(name_and_type_index)?;
                CpEntry::Methodref {
                    class,
                    name,
                    descriptor,
                }
            }
            Constant::InterfaceMethodref {
                class_index,
                name_and_type_index,
            } => {
                let class = class_name_at(class_index)?;
                let (name, descriptor) = nat_at(name_and_type_index)?;
                CpEntry::InterfaceMethodref {
                    class,
                    name,
                    descriptor,
                }
            }
            Constant::NameAndType {
                name_index,
                descriptor_index,
            } => CpEntry::NameAndType {
                name: utf8_at(name_index)?,
                descriptor: utf8_at(descriptor_index)?,
            },
        };
        out.push(resolved);
    }
    Ok(out)
}

/// Decodes JVM Modified UTF-8 into a Rust `String` (preserving U+0000 encoded as `0xC0 0x80`).
fn decode_modified_utf8(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 < 0x80 {
            units.push(u16::from(b0));
            i += 1;
        } else if (b0 & 0xe0) == 0xc0 && i + 1 < bytes.len() {
            let b1 = bytes[i + 1];
            units.push((u16::from(b0 & 0x1f) << 6) | u16::from(b1 & 0x3f));
            i += 2;
        } else if (b0 & 0xf0) == 0xe0 && i + 2 < bytes.len() {
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            units.push(
                (u16::from(b0 & 0x0f) << 12) | (u16::from(b1 & 0x3f) << 6) | u16::from(b2 & 0x3f),
            );
            i += 3;
        } else {
            units.push(0xfffd);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}
