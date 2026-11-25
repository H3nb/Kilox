// SPDX-License-Identifier: GPL-3.0-only
//! Core JVM values, generational logical object handles, typed frame slots,
//! and bounded JVM field/method descriptor parsing.

/// Stable, generation-checked logical handle to a heap-allocated object or
/// array. Never exposes a Rust memory address and survives GC and snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle {
    pub id: u32,
    pub gen: u32,
}

impl Handle {
    pub const fn new(id: u32, gen: u32) -> Self {
        Self { id, gen }
    }
}

/// Logical class identifier owned by a single `VmContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId(pub u32);

/// Logical virtual thread identifier owned by a single `VmContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u32);

/// JVM runtime value (Category-1 and Category-2 types).
/// Floating-point values store exact IEEE 754 bit patterns (`u32`/`u64`) so
/// NaN payloads and equality remain deterministic across snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Int(i32),
    Long(i64),
    Float(u32),
    Double(u64),
    Ref(Option<Handle>),
}

impl Value {
    pub const NULL: Self = Self::Ref(None);

    pub const fn default_for(ty: &FieldType) -> Self {
        match ty {
            FieldType::Boolean
            | FieldType::Byte
            | FieldType::Char
            | FieldType::Short
            | FieldType::Int => Self::Int(0),
            FieldType::Long => Self::Long(0),
            FieldType::Float => Self::Float(0),
            FieldType::Double => Self::Double(0),
            FieldType::Object(_) | FieldType::Array(_) => Self::Ref(None),
        }
    }

    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long(_) | Self::Double(_))
    }

    pub const fn as_int(self) -> Option<i32> {
        match self {
            Self::Int(v) => Some(v),
            _ => None,
        }
    }

    pub const fn as_long(self) -> Option<i64> {
        match self {
            Self::Long(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_f32(self) -> Option<f32> {
        match self {
            Self::Float(bits) => Some(f32::from_bits(bits)),
            _ => None,
        }
    }

    pub fn as_f64(self) -> Option<f64> {
        match self {
            Self::Double(bits) => Some(f64::from_bits(bits)),
            _ => None,
        }
    }

    pub const fn as_ref(self) -> Option<Option<Handle>> {
        match self {
            Self::Ref(h) => Some(h),
            _ => None,
        }
    }

    pub fn from_f32(v: f32) -> Self {
        if v.is_nan() {
            Self::Float(0x7fc0_0000)
        } else {
            Self::Float(v.to_bits())
        }
    }

    pub fn from_f64(v: f64) -> Self {
        if v.is_nan() {
            Self::Double(0x7ff8_0000_0000_0000)
        } else {
            Self::Double(v.to_bits())
        }
    }
}

/// Typed slot used inside VM-owned local variables and operand stacks.
/// Category-2 values (`Long`, `Double`) occupy one value slot followed by `Top`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Empty,
    Int(i32),
    Long(i64),
    Float(u32),
    Double(u64),
    Ref(Option<Handle>),
    Top,
}

impl Slot {
    pub const fn from_value(v: Value) -> Self {
        match v {
            Value::Int(x) => Self::Int(x),
            Value::Long(x) => Self::Long(x),
            Value::Float(x) => Self::Float(x),
            Value::Double(x) => Self::Double(x),
            Value::Ref(h) => Self::Ref(h),
        }
    }

    pub const fn to_value(self) -> Option<Value> {
        match self {
            Self::Int(x) => Some(Value::Int(x)),
            Self::Long(x) => Some(Value::Long(x)),
            Self::Float(x) => Some(Value::Float(x)),
            Self::Double(x) => Some(Value::Double(x)),
            Self::Ref(h) => Some(Value::Ref(h)),
            Self::Empty | Self::Top => None,
        }
    }
}

/// Parsed JVM field type descriptor (JVMS 2nd ed. §4.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldType {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object(String),
    Array(Box<FieldType>),
}

impl FieldType {
    pub const fn is_category2(&self) -> bool {
        matches!(self, Self::Long | Self::Double)
    }

    pub const fn uses_floating_point(&self) -> bool {
        matches!(self, Self::Float | Self::Double)
    }

    pub fn to_descriptor(&self) -> String {
        match self {
            Self::Boolean => "Z".to_string(),
            Self::Byte => "B".to_string(),
            Self::Char => "C".to_string(),
            Self::Short => "S".to_string(),
            Self::Int => "I".to_string(),
            Self::Long => "J".to_string(),
            Self::Float => "F".to_string(),
            Self::Double => "D".to_string(),
            Self::Object(name) => format!("L{name};"),
            Self::Array(elem) => format!("[{}", elem.to_descriptor()),
        }
    }
}

/// Parsed JVM method descriptor (JVMS 2nd ed. §4.3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodDescriptor {
    pub params: Vec<FieldType>,
    pub return_type: Option<FieldType>,
}

impl MethodDescriptor {
    /// Total local-variable slots required for parameters (excluding `this`).
    pub fn param_slot_count(&self) -> usize {
        self.params
            .iter()
            .map(|p| if p.is_category2() { 2 } else { 1 })
            .sum()
    }

    pub fn uses_floating_point(&self) -> bool {
        self.params.iter().any(FieldType::uses_floating_point)
            || self
                .return_type
                .as_ref()
                .is_some_and(FieldType::uses_floating_point)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    Empty,
    TooDeep,
    InvalidSyntax,
    TrailingBytes,
}

const MAX_ARRAY_DIMENSIONS: usize = 255;

pub fn parse_field_descriptor(raw: &str) -> Result<FieldType, DescriptorError> {
    if raw.is_empty() {
        return Err(DescriptorError::Empty);
    }
    let bytes = raw.as_bytes();
    let (ty, next) = parse_field_at(bytes, 0, 0)?;
    if next != bytes.len() {
        return Err(DescriptorError::TrailingBytes);
    }
    Ok(ty)
}

pub fn parse_method_descriptor(raw: &str) -> Result<MethodDescriptor, DescriptorError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return Err(DescriptorError::InvalidSyntax);
    }
    let mut pos = 1;
    let mut params = Vec::new();
    while pos < bytes.len() && bytes[pos] != b')' {
        let (ty, next) = parse_field_at(bytes, pos, 0)?;
        params.push(ty);
        pos = next;
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return Err(DescriptorError::InvalidSyntax);
    }
    pos += 1;
    if pos >= bytes.len() {
        return Err(DescriptorError::InvalidSyntax);
    }
    let return_type = if bytes[pos] == b'V' {
        pos += 1;
        None
    } else {
        let (ty, next) = parse_field_at(bytes, pos, 0)?;
        pos = next;
        Some(ty)
    };
    if pos != bytes.len() {
        return Err(DescriptorError::TrailingBytes);
    }
    Ok(MethodDescriptor {
        params,
        return_type,
    })
}

fn parse_field_at(
    bytes: &[u8],
    pos: usize,
    depth: usize,
) -> Result<(FieldType, usize), DescriptorError> {
    if depth > MAX_ARRAY_DIMENSIONS {
        return Err(DescriptorError::TooDeep);
    }
    if pos >= bytes.len() {
        return Err(DescriptorError::InvalidSyntax);
    }
    match bytes[pos] {
        b'Z' => Ok((FieldType::Boolean, pos + 1)),
        b'B' => Ok((FieldType::Byte, pos + 1)),
        b'C' => Ok((FieldType::Char, pos + 1)),
        b'S' => Ok((FieldType::Short, pos + 1)),
        b'I' => Ok((FieldType::Int, pos + 1)),
        b'J' => Ok((FieldType::Long, pos + 1)),
        b'F' => Ok((FieldType::Float, pos + 1)),
        b'D' => Ok((FieldType::Double, pos + 1)),
        b'L' => {
            let start = pos + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b';' {
                end += 1;
            }
            if end == start || end >= bytes.len() {
                return Err(DescriptorError::InvalidSyntax);
            }
            let name = std::str::from_utf8(&bytes[start..end])
                .map_err(|_| DescriptorError::InvalidSyntax)?;
            Ok((FieldType::Object(name.to_string()), end + 1))
        }
        b'[' => {
            let (elem, next) = parse_field_at(bytes, pos + 1, depth + 1)?;
            Ok((FieldType::Array(Box::new(elem)), next))
        }
        _ => Err(DescriptorError::InvalidSyntax),
    }
}
