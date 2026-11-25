// SPDX-License-Identifier: GPL-3.0-only
//! CLDC 1.0/1.1 bytecode decoder, legacy `StackMap` parser, and abstract
//! operand-stack / control-flow verifier.
//!
//! Decodes JVMS 2nd Edition / CLDC opcodes into validated VM instructions,
//! parses legacy CLDC `StackMap` attributes (distinct from Java SE 6
//! `StackMapTable`), enforces `ProfileContract` edition rules (such as
//! forbidding floating-point opcodes in CLDC 1.0), validates branch, switch,
//! and exception-handler boundaries, and verifies operand-stack depth,
//! underflow/overflow, merge consistency, and fallthrough safety at class
//! admission.

use std::collections::{BTreeMap, VecDeque};

use crate::classfile::{ClassFile, Code, Constant, ExceptionHandler};

use super::profile::ProfileContract;
use super::value::{parse_field_descriptor, parse_method_descriptor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyErrorKind {
    UnsupportedOpcode(u8),
    ForbiddenInCldc10(u8),
    TruncatedInstruction,
    InvalidWideTarget(u8),
    InvalidBranchTarget(i32),
    InvalidExceptionRange,
    InvalidStackMap(&'static str),
    MissingRequiredStackMap,
    InvalidSwitchTable,
    LocalOutOfBounds(u16),
    CodeTooLarge,
    InvalidConstantPoolRef(u16),
    StackUnderflow,
    StackOverflow,
    InconsistentStackJoin,
    FallthroughOffEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub pc: usize,
    pub kind: VerifyErrorKind,
}

impl VerifyError {
    pub const fn new(pc: usize, kind: VerifyErrorKind) -> Self {
        Self { pc, kind }
    }
}

/// Legacy CLDC `StackMap` verification type tags (CLDC 1.0/1.1 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationType {
    Top,
    Integer,
    Float,
    Double,
    Long,
    Null,
    UninitializedThis,
    Object { cp_index: u16 },
    Uninitialized { offset: u16 },
}

impl VerificationType {
    const fn slot_width(self) -> usize {
        match self {
            Self::Long | Self::Double => 2,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackMapFrame {
    pub offset: u16,
    pub locals: Vec<VerificationType>,
    pub stack: Vec<VerificationType>,
}

impl StackMapFrame {
    fn locals_slots(&self) -> usize {
        self.locals.iter().map(|t| t.slot_width()).sum()
    }

    fn stack_slots(&self) -> usize {
        self.stack.iter().map(|t| t.slot_width()).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntCmp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Nop,
    AConstNull,
    IConst(i32),
    LConst(i64),
    FConst(u32),
    DConst(u64),
    Ldc(u16),
    Ldc2W(u16),

    ILoad(u16),
    LLoad(u16),
    FLoad(u16),
    DLoad(u16),
    ALoad(u16),

    IALoad,
    LALoad,
    FALoad,
    DALoad,
    AALoad,
    BALoad,
    CALoad,
    SALoad,

    IStore(u16),
    LStore(u16),
    FStore(u16),
    DStore(u16),
    AStore(u16),

    IAStore,
    LAStore,
    FAStore,
    DAStore,
    AAStore,
    BAStore,
    CAStore,
    SAStore,

    Pop,
    Pop2,
    Dup,
    DupX1,
    DupX2,
    Dup2,
    Dup2X1,
    Dup2X2,
    Swap,

    IAdd,
    LAdd,
    FAdd,
    DAdd,
    ISub,
    LSub,
    FSub,
    DSub,
    IMul,
    LMul,
    FMul,
    DMul,
    IDiv,
    LDiv,
    FDiv,
    DDiv,
    IRem,
    LRem,
    FRem,
    DRem,
    INeg,
    LNeg,
    FNeg,
    DNeg,

    IShl,
    LShl,
    IShr,
    LShr,
    IUShr,
    LUShr,
    IAnd,
    LAnd,
    IOr,
    LOr,
    IXor,
    LXor,
    IInc {
        index: u16,
        delta: i16,
    },

    I2L,
    I2F,
    I2D,
    L2I,
    L2F,
    L2D,
    F2I,
    F2L,
    F2D,
    D2I,
    D2L,
    D2F,
    I2B,
    I2C,
    I2S,

    LCmp,
    FCmpL,
    FCmpG,
    DCmpL,
    DCmpG,

    IfZero(IntCmp, usize),
    IfICmp(IntCmp, usize),
    IfACmpEq(usize),
    IfACmpNe(usize),
    IfNull(usize),
    IfNonNull(usize),
    Goto(usize),

    TableSwitch {
        default_ip: usize,
        low: i32,
        high: i32,
        targets: Vec<usize>,
    },
    LookupSwitch {
        default_ip: usize,
        pairs: Vec<(i32, usize)>,
    },

    IReturn,
    LReturn,
    FReturn,
    DReturn,
    AReturn,
    Return,

    GetStatic(u16),
    PutStatic(u16),
    GetField(u16),
    PutField(u16),

    InvokeVirtual(u16),
    InvokeSpecial(u16),
    InvokeStatic(u16),
    InvokeInterface {
        cp_index: u16,
        count: u8,
    },

    New(u16),
    NewArray(u8),
    ANewArray(u16),
    ArrayLength,
    AThrow,
    CheckCast(u16),
    InstanceOf(u16),
    MonitorEnter,
    MonitorExit,
    MultiANewArray {
        cp_index: u16,
        dimensions: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub pc: u16,
    pub op: Op,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_ip: usize,
    pub handler_pc: u16,
    pub catch_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedMethod {
    pub max_stack: u16,
    pub max_locals: u16,
    pub instructions: Vec<DecodedInstruction>,
    pub exceptions: Vec<VerifiedExceptionHandler>,
    pub stack_map: Vec<StackMapFrame>,
}

const MAX_METHOD_CODE_LEN: usize = 65_535;

/// Parses a legacy CLDC `StackMap` attribute payload.
pub fn parse_legacy_stack_map(
    bytes: &[u8],
    profile: &ProfileContract,
) -> Result<Vec<StackMapFrame>, VerifyError> {
    let mut pos = 0usize;
    let count = read_u16(bytes, &mut pos)
        .ok_or_else(|| VerifyError::new(0, VerifyErrorKind::InvalidStackMap("truncated count")))?;
    let mut frames = Vec::with_capacity((count as usize).min(256));
    for _ in 0..count {
        let offset = read_u16(bytes, &mut pos).ok_or_else(|| {
            VerifyError::new(pos, VerifyErrorKind::InvalidStackMap("truncated offset"))
        })?;
        let locals = read_vtype_list(bytes, &mut pos, profile)?;
        let stack = read_vtype_list(bytes, &mut pos, profile)?;
        frames.push(StackMapFrame {
            offset,
            locals,
            stack,
        });
    }
    if pos != bytes.len() {
        return Err(VerifyError::new(
            pos,
            VerifyErrorKind::InvalidStackMap("trailing bytes"),
        ));
    }
    Ok(frames)
}

fn read_vtype_list(
    bytes: &[u8],
    pos: &mut usize,
    profile: &ProfileContract,
) -> Result<Vec<VerificationType>, VerifyError> {
    let n = read_u16(bytes, pos).ok_or_else(|| {
        VerifyError::new(*pos, VerifyErrorKind::InvalidStackMap("truncated list"))
    })?;
    let mut out = Vec::with_capacity((n as usize).min(64));
    for _ in 0..n {
        let tag = read_u8(bytes, pos).ok_or_else(|| {
            VerifyError::new(*pos, VerifyErrorKind::InvalidStackMap("truncated tag"))
        })?;
        let vtype = match tag {
            0 => VerificationType::Top,
            1 => VerificationType::Integer,
            2 => {
                if !profile.cldc.allows_floating_point() {
                    return Err(VerifyError::new(
                        *pos,
                        VerifyErrorKind::InvalidStackMap("float forbidden in CLDC 1.0"),
                    ));
                }
                VerificationType::Float
            }
            3 => {
                if !profile.cldc.allows_floating_point() {
                    return Err(VerifyError::new(
                        *pos,
                        VerifyErrorKind::InvalidStackMap("double forbidden in CLDC 1.0"),
                    ));
                }
                VerificationType::Double
            }
            4 => VerificationType::Long,
            5 => VerificationType::Null,
            6 => VerificationType::UninitializedThis,
            7 => {
                let cp_index = read_u16(bytes, pos).ok_or_else(|| {
                    VerifyError::new(*pos, VerifyErrorKind::InvalidStackMap("truncated cp_index"))
                })?;
                VerificationType::Object { cp_index }
            }
            8 => {
                let offset = read_u16(bytes, pos).ok_or_else(|| {
                    VerifyError::new(
                        *pos,
                        VerifyErrorKind::InvalidStackMap("truncated new offset"),
                    )
                })?;
                VerificationType::Uninitialized { offset }
            }
            _ => {
                return Err(VerifyError::new(
                    *pos,
                    VerifyErrorKind::InvalidStackMap("unknown verification type tag"),
                ));
            }
        };
        out.push(vtype);
    }
    Ok(out)
}

/// Decodes and validates a method's `Code` attribute under `ProfileContract`.
pub fn decode_and_verify(
    class: &ClassFile<'_>,
    code: &Code<'_>,
    profile: &ProfileContract,
) -> Result<DecodedMethod, VerifyError> {
    let bytes = code.instructions;
    if bytes.is_empty() || bytes.len() > MAX_METHOD_CODE_LEN {
        return Err(VerifyError::new(0, VerifyErrorKind::CodeTooLarge));
    }

    // Parse legacy `StackMap` attribute if present on the Code attribute.
    let mut stack_map = Vec::new();
    for attr in &code.attributes {
        if class.utf8_bytes(attr.name_index) == Some(b"StackMap") {
            stack_map = parse_legacy_stack_map(attr.info, profile)?;
            break;
        }
    }

    // Pass 1: Decode raw instructions and record exact PC -> instruction index.
    let mut raw_ops: Vec<(u16, RawOp)> = Vec::new();
    let mut pc_to_ip: BTreeMap<u16, usize> = BTreeMap::new();
    let mut pos = 0usize;
    let mut has_branch = false;

    while pos < bytes.len() {
        let start_pc = pos;
        let pc_u16 = u16::try_from(start_pc)
            .map_err(|_| VerifyError::new(start_pc, VerifyErrorKind::CodeTooLarge))?;
        pc_to_ip.insert(pc_u16, raw_ops.len());
        let opcode = bytes[pos];
        pos += 1;

        if !profile.cldc.allows_floating_point() && is_float_or_double_opcode(opcode) {
            return Err(VerifyError::new(
                start_pc,
                VerifyErrorKind::ForbiddenInCldc10(opcode),
            ));
        }

        let raw = decode_one(opcode, start_pc, bytes, &mut pos, code.max_locals, profile)?;
        if raw.is_branch() {
            has_branch = true;
        }
        raw_ops.push((pc_u16, raw));
    }

    if profile.require_stack_map && has_branch && stack_map.is_empty() {
        return Err(VerifyError::new(0, VerifyErrorKind::MissingRequiredStackMap));
    }

    // Validate legacy StackMap target offsets and declared slot bounds.
    let mut stack_map_by_ip: BTreeMap<usize, usize> = BTreeMap::new();
    for frame in &stack_map {
        let Some(&ip) = pc_to_ip.get(&frame.offset) else {
            return Err(VerifyError::new(
                frame.offset as usize,
                VerifyErrorKind::InvalidStackMap("frame offset not on instruction boundary"),
            ));
        };
        if frame.locals_slots() > usize::from(code.max_locals)
            || frame.stack_slots() > usize::from(code.max_stack)
        {
            return Err(VerifyError::new(
                frame.offset as usize,
                VerifyErrorKind::InvalidStackMap("frame exceeds max_locals or max_stack"),
            ));
        }
        stack_map_by_ip.insert(ip, frame.stack_slots());
    }

    // Pass 2: Resolve branch & switch bytecode offsets to instruction indices.
    let mut instructions = Vec::with_capacity(raw_ops.len());
    for (pc, raw) in raw_ops {
        let op = resolve_raw_op(pc, raw, &pc_to_ip)?;
        instructions.push(DecodedInstruction { pc, op });
    }

    // Validate exception handler boundaries.
    let mut exceptions = Vec::with_capacity(code.exceptions.len());
    for h in &code.exceptions {
        exceptions.push(verify_exception_handler(h, bytes.len(), &pc_to_ip)?);
    }

    // Pass 3: Abstract operand-stack depth & control-flow verification.
    verify_stack_and_control_flow(
        class,
        &instructions,
        &exceptions,
        &stack_map_by_ip,
        usize::from(code.max_stack),
    )?;

    Ok(DecodedMethod {
        max_stack: code.max_stack,
        max_locals: code.max_locals,
        instructions,
        exceptions,
        stack_map,
    })
}

/// Abstract worklist verifier ensuring operand-stack underflow, overflow,
/// merge-depth mismatches, invalid constant-pool refs, and fallthrough off end
/// are rejected at class admission.
fn verify_stack_and_control_flow(
    class: &ClassFile<'_>,
    instructions: &[DecodedInstruction],
    exceptions: &[VerifiedExceptionHandler],
    stack_map_by_ip: &BTreeMap<usize, usize>,
    max_stack: usize,
) -> Result<(), VerifyError> {
    let mut known_depth: Vec<Option<usize>> = vec![None; instructions.len()];
    let mut worklist: VecDeque<usize> = VecDeque::new();

    if !instructions.is_empty() {
        known_depth[0] = Some(0);
        worklist.push_back(0);
    }
    for h in exceptions {
        if 1 > max_stack {
            return Err(VerifyError::new(
                h.handler_pc as usize,
                VerifyErrorKind::StackOverflow,
            ));
        }
        enqueue_depth(
            h.handler_ip,
            h.handler_pc as usize,
            1,
            &mut known_depth,
            &mut worklist,
        )?;
    }

    while let Some(ip) = worklist.pop_front() {
        let instr = &instructions[ip];
        let pc = instr.pc as usize;
        let depth = known_depth[ip].expect("worklist entry has depth");

        if let Some(&declared_stack) = stack_map_by_ip.get(&ip) {
            if declared_stack != depth {
                return Err(VerifyError::new(pc, VerifyErrorKind::InconsistentStackJoin));
            }
        }

        let effect = instruction_stack_effect(class, pc, &instr.op)?;
        if depth < effect.min_pop {
            return Err(VerifyError::new(pc, VerifyErrorKind::StackUnderflow));
        }
        let next_depth_signed = (depth as isize) + effect.delta;
        if next_depth_signed < 0 {
            return Err(VerifyError::new(pc, VerifyErrorKind::StackUnderflow));
        }
        let next_depth = next_depth_signed as usize;
        if next_depth > max_stack {
            return Err(VerifyError::new(pc, VerifyErrorKind::StackOverflow));
        }

        for target in effect.targets {
            enqueue_depth(target, pc, next_depth, &mut known_depth, &mut worklist)?;
        }

        if effect.falls_through {
            let next_ip = ip + 1;
            if next_ip >= instructions.len() {
                return Err(VerifyError::new(pc, VerifyErrorKind::FallthroughOffEnd));
            }
            enqueue_depth(next_ip, pc, next_depth, &mut known_depth, &mut worklist)?;
        }
    }

    Ok(())
}

fn enqueue_depth(
    target_ip: usize,
    source_pc: usize,
    depth: usize,
    known_depth: &mut [Option<usize>],
    worklist: &mut VecDeque<usize>,
) -> Result<(), VerifyError> {
    match known_depth[target_ip] {
        None => {
            known_depth[target_ip] = Some(depth);
            worklist.push_back(target_ip);
            Ok(())
        }
        Some(existing) if existing == depth => Ok(()),
        Some(_) => Err(VerifyError::new(
            source_pc,
            VerifyErrorKind::InconsistentStackJoin,
        )),
    }
}

struct StackEffect {
    min_pop: usize,
    delta: isize,
    falls_through: bool,
    targets: Vec<usize>,
}

impl StackEffect {
    fn linear(min_pop: usize, delta: isize) -> Self {
        Self {
            min_pop,
            delta,
            falls_through: true,
            targets: Vec::new(),
        }
    }

    fn terminal(min_pop: usize, delta: isize) -> Self {
        Self {
            min_pop,
            delta,
            falls_through: false,
            targets: Vec::new(),
        }
    }

    fn branch(min_pop: usize, delta: isize, target: usize, falls_through: bool) -> Self {
        Self {
            min_pop,
            delta,
            falls_through,
            targets: vec![target],
        }
    }
}

fn instruction_stack_effect(
    class: &ClassFile<'_>,
    pc: usize,
    op: &Op,
) -> Result<StackEffect, VerifyError> {
    Ok(match op {
        Op::Nop | Op::IInc { .. } => StackEffect::linear(0, 0),
        Op::AConstNull
        | Op::IConst(_)
        | Op::FConst(_)
        | Op::ILoad(_)
        | Op::FLoad(_)
        | Op::ALoad(_) => StackEffect::linear(0, 1),
        Op::LConst(_) | Op::DConst(_) | Op::LLoad(_) | Op::DLoad(_) => StackEffect::linear(0, 2),

        Op::Ldc(cp_idx) => {
            match class.constant_pool.get(*cp_idx as usize) {
                Some(Constant::Integer(_) | Constant::Float(_) | Constant::String { .. }) => {}
                _ => {
                    return Err(VerifyError::new(
                        pc,
                        VerifyErrorKind::InvalidConstantPoolRef(*cp_idx),
                    ));
                }
            }
            StackEffect::linear(0, 1)
        }
        Op::Ldc2W(cp_idx) => {
            match class.constant_pool.get(*cp_idx as usize) {
                Some(Constant::Long(_) | Constant::Double(_)) => {}
                _ => {
                    return Err(VerifyError::new(
                        pc,
                        VerifyErrorKind::InvalidConstantPoolRef(*cp_idx),
                    ));
                }
            }
            StackEffect::linear(0, 2)
        }

        Op::IALoad | Op::FALoad | Op::AALoad | Op::BALoad | Op::CALoad | Op::SALoad => {
            StackEffect::linear(2, -1)
        }
        Op::LALoad | Op::DALoad => StackEffect::linear(2, 0),

        Op::IStore(_) | Op::FStore(_) | Op::AStore(_) => StackEffect::linear(1, -1),
        Op::LStore(_) | Op::DStore(_) => StackEffect::linear(2, -2),

        Op::IAStore | Op::FAStore | Op::AAStore | Op::BAStore | Op::CAStore | Op::SAStore => {
            StackEffect::linear(3, -3)
        }
        Op::LAStore | Op::DAStore => StackEffect::linear(4, -4),

        Op::Pop => StackEffect::linear(1, -1),
        Op::Pop2 => StackEffect::linear(2, -2),
        Op::Dup => StackEffect::linear(1, 1),
        Op::DupX1 => StackEffect::linear(2, 1),
        Op::DupX2 => StackEffect::linear(3, 1),
        Op::Dup2 => StackEffect::linear(2, 2),
        Op::Dup2X1 => StackEffect::linear(3, 2),
        Op::Dup2X2 => StackEffect::linear(4, 2),
        Op::Swap => StackEffect::linear(2, 0),

        Op::IAdd
        | Op::ISub
        | Op::IMul
        | Op::IDiv
        | Op::IRem
        | Op::IShl
        | Op::IShr
        | Op::IUShr
        | Op::IAnd
        | Op::IOr
        | Op::IXor
        | Op::FAdd
        | Op::FSub
        | Op::FMul
        | Op::FDiv
        | Op::FRem
        | Op::FCmpL
        | Op::FCmpG => StackEffect::linear(2, -1),

        Op::LAdd
        | Op::LSub
        | Op::LMul
        | Op::LDiv
        | Op::LRem
        | Op::LAnd
        | Op::LOr
        | Op::LXor
        | Op::DAdd
        | Op::DSub
        | Op::DMul
        | Op::DDiv
        | Op::DRem => StackEffect::linear(4, -2),

        Op::LShl | Op::LShr | Op::LUShr => StackEffect::linear(3, -1),
        Op::LCmp | Op::DCmpL | Op::DCmpG => StackEffect::linear(4, -3),

        Op::INeg
        | Op::FNeg
        | Op::I2F
        | Op::F2I
        | Op::I2B
        | Op::I2C
        | Op::I2S
        | Op::ArrayLength
        | Op::NewArray(_) => StackEffect::linear(1, 0),
        Op::LNeg | Op::DNeg | Op::L2D | Op::D2L => StackEffect::linear(2, 0),
        Op::I2L | Op::I2D | Op::F2L | Op::F2D => StackEffect::linear(1, 1),
        Op::L2I | Op::L2F | Op::D2I | Op::D2F => StackEffect::linear(2, -1),

        Op::IfZero(_, t) | Op::IfNull(t) | Op::IfNonNull(t) => StackEffect::branch(1, -1, *t, true),
        Op::IfICmp(_, t) | Op::IfACmpEq(t) | Op::IfACmpNe(t) => {
            StackEffect::branch(2, -2, *t, true)
        }
        Op::Goto(t) => StackEffect::branch(0, 0, *t, false),
        Op::TableSwitch {
            default_ip,
            targets,
            ..
        } => {
            let mut all = Vec::with_capacity(targets.len() + 1);
            all.push(*default_ip);
            all.extend_from_slice(targets);
            StackEffect {
                min_pop: 1,
                delta: -1,
                falls_through: false,
                targets: all,
            }
        }
        Op::LookupSwitch { default_ip, pairs } => {
            let mut all = Vec::with_capacity(pairs.len() + 1);
            all.push(*default_ip);
            for &(_, t) in pairs {
                all.push(t);
            }
            StackEffect {
                min_pop: 1,
                delta: -1,
                falls_through: false,
                targets: all,
            }
        }

        Op::IReturn | Op::FReturn | Op::AReturn | Op::AThrow => StackEffect::terminal(1, -1),
        Op::LReturn | Op::DReturn => StackEffect::terminal(2, -2),
        Op::Return => StackEffect::terminal(0, 0),

        Op::GetStatic(cp_idx) => {
            let slots = cp_field_slots(class, pc, *cp_idx)?;
            StackEffect::linear(0, slots as isize)
        }
        Op::PutStatic(cp_idx) => {
            let slots = cp_field_slots(class, pc, *cp_idx)?;
            StackEffect::linear(slots, -(slots as isize))
        }
        Op::GetField(cp_idx) => {
            let slots = cp_field_slots(class, pc, *cp_idx)?;
            StackEffect::linear(1, (slots as isize) - 1)
        }
        Op::PutField(cp_idx) => {
            let slots = cp_field_slots(class, pc, *cp_idx)?;
            StackEffect::linear(1 + slots, -((1 + slots) as isize))
        }

        Op::InvokeStatic(cp_idx) => {
            let (param_slots, ret_slots) = cp_method_slots(class, pc, *cp_idx, false)?;
            StackEffect::linear(param_slots, (ret_slots as isize) - (param_slots as isize))
        }
        Op::InvokeVirtual(cp_idx) | Op::InvokeSpecial(cp_idx) => {
            let (param_slots, ret_slots) = cp_method_slots(class, pc, *cp_idx, false)?;
            let pop = 1 + param_slots;
            StackEffect::linear(pop, (ret_slots as isize) - (pop as isize))
        }
        Op::InvokeInterface { cp_index, .. } => {
            let (param_slots, ret_slots) = cp_method_slots(class, pc, *cp_index, true)?;
            let pop = 1 + param_slots;
            StackEffect::linear(pop, (ret_slots as isize) - (pop as isize))
        }

        Op::New(cp_idx) => {
            require_class_cp(class, pc, *cp_idx)?;
            StackEffect::linear(0, 1)
        }
        Op::ANewArray(cp_idx) | Op::CheckCast(cp_idx) | Op::InstanceOf(cp_idx) => {
            require_class_cp(class, pc, *cp_idx)?;
            StackEffect::linear(1, 0)
        }
        Op::MultiANewArray {
            cp_index,
            dimensions,
        } => {
            require_class_cp(class, pc, *cp_index)?;
            let dims = usize::from(*dimensions);
            StackEffect::linear(dims, 1 - (dims as isize))
        }
        Op::MonitorEnter | Op::MonitorExit => StackEffect::linear(1, -1),
    })
}

fn require_class_cp(class: &ClassFile<'_>, pc: usize, cp_idx: u16) -> Result<(), VerifyError> {
    match class.constant_pool.get(cp_idx as usize) {
        Some(Constant::Class { .. }) => Ok(()),
        _ => Err(VerifyError::new(
            pc,
            VerifyErrorKind::InvalidConstantPoolRef(cp_idx),
        )),
    }
}

fn cp_field_slots(class: &ClassFile<'_>, pc: usize, cp_idx: u16) -> Result<usize, VerifyError> {
    let nat_idx = match class.constant_pool.get(cp_idx as usize) {
        Some(Constant::Fieldref {
            name_and_type_index,
            ..
        }) => *name_and_type_index,
        _ => {
            return Err(VerifyError::new(
                pc,
                VerifyErrorKind::InvalidConstantPoolRef(cp_idx),
            ));
        }
    };
    let desc_idx = match class.constant_pool.get(nat_idx as usize) {
        Some(Constant::NameAndType {
            descriptor_index, ..
        }) => *descriptor_index,
        _ => {
            return Err(VerifyError::new(
                pc,
                VerifyErrorKind::InvalidConstantPoolRef(cp_idx),
            ));
        }
    };
    let raw = class
        .utf8_bytes(desc_idx)
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| VerifyError::new(pc, VerifyErrorKind::InvalidConstantPoolRef(cp_idx)))?;
    let ty = parse_field_descriptor(raw)
        .map_err(|_| VerifyError::new(pc, VerifyErrorKind::InvalidConstantPoolRef(cp_idx)))?;
    Ok(if ty.is_category2() { 2 } else { 1 })
}

fn cp_method_slots(
    class: &ClassFile<'_>,
    pc: usize,
    cp_idx: u16,
    is_interface: bool,
) -> Result<(usize, usize), VerifyError> {
    let nat_idx = match class.constant_pool.get(cp_idx as usize) {
        Some(Constant::Methodref {
            name_and_type_index,
            ..
        }) if !is_interface => *name_and_type_index,
        Some(Constant::InterfaceMethodref {
            name_and_type_index,
            ..
        }) if is_interface => *name_and_type_index,
        _ => {
            return Err(VerifyError::new(
                pc,
                VerifyErrorKind::InvalidConstantPoolRef(cp_idx),
            ));
        }
    };
    let desc_idx = match class.constant_pool.get(nat_idx as usize) {
        Some(Constant::NameAndType {
            descriptor_index, ..
        }) => *descriptor_index,
        _ => {
            return Err(VerifyError::new(
                pc,
                VerifyErrorKind::InvalidConstantPoolRef(cp_idx),
            ));
        }
    };
    let raw = class
        .utf8_bytes(desc_idx)
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| VerifyError::new(pc, VerifyErrorKind::InvalidConstantPoolRef(cp_idx)))?;
    let desc = parse_method_descriptor(raw)
        .map_err(|_| VerifyError::new(pc, VerifyErrorKind::InvalidConstantPoolRef(cp_idx)))?;
    let ret_slots = match desc.return_type {
        None => 0,
        Some(ref t) if t.is_category2() => 2,
        Some(_) => 1,
    };
    Ok((desc.param_slot_count(), ret_slots))
}

fn verify_exception_handler(
    h: &ExceptionHandler,
    code_len: usize,
    pc_to_ip: &BTreeMap<u16, usize>,
) -> Result<VerifiedExceptionHandler, VerifyError> {
    if h.start_pc >= h.end_pc || (h.end_pc as usize) > code_len {
        return Err(VerifyError::new(
            h.start_pc as usize,
            VerifyErrorKind::InvalidExceptionRange,
        ));
    }
    if !pc_to_ip.contains_key(&h.start_pc) {
        return Err(VerifyError::new(
            h.start_pc as usize,
            VerifyErrorKind::InvalidExceptionRange,
        ));
    }
    let Some(&handler_ip) = pc_to_ip.get(&h.handler_pc) else {
        return Err(VerifyError::new(
            h.handler_pc as usize,
            VerifyErrorKind::InvalidExceptionRange,
        ));
    };
    Ok(VerifiedExceptionHandler {
        start_pc: h.start_pc,
        end_pc: h.end_pc,
        handler_ip,
        handler_pc: h.handler_pc,
        catch_type: h.catch_type,
    })
}

fn is_float_or_double_opcode(op: u8) -> bool {
    matches!(
        op,
        0x0b..=0x0f // fconst_0..dconst_1
            | 0x17 | 0x18 // fload, dload
            | 0x22..=0x29 // fload_0..dload_3
            | 0x30 | 0x31 // faload, daload
            | 0x38 | 0x39 // fstore, dstore
            | 0x43..=0x4a // fstore_0..dstore_3
            | 0x51 | 0x52 // fastore, dastore
            | 0x62 | 0x63 | 0x66 | 0x67 | 0x6a | 0x6b | 0x6e | 0x6f | 0x72 | 0x73 | 0x76 | 0x77
            | 0x86 | 0x87 | 0x89 | 0x8a | 0x8b..=0x90 // f/d conversions
            | 0x95..=0x98 // fcmpl..dcmpg
            | 0xae | 0xaf // freturn, dreturn
    )
}

enum RawOp {
    Direct(Op),
    IfZero(IntCmp, i32),
    IfICmp(IntCmp, i32),
    IfACmpEq(i32),
    IfACmpNe(i32),
    IfNull(i32),
    IfNonNull(i32),
    Goto(i32),
    TableSwitch {
        default_pc: i32,
        low: i32,
        high: i32,
        targets: Vec<i32>,
    },
    LookupSwitch {
        default_pc: i32,
        pairs: Vec<(i32, i32)>,
    },
}

impl RawOp {
    fn is_branch(&self) -> bool {
        !matches!(self, Self::Direct(_))
    }
}

fn resolve_target(
    pc: u16,
    target: i32,
    pc_to_ip: &BTreeMap<u16, usize>,
) -> Result<usize, VerifyError> {
    let target_u16 = u16::try_from(target)
        .map_err(|_| VerifyError::new(pc as usize, VerifyErrorKind::InvalidBranchTarget(target)))?;
    pc_to_ip
        .get(&target_u16)
        .copied()
        .ok_or_else(|| VerifyError::new(pc as usize, VerifyErrorKind::InvalidBranchTarget(target)))
}

fn resolve_raw_op(
    pc: u16,
    raw: RawOp,
    pc_to_ip: &BTreeMap<u16, usize>,
) -> Result<Op, VerifyError> {
    Ok(match raw {
        RawOp::Direct(op) => op,
        RawOp::IfZero(cmp, t) => Op::IfZero(cmp, resolve_target(pc, t, pc_to_ip)?),
        RawOp::IfICmp(cmp, t) => Op::IfICmp(cmp, resolve_target(pc, t, pc_to_ip)?),
        RawOp::IfACmpEq(t) => Op::IfACmpEq(resolve_target(pc, t, pc_to_ip)?),
        RawOp::IfACmpNe(t) => Op::IfACmpNe(resolve_target(pc, t, pc_to_ip)?),
        RawOp::IfNull(t) => Op::IfNull(resolve_target(pc, t, pc_to_ip)?),
        RawOp::IfNonNull(t) => Op::IfNonNull(resolve_target(pc, t, pc_to_ip)?),
        RawOp::Goto(t) => Op::Goto(resolve_target(pc, t, pc_to_ip)?),
        RawOp::TableSwitch {
            default_pc,
            low,
            high,
            targets,
        } => {
            let default_ip = resolve_target(pc, default_pc, pc_to_ip)?;
            let mut resolved = Vec::with_capacity(targets.len());
            for t in targets {
                resolved.push(resolve_target(pc, t, pc_to_ip)?);
            }
            Op::TableSwitch {
                default_ip,
                low,
                high,
                targets: resolved,
            }
        }
        RawOp::LookupSwitch { default_pc, pairs } => {
            let default_ip = resolve_target(pc, default_pc, pc_to_ip)?;
            let mut resolved = Vec::with_capacity(pairs.len());
            for (k, t) in pairs {
                resolved.push((k, resolve_target(pc, t, pc_to_ip)?));
            }
            Op::LookupSwitch {
                default_ip,
                pairs: resolved,
            }
        }
    })
}

fn check_local(pc: usize, idx: u16, slots: u16, max_locals: u16) -> Result<u16, VerifyError> {
    if idx.saturating_add(slots) > max_locals {
        return Err(VerifyError::new(pc, VerifyErrorKind::LocalOutOfBounds(idx)));
    }
    Ok(idx)
}

fn decode_one(
    opcode: u8,
    start_pc: usize,
    bytes: &[u8],
    pos: &mut usize,
    max_locals: u16,
    profile: &ProfileContract,
) -> Result<RawOp, VerifyError> {
    let base = start_pc as i32;
    let trunc = || VerifyError::new(start_pc, VerifyErrorKind::TruncatedInstruction);

    let op = match opcode {
        0x00 => Op::Nop,
        0x01 => Op::AConstNull,
        0x02 => Op::IConst(-1),
        0x03 => Op::IConst(0),
        0x04 => Op::IConst(1),
        0x05 => Op::IConst(2),
        0x06 => Op::IConst(3),
        0x07 => Op::IConst(4),
        0x08 => Op::IConst(5),
        0x09 => Op::LConst(0),
        0x0a => Op::LConst(1),
        0x0b => Op::FConst(0.0f32.to_bits()),
        0x0c => Op::FConst(1.0f32.to_bits()),
        0x0d => Op::FConst(2.0f32.to_bits()),
        0x0e => Op::DConst(0.0f64.to_bits()),
        0x0f => Op::DConst(1.0f64.to_bits()),
        0x10 => Op::IConst(read_i8(bytes, pos).ok_or_else(trunc)? as i32),
        0x11 => Op::IConst(read_i16(bytes, pos).ok_or_else(trunc)? as i32),
        0x12 => Op::Ldc(u16::from(read_u8(bytes, pos).ok_or_else(trunc)?)),
        0x13 => Op::Ldc(read_u16(bytes, pos).ok_or_else(trunc)?),
        0x14 => Op::Ldc2W(read_u16(bytes, pos).ok_or_else(trunc)?),

        0x15 => Op::ILoad(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),
        0x16 => Op::LLoad(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            2,
            max_locals,
        )?),
        0x17 => Op::FLoad(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),
        0x18 => Op::DLoad(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            2,
            max_locals,
        )?),
        0x19 => Op::ALoad(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),

        0x1a..=0x1d => Op::ILoad(check_local(
            start_pc,
            u16::from(opcode - 0x1a),
            1,
            max_locals,
        )?),
        0x1e..=0x21 => Op::LLoad(check_local(
            start_pc,
            u16::from(opcode - 0x1e),
            2,
            max_locals,
        )?),
        0x22..=0x25 => Op::FLoad(check_local(
            start_pc,
            u16::from(opcode - 0x22),
            1,
            max_locals,
        )?),
        0x26..=0x29 => Op::DLoad(check_local(
            start_pc,
            u16::from(opcode - 0x26),
            2,
            max_locals,
        )?),
        0x2a..=0x2d => Op::ALoad(check_local(
            start_pc,
            u16::from(opcode - 0x2a),
            1,
            max_locals,
        )?),

        0x2e => Op::IALoad,
        0x2f => Op::LALoad,
        0x30 => Op::FALoad,
        0x31 => Op::DALoad,
        0x32 => Op::AALoad,
        0x33 => Op::BALoad,
        0x34 => Op::CALoad,
        0x35 => Op::SALoad,

        0x36 => Op::IStore(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),
        0x37 => Op::LStore(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            2,
            max_locals,
        )?),
        0x38 => Op::FStore(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),
        0x39 => Op::DStore(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            2,
            max_locals,
        )?),
        0x3a => Op::AStore(check_local(
            start_pc,
            u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
            1,
            max_locals,
        )?),

        0x3b..=0x3e => Op::IStore(check_local(
            start_pc,
            u16::from(opcode - 0x3b),
            1,
            max_locals,
        )?),
        0x3f..=0x42 => Op::LStore(check_local(
            start_pc,
            u16::from(opcode - 0x3f),
            2,
            max_locals,
        )?),
        0x43..=0x46 => Op::FStore(check_local(
            start_pc,
            u16::from(opcode - 0x43),
            1,
            max_locals,
        )?),
        0x47..=0x4a => Op::DStore(check_local(
            start_pc,
            u16::from(opcode - 0x47),
            2,
            max_locals,
        )?),
        0x4b..=0x4e => Op::AStore(check_local(
            start_pc,
            u16::from(opcode - 0x4b),
            1,
            max_locals,
        )?),

        0x4f => Op::IAStore,
        0x50 => Op::LAStore,
        0x51 => Op::FAStore,
        0x52 => Op::DAStore,
        0x53 => Op::AAStore,
        0x54 => Op::BAStore,
        0x55 => Op::CAStore,
        0x56 => Op::SAStore,

        0x57 => Op::Pop,
        0x58 => Op::Pop2,
        0x59 => Op::Dup,
        0x5a => Op::DupX1,
        0x5b => Op::DupX2,
        0x5c => Op::Dup2,
        0x5d => Op::Dup2X1,
        0x5e => Op::Dup2X2,
        0x5f => Op::Swap,

        0x60 => Op::IAdd,
        0x61 => Op::LAdd,
        0x62 => Op::FAdd,
        0x63 => Op::DAdd,
        0x64 => Op::ISub,
        0x65 => Op::LSub,
        0x66 => Op::FSub,
        0x67 => Op::DSub,
        0x68 => Op::IMul,
        0x69 => Op::LMul,
        0x6a => Op::FMul,
        0x6b => Op::DMul,
        0x6c => Op::IDiv,
        0x6d => Op::LDiv,
        0x6e => Op::FDiv,
        0x6f => Op::DDiv,
        0x70 => Op::IRem,
        0x71 => Op::LRem,
        0x72 => Op::FRem,
        0x73 => Op::DRem,
        0x74 => Op::INeg,
        0x75 => Op::LNeg,
        0x76 => Op::FNeg,
        0x77 => Op::DNeg,

        0x78 => Op::IShl,
        0x79 => Op::LShl,
        0x7a => Op::IShr,
        0x7b => Op::LShr,
        0x7c => Op::IUShr,
        0x7d => Op::LUShr,
        0x7e => Op::IAnd,
        0x7f => Op::LAnd,
        0x80 => Op::IOr,
        0x81 => Op::LOr,
        0x82 => Op::IXor,
        0x83 => Op::LXor,
        0x84 => {
            let index = check_local(
                start_pc,
                u16::from(read_u8(bytes, pos).ok_or_else(trunc)?),
                1,
                max_locals,
            )?;
            let delta = i16::from(read_i8(bytes, pos).ok_or_else(trunc)?);
            Op::IInc { index, delta }
        }

        0x85 => Op::I2L,
        0x86 => Op::I2F,
        0x87 => Op::I2D,
        0x88 => Op::L2I,
        0x89 => Op::L2F,
        0x8a => Op::L2D,
        0x8b => Op::F2I,
        0x8c => Op::F2L,
        0x8d => Op::F2D,
        0x8e => Op::D2I,
        0x8f => Op::D2L,
        0x90 => Op::D2F,
        0x91 => Op::I2B,
        0x92 => Op::I2C,
        0x93 => Op::I2S,

        0x94 => Op::LCmp,
        0x95 => Op::FCmpL,
        0x96 => Op::FCmpG,
        0x97 => Op::DCmpL,
        0x98 => Op::DCmpG,

        0x99..=0x9e => {
            let cmp = match opcode {
                0x99 => IntCmp::Eq,
                0x9a => IntCmp::Ne,
                0x9b => IntCmp::Lt,
                0x9c => IntCmp::Ge,
                0x9d => IntCmp::Gt,
                _ => IntCmp::Le,
            };
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfZero(cmp, base.wrapping_add(rel)));
        }
        0x9f..=0xa4 => {
            let cmp = match opcode {
                0x9f => IntCmp::Eq,
                0xa0 => IntCmp::Ne,
                0xa1 => IntCmp::Lt,
                0xa2 => IntCmp::Ge,
                0xa3 => IntCmp::Gt,
                _ => IntCmp::Le,
            };
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfICmp(cmp, base.wrapping_add(rel)));
        }
        0xa5 => {
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfACmpEq(base.wrapping_add(rel)));
        }
        0xa6 => {
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfACmpNe(base.wrapping_add(rel)));
        }
        0xa7 => {
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::Goto(base.wrapping_add(rel)));
        }
        0xaa => {
            let pad = (4 - (*pos % 4)) % 4;
            if *pos + pad > bytes.len() {
                return Err(trunc());
            }
            *pos += pad;
            let default_pc = base.wrapping_add(read_i32(bytes, pos).ok_or_else(trunc)?);
            let low = read_i32(bytes, pos).ok_or_else(trunc)?;
            let high = read_i32(bytes, pos).ok_or_else(trunc)?;
            if low > high {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::InvalidSwitchTable,
                ));
            }
            let count = (i64::from(high) - i64::from(low) + 1) as usize;
            if count > 16_384 {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::InvalidSwitchTable,
                ));
            }
            let mut targets = Vec::with_capacity(count);
            for _ in 0..count {
                let rel = read_i32(bytes, pos).ok_or_else(trunc)?;
                targets.push(base.wrapping_add(rel));
            }
            return Ok(RawOp::TableSwitch {
                default_pc,
                low,
                high,
                targets,
            });
        }
        0xab => {
            let pad = (4 - (*pos % 4)) % 4;
            if *pos + pad > bytes.len() {
                return Err(trunc());
            }
            *pos += pad;
            let default_pc = base.wrapping_add(read_i32(bytes, pos).ok_or_else(trunc)?);
            let npairs = read_i32(bytes, pos).ok_or_else(trunc)?;
            if !(0..=16_384).contains(&npairs) {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::InvalidSwitchTable,
                ));
            }
            let mut pairs = Vec::with_capacity(npairs as usize);
            let mut prev_key: Option<i32> = None;
            for _ in 0..npairs {
                let key = read_i32(bytes, pos).ok_or_else(trunc)?;
                if let Some(prev) = prev_key {
                    if key <= prev {
                        return Err(VerifyError::new(
                            start_pc,
                            VerifyErrorKind::InvalidSwitchTable,
                        ));
                    }
                }
                prev_key = Some(key);
                let rel = read_i32(bytes, pos).ok_or_else(trunc)?;
                pairs.push((key, base.wrapping_add(rel)));
            }
            return Ok(RawOp::LookupSwitch { default_pc, pairs });
        }

        0xac => Op::IReturn,
        0xad => Op::LReturn,
        0xae => Op::FReturn,
        0xaf => Op::DReturn,
        0xb0 => Op::AReturn,
        0xb1 => Op::Return,

        0xb2 => Op::GetStatic(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb3 => Op::PutStatic(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb4 => Op::GetField(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb5 => Op::PutField(read_u16(bytes, pos).ok_or_else(trunc)?),

        0xb6 => Op::InvokeVirtual(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb7 => Op::InvokeSpecial(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb8 => Op::InvokeStatic(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xb9 => {
            let cp_index = read_u16(bytes, pos).ok_or_else(trunc)?;
            let count = read_u8(bytes, pos).ok_or_else(trunc)?;
            let zero = read_u8(bytes, pos).ok_or_else(trunc)?;
            if count == 0 || zero != 0 {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::TruncatedInstruction,
                ));
            }
            Op::InvokeInterface { cp_index, count }
        }

        0xbb => Op::New(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xbc => Op::NewArray(read_u8(bytes, pos).ok_or_else(trunc)?),
        0xbd => Op::ANewArray(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xbe => Op::ArrayLength,
        0xbf => Op::AThrow,
        0xc0 => Op::CheckCast(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xc1 => Op::InstanceOf(read_u16(bytes, pos).ok_or_else(trunc)?),
        0xc2 => Op::MonitorEnter,
        0xc3 => Op::MonitorExit,

        0xc4 => {
            let sub = read_u8(bytes, pos).ok_or_else(trunc)?;
            if !profile.cldc.allows_floating_point() && is_float_or_double_opcode(sub) {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::ForbiddenInCldc10(sub),
                ));
            }
            let idx = read_u16(bytes, pos).ok_or_else(trunc)?;
            match sub {
                0x15 => Op::ILoad(check_local(start_pc, idx, 1, max_locals)?),
                0x16 => Op::LLoad(check_local(start_pc, idx, 2, max_locals)?),
                0x17 => Op::FLoad(check_local(start_pc, idx, 1, max_locals)?),
                0x18 => Op::DLoad(check_local(start_pc, idx, 2, max_locals)?),
                0x19 => Op::ALoad(check_local(start_pc, idx, 1, max_locals)?),
                0x36 => Op::IStore(check_local(start_pc, idx, 1, max_locals)?),
                0x37 => Op::LStore(check_local(start_pc, idx, 2, max_locals)?),
                0x38 => Op::FStore(check_local(start_pc, idx, 1, max_locals)?),
                0x39 => Op::DStore(check_local(start_pc, idx, 2, max_locals)?),
                0x3a => Op::AStore(check_local(start_pc, idx, 1, max_locals)?),
                0x84 => {
                    let delta = read_i16(bytes, pos).ok_or_else(trunc)?;
                    Op::IInc {
                        index: check_local(start_pc, idx, 1, max_locals)?,
                        delta,
                    }
                }
                _ => {
                    return Err(VerifyError::new(
                        start_pc,
                        VerifyErrorKind::InvalidWideTarget(sub),
                    ));
                }
            }
        }
        0xc5 => {
            let cp_index = read_u16(bytes, pos).ok_or_else(trunc)?;
            let dimensions = read_u8(bytes, pos).ok_or_else(trunc)?;
            if dimensions == 0 {
                return Err(VerifyError::new(
                    start_pc,
                    VerifyErrorKind::TruncatedInstruction,
                ));
            }
            Op::MultiANewArray {
                cp_index,
                dimensions,
            }
        }
        0xc6 => {
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfNull(base.wrapping_add(rel)));
        }
        0xc7 => {
            let rel = i32::from(read_i16(bytes, pos).ok_or_else(trunc)?);
            return Ok(RawOp::IfNonNull(base.wrapping_add(rel)));
        }
        0xc8 => {
            let rel = read_i32(bytes, pos).ok_or_else(trunc)?;
            return Ok(RawOp::Goto(base.wrapping_add(rel)));
        }

        _ => {
            return Err(VerifyError::new(
                start_pc,
                VerifyErrorKind::UnsupportedOpcode(opcode),
            ));
        }
    };

    Ok(RawOp::Direct(op))
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Option<u8> {
    let v = *bytes.get(*pos)?;
    *pos += 1;
    Some(v)
}

fn read_i8(bytes: &[u8], pos: &mut usize) -> Option<i8> {
    read_u8(bytes, pos).map(|b| b as i8)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Option<u16> {
    let b0 = u16::from(*bytes.get(*pos)?);
    let b1 = u16::from(*bytes.get(*pos + 1)?);
    *pos += 2;
    Some((b0 << 8) | b1)
}

fn read_i16(bytes: &[u8], pos: &mut usize) -> Option<i16> {
    read_u16(bytes, pos).map(|v| v as i16)
}

fn read_i32(bytes: &[u8], pos: &mut usize) -> Option<i32> {
    let b0 = u32::from(*bytes.get(*pos)?);
    let b1 = u32::from(*bytes.get(*pos + 1)?);
    let b2 = u32::from(*bytes.get(*pos + 2)?);
    let b3 = u32::from(*bytes.get(*pos + 3)?);
    *pos += 4;
    Some(((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) as i32)
}
