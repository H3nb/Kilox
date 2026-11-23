// SPDX-License-Identifier: GPL-3.0-only
//! Safe-Rust, zero-native-recursion bytecode interpreter for CLDC 1.0/1.1.
//!
//! Executes one validated guest instruction per `step_thread` call against
//! VM-owned frames, handle heap, class loader, and preemptive monitor scheduler.

use super::heap::{ArrayKind, ArrayStorage, HeapError};
use super::loader::{ClassInitState, CpEntry, LoaderError};
use super::scheduler::{Frame, ThreadState};
use super::value::{ClassId, Handle, Slot, ThreadId, Value};
use super::verifier::{IntCmp, Op};
use super::{VmContext, VmError, VmStep};

/// Executes a single guest bytecode instruction for the specified runnable thread.
pub(crate) fn step_thread(vm: &mut VmContext, tid: ThreadId) -> Result<VmStep, VmError> {
    let (class_id, method_idx, ip) = {
        let thread = vm
            .scheduler
            .thread(tid)
            .ok_or(VmError::InternalState("missing active thread"))?;
        let Some(frame) = thread.frames.last() else {
            return finish_thread(vm, tid, None);
        };
        (frame.class_id, frame.method_index, frame.ip)
    };

    let (op, current_pc, instr_len) = {
        let cls = vm
            .loader
            .class(class_id)
            .ok_or(VmError::InternalState("missing frame class"))?;
        let method = cls
            .methods
            .get(method_idx)
            .ok_or(VmError::InternalState("missing frame method"))?;
        let code = method
            .code
            .as_ref()
            .ok_or(VmError::InternalState("non-code method on stack"))?;
        let instr = code
            .instructions
            .get(ip)
            .ok_or(VmError::InternalState("instruction pointer out of bounds"))?;
        (instr.op.clone(), instr.pc, code.instructions.len())
    };

    vm.scheduler.consume_quantum(tid);

    // Advance IP tentatively; branch/call/exception/block handlers override as needed.
    let next_ip = ip + 1;
    let mut jumped_ip: Option<usize> = None;

    match op {
        Op::Nop => {}
        Op::AConstNull => push_val(vm, tid, Value::NULL)?,
        Op::IConst(v) => push_val(vm, tid, Value::Int(v))?,
        Op::LConst(v) => push_val(vm, tid, Value::Long(v))?,
        Op::FConst(bits) => push_val(vm, tid, Value::Float(bits))?,
        Op::DConst(bits) => push_val(vm, tid, Value::Double(bits))?,

        Op::Ldc(cp_idx) => {
            let entry = cp_entry(vm, class_id, cp_idx)?.clone();
            match entry {
                CpEntry::Integer(v) => push_val(vm, tid, Value::Int(v))?,
                CpEntry::Float(bits) => push_val(vm, tid, Value::Float(bits))?,
                CpEntry::StringLiteral(text) => {
                    let str_cls = vm.loader.well_known().string;
                    let handle = vm.heap.intern_string(str_cls, &text)?;
                    push_val(vm, tid, Value::Ref(Some(handle)))?;
                }
                _ => return Err(VmError::InternalState("unsupported ldc constant")),
            }
        }
        Op::Ldc2W(cp_idx) => {
            let entry = cp_entry(vm, class_id, cp_idx)?.clone();
            match entry {
                CpEntry::Long(v) => push_val(vm, tid, Value::Long(v))?,
                CpEntry::Double(bits) => push_val(vm, tid, Value::Double(bits))?,
                _ => return Err(VmError::InternalState("unsupported ldc2_w constant")),
            }
        }

        Op::ILoad(idx) => {
            let v = match read_local(vm, tid, idx as usize)? {
                Slot::Int(x) => Value::Int(x),
                _ => return Err(VmError::InternalState("iload type mismatch")),
            };
            push_val(vm, tid, v)?;
        }
        Op::LLoad(idx) => {
            let v = match read_local(vm, tid, idx as usize)? {
                Slot::Long(x) => Value::Long(x),
                _ => return Err(VmError::InternalState("lload type mismatch")),
            };
            push_val(vm, tid, v)?;
        }
        Op::FLoad(idx) => {
            let v = match read_local(vm, tid, idx as usize)? {
                Slot::Float(x) => Value::Float(x),
                _ => return Err(VmError::InternalState("fload type mismatch")),
            };
            push_val(vm, tid, v)?;
        }
        Op::DLoad(idx) => {
            let v = match read_local(vm, tid, idx as usize)? {
                Slot::Double(x) => Value::Double(x),
                _ => return Err(VmError::InternalState("dload type mismatch")),
            };
            push_val(vm, tid, v)?;
        }
        Op::ALoad(idx) => {
            let v = match read_local(vm, tid, idx as usize)? {
                Slot::Ref(h) => Value::Ref(h),
                _ => return Err(VmError::InternalState("aload type mismatch")),
            };
            push_val(vm, tid, v)?;
        }

        Op::IStore(idx) => {
            let v = pop_int(vm, tid)?;
            write_local(vm, tid, idx as usize, Value::Int(v))?;
        }
        Op::LStore(idx) => {
            let v = pop_long(vm, tid)?;
            write_local(vm, tid, idx as usize, Value::Long(v))?;
        }
        Op::FStore(idx) => {
            let v = pop_float(vm, tid)?;
            write_local(vm, tid, idx as usize, Value::Float(v))?;
        }
        Op::DStore(idx) => {
            let v = pop_double(vm, tid)?;
            write_local(vm, tid, idx as usize, Value::Double(v))?;
        }
        Op::AStore(idx) => {
            let h = pop_ref(vm, tid)?;
            write_local(vm, tid, idx as usize, Value::Ref(h))?;
        }

        Op::IALoad
        | Op::LALoad
        | Op::FALoad
        | Op::DALoad
        | Op::AALoad
        | Op::BALoad
        | Op::CALoad
        | Op::SALoad => {
            let index = pop_int(vm, tid)?;
            let Some(arr_handle) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let len = vm.heap.array_len(arr_handle)?;
            if index < 0 || (index as usize) >= len {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().array_index_out_of_bounds,
                );
            }
            let idx = index as usize;
            let loaded = match (op, vm.heap.array_storage(arr_handle)?) {
                (Op::IALoad, ArrayStorage::Int(v)) => Value::Int(v[idx]),
                (Op::LALoad, ArrayStorage::Long(v)) => Value::Long(v[idx]),
                (Op::FALoad, ArrayStorage::Float(v)) => Value::Float(v[idx]),
                (Op::DALoad, ArrayStorage::Double(v)) => Value::Double(v[idx]),
                (Op::AALoad, ArrayStorage::Reference { elements, .. }) => Value::Ref(elements[idx]),
                (Op::BALoad, ArrayStorage::Byte(v)) => Value::Int(i32::from(v[idx])),
                (Op::BALoad, ArrayStorage::Boolean(v)) => Value::Int(i32::from(v[idx] != 0)),
                (Op::CALoad, ArrayStorage::Char(v)) => Value::Int(i32::from(v[idx])),
                (Op::SALoad, ArrayStorage::Short(v)) => Value::Int(i32::from(v[idx])),
                _ => return Err(VmError::InternalState("array load type mismatch")),
            };
            push_val(vm, tid, loaded)?;
        }

        Op::IAStore
        | Op::LAStore
        | Op::FAStore
        | Op::DAStore
        | Op::AAStore
        | Op::BAStore
        | Op::CAStore
        | Op::SAStore => {
            let val = match op {
                Op::IAStore | Op::BAStore | Op::CAStore | Op::SAStore => Value::Int(pop_int(vm, tid)?),
                Op::LAStore => Value::Long(pop_long(vm, tid)?),
                Op::FAStore => Value::Float(pop_float(vm, tid)?),
                Op::DAStore => Value::Double(pop_double(vm, tid)?),
                Op::AAStore => Value::Ref(pop_ref(vm, tid)?),
                _ => unreachable!(),
            };
            let index = pop_int(vm, tid)?;
            let Some(arr_handle) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let len = vm.heap.array_len(arr_handle)?;
            if index < 0 || (index as usize) >= len {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().array_index_out_of_bounds,
                );
            }
            let idx = index as usize;
            if let (Op::AAStore, Value::Ref(Some(elem_h))) = (&op, val) {
                let elem_cls = vm.heap.class_of(elem_h)?;
                let expected_cls = match vm.heap.array_storage(arr_handle)? {
                    ArrayStorage::Reference { element_class, .. } => *element_class,
                    _ => return Err(VmError::InternalState("aastore on primitive array")),
                };
                if !vm.loader.is_assignable_to(elem_cls, expected_cls) {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().array_store_exception,
                    );
                }
            }
            match (op, vm.heap.array_storage_mut(arr_handle)?, val) {
                (Op::IAStore, ArrayStorage::Int(v), Value::Int(x)) => v[idx] = x,
                (Op::LAStore, ArrayStorage::Long(v), Value::Long(x)) => v[idx] = x,
                (Op::FAStore, ArrayStorage::Float(v), Value::Float(x)) => v[idx] = x,
                (Op::DAStore, ArrayStorage::Double(v), Value::Double(x)) => v[idx] = x,
                (Op::AAStore, ArrayStorage::Reference { elements, .. }, Value::Ref(h)) => {
                    elements[idx] = h;
                }
                (Op::BAStore, ArrayStorage::Byte(v), Value::Int(x)) => v[idx] = x as i8,
                (Op::BAStore, ArrayStorage::Boolean(v), Value::Int(x)) => v[idx] = (x & 1) as u8,
                (Op::CAStore, ArrayStorage::Char(v), Value::Int(x)) => v[idx] = x as u16,
                (Op::SAStore, ArrayStorage::Short(v), Value::Int(x)) => v[idx] = x as i16,
                _ => return Err(VmError::InternalState("array store type mismatch")),
            }
        }

        Op::Pop => {
            let _ = pop_slot(vm, tid)?;
        }
        Op::Pop2 => {
            let _ = pop_slot(vm, tid)?;
            let _ = pop_slot(vm, tid)?;
        }
        Op::Dup => {
            let v = pop_slot(vm, tid)?;
            push_slot(vm, tid, v)?;
            push_slot(vm, tid, v)?;
        }
        Op::DupX1 => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
        }
        Op::DupX2 => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            let v3 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v3)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
        }
        Op::Dup2 => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
        }
        Op::Dup2X1 => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            let v3 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v3)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
        }
        Op::Dup2X2 => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            let v3 = pop_slot(vm, tid)?;
            let v4 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v4)?;
            push_slot(vm, tid, v3)?;
            push_slot(vm, tid, v2)?;
            push_slot(vm, tid, v1)?;
        }
        Op::Swap => {
            let v1 = pop_slot(vm, tid)?;
            let v2 = pop_slot(vm, tid)?;
            push_slot(vm, tid, v1)?;
            push_slot(vm, tid, v2)?;
        }

        Op::IAdd => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_add(b)))?;
        }
        Op::ISub => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_sub(b)))?;
        }
        Op::IMul => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_mul(b)))?;
        }
        Op::IDiv => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            if b == 0 {
                return raise_builtin_exception(vm, tid, vm.loader.well_known().arithmetic_exception);
            }
            push_val(vm, tid, Value::Int(a.wrapping_div(b)))?;
        }
        Op::IRem => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            if b == 0 {
                return raise_builtin_exception(vm, tid, vm.loader.well_known().arithmetic_exception);
            }
            push_val(vm, tid, Value::Int(a.wrapping_rem(b)))?;
        }
        Op::INeg => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_neg()))?;
        }
        Op::IShl => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_shl((b & 0x1f) as u32)))?;
        }
        Op::IShr => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a.wrapping_shr((b & 0x1f) as u32)))?;
        }
        Op::IUShr => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(
                vm,
                tid,
                Value::Int(((a as u32).wrapping_shr((b & 0x1f) as u32)) as i32),
            )?;
        }
        Op::IAnd => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a & b))?;
        }
        Op::IOr => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a | b))?;
        }
        Op::IXor => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(a ^ b))?;
        }
        Op::IInc { index, delta } => {
            let cur = match read_local(vm, tid, index as usize)? {
                Slot::Int(x) => x,
                _ => return Err(VmError::InternalState("iinc on non-int local")),
            };
            write_local(
                vm,
                tid,
                index as usize,
                Value::Int(cur.wrapping_add(i32::from(delta))),
            )?;
        }

        Op::LAdd => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_add(b)))?;
        }
        Op::LSub => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_sub(b)))?;
        }
        Op::LMul => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_mul(b)))?;
        }
        Op::LDiv => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            if b == 0 {
                return raise_builtin_exception(vm, tid, vm.loader.well_known().arithmetic_exception);
            }
            push_val(vm, tid, Value::Long(a.wrapping_div(b)))?;
        }
        Op::LRem => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            if b == 0 {
                return raise_builtin_exception(vm, tid, vm.loader.well_known().arithmetic_exception);
            }
            push_val(vm, tid, Value::Long(a.wrapping_rem(b)))?;
        }
        Op::LNeg => {
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_neg()))?;
        }
        Op::LShl => {
            let b = pop_int(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_shl((b & 0x3f) as u32)))?;
        }
        Op::LShr => {
            let b = pop_int(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a.wrapping_shr((b & 0x3f) as u32)))?;
        }
        Op::LUShr => {
            let b = pop_int(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(
                vm,
                tid,
                Value::Long(((a as u64).wrapping_shr((b & 0x3f) as u32)) as i64),
            )?;
        }
        Op::LAnd => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a & b))?;
        }
        Op::LOr => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a | b))?;
        }
        Op::LXor => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Long(a ^ b))?;
        }

        Op::FAdd => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a + b))?;
        }
        Op::FSub => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a - b))?;
        }
        Op::FMul => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a * b))?;
        }
        Op::FDiv => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a / b))?;
        }
        Op::FRem => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a % b))?;
        }
        Op::FNeg => {
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f32(-a))?;
        }

        Op::DAdd => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(a + b))?;
        }
        Op::DSub => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(a - b))?;
        }
        Op::DMul => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(a * b))?;
        }
        Op::DDiv => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(a / b))?;
        }
        Op::DRem => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(a % b))?;
        }
        Op::DNeg => {
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f64(-a))?;
        }

        Op::I2L => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Long(i64::from(a)))?;
        }
        Op::I2F => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::from_f32(a as f32))?;
        }
        Op::I2D => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::from_f64(f64::from(a)))?;
        }
        Op::L2I => {
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::Int(a as i32))?;
        }
        Op::L2F => {
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::from_f32(a as f32))?;
        }
        Op::L2D => {
            let a = pop_long(vm, tid)?;
            push_val(vm, tid, Value::from_f64(a as f64))?;
        }
        Op::F2I => {
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::Int(java_f32_to_i32(a)))?;
        }
        Op::F2L => {
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::Long(java_f32_to_i64(a)))?;
        }
        Op::F2D => {
            let a = f32::from_bits(pop_float(vm, tid)?);
            push_val(vm, tid, Value::from_f64(f64::from(a)))?;
        }
        Op::D2I => {
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::Int(java_f64_to_i32(a)))?;
        }
        Op::D2L => {
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::Long(java_f64_to_i64(a)))?;
        }
        Op::D2F => {
            let a = f64::from_bits(pop_double(vm, tid)?);
            push_val(vm, tid, Value::from_f32(a as f32))?;
        }
        Op::I2B => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(i32::from(a as i8)))?;
        }
        Op::I2C => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(i32::from(a as u16)))?;
        }
        Op::I2S => {
            let a = pop_int(vm, tid)?;
            push_val(vm, tid, Value::Int(i32::from(a as i16)))?;
        }

        Op::LCmp => {
            let b = pop_long(vm, tid)?;
            let a = pop_long(vm, tid)?;
            let res = if a > b {
                1
            } else if a < b {
                -1
            } else {
                0
            };
            push_val(vm, tid, Value::Int(res))?;
        }
        Op::FCmpL | Op::FCmpG => {
            let b = f32::from_bits(pop_float(vm, tid)?);
            let a = f32::from_bits(pop_float(vm, tid)?);
            let res = if a.is_nan() || b.is_nan() {
                if matches!(op, Op::FCmpG) { 1 } else { -1 }
            } else if a > b {
                1
            } else if a < b {
                -1
            } else {
                0
            };
            push_val(vm, tid, Value::Int(res))?;
        }
        Op::DCmpL | Op::DCmpG => {
            let b = f64::from_bits(pop_double(vm, tid)?);
            let a = f64::from_bits(pop_double(vm, tid)?);
            let res = if a.is_nan() || b.is_nan() {
                if matches!(op, Op::DCmpG) { 1 } else { -1 }
            } else if a > b {
                1
            } else if a < b {
                -1
            } else {
                0
            };
            push_val(vm, tid, Value::Int(res))?;
        }

        Op::IfZero(cmp, target) => {
            let a = pop_int(vm, tid)?;
            if test_cmp(cmp, a, 0) {
                jumped_ip = Some(target);
            }
        }
        Op::IfICmp(cmp, target) => {
            let b = pop_int(vm, tid)?;
            let a = pop_int(vm, tid)?;
            if test_cmp(cmp, a, b) {
                jumped_ip = Some(target);
            }
        }
        Op::IfACmpEq(target) => {
            let b = pop_ref(vm, tid)?;
            let a = pop_ref(vm, tid)?;
            if a == b {
                jumped_ip = Some(target);
            }
        }
        Op::IfACmpNe(target) => {
            let b = pop_ref(vm, tid)?;
            let a = pop_ref(vm, tid)?;
            if a != b {
                jumped_ip = Some(target);
            }
        }
        Op::IfNull(target) => {
            if pop_ref(vm, tid)?.is_none() {
                jumped_ip = Some(target);
            }
        }
        Op::IfNonNull(target) => {
            if pop_ref(vm, tid)?.is_some() {
                jumped_ip = Some(target);
            }
        }
        Op::Goto(target) => {
            jumped_ip = Some(target);
        }
        Op::TableSwitch {
            default_ip,
            low,
            high,
            targets,
        } => {
            let key = pop_int(vm, tid)?;
            if key >= low && key <= high {
                jumped_ip = Some(targets[(key - low) as usize]);
            } else {
                jumped_ip = Some(default_ip);
            }
        }
        Op::LookupSwitch { default_ip, pairs } => {
            let key = pop_int(vm, tid)?;
            let target = pairs
                .binary_search_by_key(&key, |(k, _)| *k)
                .map(|idx| pairs[idx].1)
                .unwrap_or(default_ip);
            jumped_ip = Some(target);
        }

        Op::IReturn => {
            let v = Value::Int(pop_int(vm, tid)?);
            return return_from_frame(vm, tid, Some(v));
        }
        Op::LReturn => {
            let v = Value::Long(pop_long(vm, tid)?);
            return return_from_frame(vm, tid, Some(v));
        }
        Op::FReturn => {
            let v = Value::Float(pop_float(vm, tid)?);
            return return_from_frame(vm, tid, Some(v));
        }
        Op::DReturn => {
            let v = Value::Double(pop_double(vm, tid)?);
            return return_from_frame(vm, tid, Some(v));
        }
        Op::AReturn => {
            let v = Value::Ref(pop_ref(vm, tid)?);
            return return_from_frame(vm, tid, Some(v));
        }
        Op::Return => {
            return return_from_frame(vm, tid, None);
        }

        Op::GetStatic(cp_idx) => {
            let (cls_name, fname, fdesc) = cp_fieldref(vm, class_id, cp_idx)?;
            let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().no_class_def_found_error,
                );
            };
            if trigger_clinit_if_needed(vm, tid, target_cls)? {
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let Some((owner_cls, slot)) = vm.loader.resolve_static_field(target_cls, &fname, &fdesc)
            else {
                return Err(VmError::Loader(LoaderError::NoSuchField {
                    class: cls_name,
                    name: fname,
                }));
            };
            let val = vm.loader.class(owner_cls).unwrap().static_fields[slot];
            push_val(vm, tid, val)?;
        }

        Op::PutStatic(cp_idx) => {
            let (cls_name, fname, fdesc) = cp_fieldref(vm, class_id, cp_idx)?;
            let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().no_class_def_found_error,
                );
            };
            if trigger_clinit_if_needed(vm, tid, target_cls)? {
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let val = pop_val(vm, tid)?;
            let Some((owner_cls, slot)) = vm.loader.resolve_static_field(target_cls, &fname, &fdesc)
            else {
                return Err(VmError::Loader(LoaderError::NoSuchField {
                    class: cls_name,
                    name: fname,
                }));
            };
            vm.loader.class_mut(owner_cls).unwrap().static_fields[slot] = val;
        }

        Op::GetField(cp_idx) => {
            let (cls_name, fname, fdesc) = cp_fieldref(vm, class_id, cp_idx)?;
            let Some(obj) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let obj_cls = vm.heap.class_of(obj)?;
            let Some(slot) = vm.loader.resolve_instance_field(obj_cls, &fname, &fdesc) else {
                return Err(VmError::Loader(LoaderError::NoSuchField {
                    class: cls_name,
                    name: fname,
                }));
            };
            let val = vm.heap.get_field(obj, slot)?;
            push_val(vm, tid, val)?;
        }

        Op::PutField(cp_idx) => {
            let (cls_name, fname, fdesc) = cp_fieldref(vm, class_id, cp_idx)?;
            let val = pop_val(vm, tid)?;
            let Some(obj) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let obj_cls = vm.heap.class_of(obj)?;
            let Some(slot) = vm.loader.resolve_instance_field(obj_cls, &fname, &fdesc) else {
                return Err(VmError::Loader(LoaderError::NoSuchField {
                    class: cls_name,
                    name: fname,
                }));
            };
            vm.heap.put_field(obj, slot, val)?;
        }

        Op::New(cp_idx) => {
            let cls_name = cp_class(vm, class_id, cp_idx)?;
            let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().no_class_def_found_error,
                );
            };
            if trigger_clinit_if_needed(vm, tid, target_cls)? {
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let (defaults, is_weak) = {
                let c = vm.loader.class(target_cls).unwrap();
                (c.instance_field_defaults.clone(), c.is_weak_reference)
            };
            match vm.heap.alloc_instance(target_cls, defaults, is_weak) {
                Ok(h) => push_val(vm, tid, Value::Ref(Some(h)))?,
                Err(HeapError::OutOfMemory) => {
                    vm.collect_garbage();
                    match vm.heap.alloc_instance(
                        target_cls,
                        vm.loader.class(target_cls).unwrap().instance_field_defaults.clone(),
                        is_weak,
                    ) {
                        Ok(h) => push_val(vm, tid, Value::Ref(Some(h)))?,
                        Err(HeapError::OutOfMemory) => {
                            return raise_builtin_exception(
                                vm,
                                tid,
                                vm.loader.well_known().out_of_memory_error,
                            );
                        }
                        Err(e) => return Err(VmError::Heap(e)),
                    }
                }
                Err(e) => return Err(VmError::Heap(e)),
            }
        }

        Op::NewArray(atype) => {
            let count = pop_int(vm, tid)?;
            let Some(kind) = ArrayKind::from_atype(atype) else {
                return Err(VmError::InternalState("invalid newarray atype"));
            };
            let arr_cls = vm.loader.well_known().object;
            match vm.heap.alloc_primitive_array(arr_cls, kind, count) {
                Ok(h) => push_val(vm, tid, Value::Ref(Some(h)))?,
                Err(HeapError::NegativeArraySize(_)) => {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().negative_array_size,
                    );
                }
                Err(HeapError::OutOfMemory) => {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().out_of_memory_error,
                    );
                }
                Err(e) => return Err(VmError::Heap(e)),
            }
        }

        Op::ANewArray(cp_idx) => {
            let count = pop_int(vm, tid)?;
            let cls_name = cp_class(vm, class_id, cp_idx)?;
            let elem_cls = vm
                .loader
                .find_class(&cls_name)
                .unwrap_or_else(|| vm.loader.well_known().object);
            let arr_cls = vm.loader.well_known().object;
            match vm.heap.alloc_ref_array(arr_cls, elem_cls, count) {
                Ok(h) => push_val(vm, tid, Value::Ref(Some(h)))?,
                Err(HeapError::NegativeArraySize(_)) => {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().negative_array_size,
                    );
                }
                Err(HeapError::OutOfMemory) => {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().out_of_memory_error,
                    );
                }
                Err(e) => return Err(VmError::Heap(e)),
            }
        }

        Op::MultiANewArray {
            cp_index,
            dimensions,
        } => {
            let mut counts = vec![0i32; dimensions as usize];
            for c in counts.iter_mut().rev() {
                *c = pop_int(vm, tid)?;
                if *c < 0 {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().negative_array_size,
                    );
                }
            }
            let _cls_name = cp_class(vm, class_id, cp_index)?;
            let obj_cls = vm.loader.well_known().object;
            let root = alloc_multi_ref_array(vm, obj_cls, &counts)?;
            push_val(vm, tid, Value::Ref(Some(root)))?;
        }

        Op::ArrayLength => {
            let Some(h) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let len = vm.heap.array_len(h)?;
            push_val(vm, tid, Value::Int(len as i32))?;
        }

        Op::CheckCast(cp_idx) => {
            let cls_name = cp_class(vm, class_id, cp_idx)?;
            let val = peek_ref(vm, tid)?;
            if let Some(h) = val {
                let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().no_class_def_found_error,
                    );
                };
                let obj_cls = vm.heap.class_of(h)?;
                if !vm.loader.is_assignable_to(obj_cls, target_cls) {
                    return raise_builtin_exception(
                        vm,
                        tid,
                        vm.loader.well_known().class_cast_exception,
                    );
                }
            }
        }

        Op::InstanceOf(cp_idx) => {
            let cls_name = cp_class(vm, class_id, cp_idx)?;
            let val = pop_ref(vm, tid)?;
            let is_inst = match val {
                None => false,
                Some(h) => {
                    let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                        return raise_builtin_exception(
                            vm,
                            tid,
                            vm.loader.well_known().no_class_def_found_error,
                        );
                    };
                    let obj_cls = vm.heap.class_of(h)?;
                    vm.loader.is_assignable_to(obj_cls, target_cls)
                }
            };
            push_val(vm, tid, Value::Int(i32::from(is_inst)))?;
        }

        Op::AThrow => {
            let Some(exc_handle) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            return unwind_exception(vm, tid, exc_handle);
        }

        Op::MonitorEnter => {
            let Some(h) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            if !vm.scheduler.monitor_enter(tid, h) {
                // Re-execute `monitorenter` when re-scheduled? No, scheduler grants ownership
                // upon waking from entry_queue, so advance past `monitorenter` now.
                advance_ip(vm, tid, next_ip, instr_len)?;
                return Ok(VmStep::Blocked { thread: tid });
            }
        }

        Op::MonitorExit => {
            let Some(h) = pop_ref(vm, tid)? else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            if vm.scheduler.monitor_exit(tid, h).is_err() {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().illegal_monitor_state,
                );
            }
        }

        Op::InvokeStatic(cp_idx) => {
            let (cls_name, mname, mdesc) = cp_methodref(vm, class_id, cp_idx)?;
            if handle_builtin_static(vm, tid, &cls_name, &mname, &mdesc)? {
                advance_ip(vm, tid, next_ip, instr_len)?;
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().no_class_def_found_error,
                );
            };
            if trigger_clinit_if_needed(vm, tid, target_cls)? {
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let Some((resolved_cls, resolved_idx)) =
                vm.loader.resolve_method(target_cls, &mname, &mdesc)
            else {
                return Err(VmError::Loader(LoaderError::NoSuchMethod {
                    class: cls_name,
                    name: mname,
                    descriptor: mdesc,
                }));
            };
            advance_ip(vm, tid, next_ip, instr_len)?;
            invoke_method(vm, tid, resolved_cls, resolved_idx, None)?;
            return Ok(VmStep::Advanced {
                thread: tid,
                pc: current_pc,
            });
        }

        Op::InvokeSpecial(cp_idx) => {
            let (cls_name, mname, mdesc) = cp_methodref(vm, class_id, cp_idx)?;
            if handle_builtin_special(vm, tid, &cls_name, &mname, &mdesc)? {
                advance_ip(vm, tid, next_ip, instr_len)?;
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let Some(target_cls) = vm.loader.find_class(&cls_name) else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().no_class_def_found_error,
                );
            };
            let Some((resolved_cls, resolved_idx)) =
                vm.loader.resolve_method(target_cls, &mname, &mdesc)
            else {
                return Err(VmError::Loader(LoaderError::NoSuchMethod {
                    class: cls_name,
                    name: mname,
                    descriptor: mdesc,
                }));
            };
            advance_ip(vm, tid, next_ip, instr_len)?;
            invoke_method(vm, tid, resolved_cls, resolved_idx, Some(true))?;
            return Ok(VmStep::Advanced {
                thread: tid,
                pc: current_pc,
            });
        }

        Op::InvokeVirtual(cp_idx) | Op::InvokeInterface { cp_index: cp_idx, .. } => {
            let (cls_name, mname, mdesc) = cp_methodref(vm, class_id, cp_idx)?;
            if handle_builtin_virtual(vm, tid, &cls_name, &mname, &mdesc)? {
                advance_ip(vm, tid, next_ip, instr_len)?;
                return Ok(VmStep::Advanced {
                    thread: tid,
                    pc: current_pc,
                });
            }
            let parsed_desc = super::value::parse_method_descriptor(&mdesc)
                .map_err(|_| VmError::InternalState("invalid invoke descriptor"))?;
            let arg_slots = parsed_desc.param_slot_count();
            let receiver_opt = peek_receiver(vm, tid, arg_slots)?;
            let Some(receiver) = receiver_opt else {
                return raise_builtin_exception(
                    vm,
                    tid,
                    vm.loader.well_known().null_pointer_exception,
                );
            };
            let dynamic_cls = vm.heap.class_of(receiver)?;
            let Some((resolved_cls, resolved_idx)) =
                vm.loader.resolve_method(dynamic_cls, &mname, &mdesc)
            else {
                return Err(VmError::Loader(LoaderError::NoSuchMethod {
                    class: cls_name,
                    name: mname,
                    descriptor: mdesc,
                }));
            };
            advance_ip(vm, tid, next_ip, instr_len)?;
            invoke_method(vm, tid, resolved_cls, resolved_idx, Some(false))?;
            return Ok(VmStep::Advanced {
                thread: tid,
                pc: current_pc,
            });
        }
    }

    let final_ip = jumped_ip.unwrap_or(next_ip);
    advance_ip(vm, tid, final_ip, instr_len)?;
    Ok(VmStep::Advanced {
        thread: tid,
        pc: current_pc,
    })
}

fn alloc_multi_ref_array(
    vm: &mut VmContext,
    elem_cls: ClassId,
    dims: &[i32],
) -> Result<Handle, VmError> {
    let len = dims[0];
    let arr = vm.heap.alloc_ref_array(elem_cls, elem_cls, len)?;
    if dims.len() > 1 {
        for i in 0..(len as usize) {
            let sub = alloc_multi_ref_array(vm, elem_cls, &dims[1..])?;
            if let ArrayStorage::Reference { elements, .. } = vm.heap.array_storage_mut(arr)? {
                elements[i] = Some(sub);
            }
        }
    }
    Ok(arr)
}

fn trigger_clinit_if_needed(
    vm: &mut VmContext,
    tid: ThreadId,
    target_cls: ClassId,
) -> Result<bool, VmError> {
    let state = vm
        .loader
        .class(target_cls)
        .ok_or(VmError::InternalState("missing class for clinit"))?
        .init_state;
    match state {
        ClassInitState::Initialized => Ok(false),
        ClassInitState::Initializing(owner) if owner == tid => Ok(false),
        ClassInitState::Initializing(_) => Ok(false),
        ClassInitState::Failed => Err(VmError::InternalState("class initialization failed")),
        ClassInitState::Prepared => {
            let clinit_idx = vm
                .loader
                .class(target_cls)
                .and_then(|c| c.find_method("<clinit>", "()V"));
            if let Some(midx) = clinit_idx {
                vm.loader.class_mut(target_cls).unwrap().init_state =
                    ClassInitState::Initializing(tid);
                invoke_method(vm, tid, target_cls, midx, None)?;
                Ok(true)
            } else {
                vm.loader.class_mut(target_cls).unwrap().init_state = ClassInitState::Initialized;
                Ok(false)
            }
        }
    }
}

fn invoke_method(
    vm: &mut VmContext,
    tid: ThreadId,
    target_cls: ClassId,
    method_idx: usize,
    has_receiver: Option<bool>,
) -> Result<(), VmError> {
    let depth = vm
        .scheduler
        .thread(tid)
        .map(|t| t.frames.len())
        .unwrap_or(0);
    if depth >= vm.profile.budget.max_frames_per_thread {
        return Err(VmError::StackOverflow);
    }

    let (max_locals, max_stack, params, is_sync, is_static) = {
        let cls = vm
            .loader
            .class(target_cls)
            .ok_or(VmError::InternalState("missing target class"))?;
        let method = cls
            .methods
            .get(method_idx)
            .ok_or(VmError::InternalState("missing target method"))?;
        let code = method
            .code
            .as_ref()
            .ok_or(VmError::InternalState("cannot invoke abstract/native method without binding"))?;
        (
            code.max_locals as usize,
            code.max_stack as usize,
            method.parsed_descriptor.params.clone(),
            method.is_synchronized(),
            method.is_static(),
        )
    };

    // Pop arguments in reverse order from caller operand stack.
    let mut args = vec![Value::NULL; params.len()];
    for i in (0..params.len()).rev() {
        args[i] = pop_val(vm, tid)?;
    }

    let receiver = if has_receiver.is_some() && !is_static {
        let Some(r) = pop_ref(vm, tid)? else {
            return Err(VmError::Heap(HeapError::NullPointer));
        };
        Some(r)
    } else {
        None
    };

    let sync_monitor = if is_sync {
        if let Some(r) = receiver {
            let _ = vm.scheduler.monitor_enter(tid, r);
            Some(r)
        } else {
            None
        }
    } else {
        None
    };

    let mut frame = Frame::new(target_cls, method_idx, max_locals, max_stack, sync_monitor);
    let mut local_slot = 0usize;
    if let Some(r) = receiver {
        frame.set_local_value(local_slot, Value::Ref(Some(r)));
        local_slot += 1;
    }
    for (param_ty, val) in params.iter().zip(args.into_iter()) {
        frame.set_local_value(local_slot, val);
        local_slot += if param_ty.is_category2() { 2 } else { 1 };
    }

    vm.scheduler
        .thread_mut(tid)
        .ok_or(VmError::InternalState("missing thread"))?
        .frames
        .push(frame);
    Ok(())
}

fn return_from_frame(
    vm: &mut VmContext,
    tid: ThreadId,
    ret_val: Option<Value>,
) -> Result<VmStep, VmError> {
    let popped = vm
        .scheduler
        .thread_mut(tid)
        .ok_or(VmError::InternalState("missing thread"))?
        .frames
        .pop()
        .ok_or(VmError::InternalState("empty frame stack on return"))?;

    if let Some(mon) = popped.synchronized_monitor {
        let _ = vm.scheduler.monitor_exit(tid, mon);
    }

    // Mark class initialized if returning from `<clinit>`.
    if let Some(cls) = vm.loader.class(popped.class_id) {
        if let Some(m) = cls.methods.get(popped.method_index) {
            if m.name == "<clinit>" {
                vm.loader.class_mut(popped.class_id).unwrap().init_state =
                    ClassInitState::Initialized;
            }
        }
    }

    let has_caller = vm
        .scheduler
        .thread(tid)
        .is_some_and(|t| !t.frames.is_empty());
    if has_caller {
        if let Some(v) = ret_val {
            push_val(vm, tid, v)?;
        }
        let next_pc = vm
            .scheduler
            .thread(tid)
            .and_then(|t| t.frames.last())
            .map(|f| f.pc)
            .unwrap_or(0);
        Ok(VmStep::Advanced {
            thread: tid,
            pc: next_pc,
        })
    } else {
        finish_thread(vm, tid, ret_val)
    }
}

fn finish_thread(
    vm: &mut VmContext,
    tid: ThreadId,
    ret_val: Option<Value>,
) -> Result<VmStep, VmError> {
    if let Some(t) = vm.scheduler.thread_mut(tid) {
        t.state = ThreadState::Terminated;
        t.last_return = ret_val;
    }
    if vm.scheduler.active_thread == Some(tid) {
        vm.scheduler.active_thread = None;
    }
    Ok(VmStep::ThreadReturned {
        thread: tid,
        value: ret_val,
    })
}

fn raise_builtin_exception(
    vm: &mut VmContext,
    tid: ThreadId,
    exc_class: ClassId,
) -> Result<VmStep, VmError> {
    let exc_handle = vm.heap.alloc_instance(exc_class, Vec::new(), false)?;
    unwind_exception(vm, tid, exc_handle)
}

fn unwind_exception(
    vm: &mut VmContext,
    tid: ThreadId,
    exc_handle: Handle,
) -> Result<VmStep, VmError> {
    let exc_class = vm.heap.class_of(exc_handle)?;

    loop {
        let top_info = vm
            .scheduler
            .thread(tid)
            .and_then(|t| t.frames.last())
            .map(|f| (f.class_id, f.method_index, f.pc));
        let Some((cid, midx, pc)) = top_info else {
            if let Some(t) = vm.scheduler.thread_mut(tid) {
                t.state = ThreadState::Terminated;
                t.pending_exception = Some(exc_handle);
            }
            if vm.scheduler.active_thread == Some(tid) {
                vm.scheduler.active_thread = None;
            }
            return Ok(VmStep::UncaughtException {
                thread: tid,
                exception: exc_handle,
            });
        };

        // Search exception table in the current frame.
        let mut matched: Option<(usize, u16)> = None;
        if let Some(cls) = vm.loader.class(cid) {
            if let Some(method) = cls.methods.get(midx) {
                if let Some(code) = &method.code {
                    for h in &code.exceptions {
                        if pc >= h.start_pc && pc < h.end_pc {
                            let catches = if h.catch_type == 0 {
                                true
                            } else if let Some(CpEntry::Class(cname)) =
                                cls.constant_pool.get(h.catch_type as usize)
                            {
                                vm.loader
                                    .find_class(cname)
                                    .is_some_and(|catch_cls| vm.loader.is_assignable_to(exc_class, catch_cls))
                            } else {
                                false
                            };
                            if catches {
                                matched = Some((h.handler_ip, h.handler_pc));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some((handler_ip, handler_pc)) = matched {
            let frame = vm
                .scheduler
                .thread_mut(tid)
                .unwrap()
                .frames
                .last_mut()
                .unwrap();
            frame.stack.clear();
            frame.push_value(Value::Ref(Some(exc_handle)));
            frame.ip = handler_ip;
            frame.pc = handler_pc;
            return Ok(VmStep::Advanced {
                thread: tid,
                pc: handler_pc,
            });
        }

        // Unwind frame and release any synchronized method monitor.
        let popped = vm.scheduler.thread_mut(tid).unwrap().frames.pop().unwrap();
        if let Some(mon) = popped.synchronized_monitor {
            let _ = vm.scheduler.monitor_exit(tid, mon);
        }
    }
}

/// Built-in core CLDC intrinsic hooks for bootstrap classes (`Object`, `System`, `WeakReference`).
fn handle_builtin_static(
    vm: &mut VmContext,
    tid: ThreadId,
    cls: &str,
    name: &str,
    desc: &str,
) -> Result<bool, VmError> {
    if cls == "java/lang/System" && name == "identityHashCode" && desc == "(Ljava/lang/Object;)I" {
        let hash = match pop_ref(vm, tid)? {
            None => 0,
            Some(h) => vm.heap.identity_hash(h)?,
        };
        push_val(vm, tid, Value::Int(hash))?;
        return Ok(true);
    }
    if cls == "java/lang/System" && name == "currentTimeMillis" && desc == "()J" {
        let now = vm.scheduler.virtual_time_ms() as i64;
        push_val(vm, tid, Value::Long(now))?;
        return Ok(true);
    }
    Ok(false)
}

fn handle_builtin_special(
    vm: &mut VmContext,
    tid: ThreadId,
    cls: &str,
    name: &str,
    desc: &str,
) -> Result<bool, VmError> {
    if (cls == "java/lang/Object" || cls == "java/lang/Throwable" || cls == "java/lang/Exception")
        && name == "<init>"
        && desc == "()V"
    {
        let _ = pop_ref(vm, tid)?;
        return Ok(true);
    }
    if cls == "java/lang/ref/WeakReference"
        && name == "<init>"
        && desc == "(Ljava/lang/Object;)V"
    {
        let referent = pop_ref(vm, tid)?;
        let Some(weak_obj) = pop_ref(vm, tid)? else {
            return Err(VmError::Heap(HeapError::NullPointer));
        };
        vm.heap.set_weak_referent(weak_obj, referent)?;
        return Ok(true);
    }
    Ok(false)
}

fn handle_builtin_virtual(
    vm: &mut VmContext,
    tid: ThreadId,
    cls: &str,
    name: &str,
    desc: &str,
) -> Result<bool, VmError> {
    if cls == "java/lang/Object" && name == "hashCode" && desc == "()I" {
        let Some(h) = pop_ref(vm, tid)? else {
            return Err(VmError::Heap(HeapError::NullPointer));
        };
        let hash = vm.heap.identity_hash(h)?;
        push_val(vm, tid, Value::Int(hash))?;
        return Ok(true);
    }
    if cls == "java/lang/Object" && name == "equals" && desc == "(Ljava/lang/Object;)Z" {
        let other = pop_ref(vm, tid)?;
        let Some(this) = pop_ref(vm, tid)? else {
            return Err(VmError::Heap(HeapError::NullPointer));
        };
        push_val(vm, tid, Value::Int(i32::from(Some(this) == other)))?;
        return Ok(true);
    }
    if (cls == "java/lang/ref/Reference" || cls == "java/lang/ref/WeakReference")
        && name == "get"
        && desc == "()Ljava/lang/Object;"
    {
        let Some(weak_obj) = pop_ref(vm, tid)? else {
            return Err(VmError::Heap(HeapError::NullPointer));
        };
        let target = vm.heap.get_weak_referent(weak_obj)?;
        push_val(vm, tid, Value::Ref(target))?;
        return Ok(true);
    }
    Ok(false)
}

fn advance_ip(
    vm: &mut VmContext,
    tid: ThreadId,
    new_ip: usize,
    instr_len: usize,
) -> Result<(), VmError> {
    let (cid, midx) = {
        let f = vm
            .scheduler
            .thread(tid)
            .and_then(|t| t.frames.last())
            .ok_or(VmError::InternalState("missing frame"))?;
        (f.class_id, f.method_index)
    };
    let next_pc = if new_ip < instr_len {
        vm.loader
            .class(cid)
            .and_then(|c| c.methods.get(midx))
            .and_then(|m| m.code.as_ref())
            .and_then(|code| code.instructions.get(new_ip))
            .map(|i| i.pc)
            .unwrap_or(0)
    } else {
        0
    };
    let f = vm
        .scheduler
        .thread_mut(tid)
        .and_then(|t| t.frames.last_mut())
        .ok_or(VmError::InternalState("missing frame"))?;
    f.ip = new_ip;
    f.pc = next_pc;
    Ok(())
}

fn cp_entry(vm: &VmContext, cid: ClassId, idx: u16) -> Result<&CpEntry, VmError> {
    vm.loader
        .class(cid)
        .and_then(|c| c.constant_pool.get(idx as usize))
        .ok_or(VmError::InternalState("constant pool index out of bounds"))
}

fn cp_class(vm: &VmContext, cid: ClassId, idx: u16) -> Result<String, VmError> {
    match cp_entry(vm, cid, idx)? {
        CpEntry::Class(n) => Ok(n.clone()),
        _ => Err(VmError::InternalState("expected Class constant")),
    }
}

fn cp_fieldref(vm: &VmContext, cid: ClassId, idx: u16) -> Result<(String, String, String), VmError> {
    match cp_entry(vm, cid, idx)? {
        CpEntry::Fieldref {
            class,
            name,
            descriptor,
        } => Ok((class.clone(), name.clone(), descriptor.clone())),
        _ => Err(VmError::InternalState("expected Fieldref constant")),
    }
}

fn cp_methodref(
    vm: &VmContext,
    cid: ClassId,
    idx: u16,
) -> Result<(String, String, String), VmError> {
    match cp_entry(vm, cid, idx)? {
        CpEntry::Methodref {
            class,
            name,
            descriptor,
        }
        | CpEntry::InterfaceMethodref {
            class,
            name,
            descriptor,
        } => Ok((class.clone(), name.clone(), descriptor.clone())),
        _ => Err(VmError::InternalState("expected Methodref constant")),
    }
}

fn top_frame_mut(vm: &mut VmContext, tid: ThreadId) -> Result<&mut Frame, VmError> {
    vm.scheduler
        .thread_mut(tid)
        .and_then(|t| t.frames.last_mut())
        .ok_or(VmError::InternalState("no active frame"))
}

fn push_val(vm: &mut VmContext, tid: ThreadId, val: Value) -> Result<(), VmError> {
    top_frame_mut(vm, tid)?.push_value(val);
    Ok(())
}

fn push_slot(vm: &mut VmContext, tid: ThreadId, slot: Slot) -> Result<(), VmError> {
    top_frame_mut(vm, tid)?.stack.push(slot);
    Ok(())
}

fn pop_slot(vm: &mut VmContext, tid: ThreadId) -> Result<Slot, VmError> {
    top_frame_mut(vm, tid)?
        .pop_slot()
        .ok_or(VmError::InternalState("operand stack underflow"))
}

fn pop_val(vm: &mut VmContext, tid: ThreadId) -> Result<Value, VmError> {
    top_frame_mut(vm, tid)?
        .pop_value()
        .ok_or(VmError::InternalState("operand stack underflow"))
}

fn pop_int(vm: &mut VmContext, tid: ThreadId) -> Result<i32, VmError> {
    top_frame_mut(vm, tid)?
        .pop_int()
        .ok_or(VmError::InternalState("expected int on operand stack"))
}

fn pop_long(vm: &mut VmContext, tid: ThreadId) -> Result<i64, VmError> {
    top_frame_mut(vm, tid)?
        .pop_long()
        .ok_or(VmError::InternalState("expected long on operand stack"))
}

fn pop_float(vm: &mut VmContext, tid: ThreadId) -> Result<u32, VmError> {
    top_frame_mut(vm, tid)?
        .pop_float()
        .ok_or(VmError::InternalState("expected float on operand stack"))
}

fn pop_double(vm: &mut VmContext, tid: ThreadId) -> Result<u64, VmError> {
    top_frame_mut(vm, tid)?
        .pop_double()
        .ok_or(VmError::InternalState("expected double on operand stack"))
}

fn pop_ref(vm: &mut VmContext, tid: ThreadId) -> Result<Option<Handle>, VmError> {
    top_frame_mut(vm, tid)?
        .pop_ref()
        .ok_or(VmError::InternalState("expected ref on operand stack"))
}

fn peek_ref(vm: &VmContext, tid: ThreadId) -> Result<Option<Handle>, VmError> {
    match vm
        .scheduler
        .thread(tid)
        .and_then(|t| t.frames.last())
        .and_then(|f| f.stack.last())
    {
        Some(Slot::Ref(h)) => Ok(*h),
        _ => Err(VmError::InternalState("expected ref at top of stack")),
    }
}

fn peek_receiver(vm: &VmContext, tid: ThreadId, arg_slots: usize) -> Result<Option<Handle>, VmError> {
    let stack = &vm
        .scheduler
        .thread(tid)
        .and_then(|t| t.frames.last())
        .ok_or(VmError::InternalState("missing frame"))?
        .stack;
    let idx = stack
        .len()
        .checked_sub(arg_slots + 1)
        .ok_or(VmError::InternalState("receiver underflow"))?;
    match stack[idx] {
        Slot::Ref(h) => Ok(h),
        _ => Err(VmError::InternalState("receiver is not a reference")),
    }
}

fn read_local(vm: &VmContext, tid: ThreadId, idx: usize) -> Result<Slot, VmError> {
    vm.scheduler
        .thread(tid)
        .and_then(|t| t.frames.last())
        .and_then(|f| f.locals.get(idx))
        .copied()
        .ok_or(VmError::InternalState("local index out of bounds"))
}

fn write_local(vm: &mut VmContext, tid: ThreadId, idx: usize, val: Value) -> Result<(), VmError> {
    if !top_frame_mut(vm, tid)?.set_local_value(idx, val) {
        return Err(VmError::InternalState("local write out of bounds"));
    }
    Ok(())
}

fn test_cmp(cmp: IntCmp, a: i32, b: i32) -> bool {
    match cmp {
        IntCmp::Eq => a == b,
        IntCmp::Ne => a != b,
        IntCmp::Lt => a < b,
        IntCmp::Ge => a >= b,
        IntCmp::Gt => a > b,
        IntCmp::Le => a <= b,
    }
}

fn java_f32_to_i32(v: f32) -> i32 {
    if v.is_nan() {
        0
    } else if v >= i32::MAX as f32 {
        i32::MAX
    } else if v <= i32::MIN as f32 {
        i32::MIN
    } else {
        v as i32
    }
}

fn java_f32_to_i64(v: f32) -> i64 {
    if v.is_nan() {
        0
    } else if v >= i64::MAX as f32 {
        i64::MAX
    } else if v <= i64::MIN as f32 {
        i64::MIN
    } else {
        v as i64
    }
}

fn java_f64_to_i32(v: f64) -> i32 {
    if v.is_nan() {
        0
    } else if v >= f64::from(i32::MAX) {
        i32::MAX
    } else if v <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        v as i32
    }
}

fn java_f64_to_i64(v: f64) -> i64 {
    if v.is_nan() {
        0
    } else if v >= i64::MAX as f64 {
        i64::MAX
    } else if v <= i64::MIN as f64 {
        i64::MIN
    } else {
        v as i64
    }
}
