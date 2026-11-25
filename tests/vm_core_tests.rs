// SPDX-License-Identifier: GPL-3.0-only
//! Integration tests for the Safe Rust VM Core (`j2me_vm::vm`).

use j2me_vm::vm::verifier::{parse_legacy_stack_map, VerificationType};
use j2me_vm::vm::{
    ArrayKind, CldcVersion, HeapBudget, MidpVersion, ProfileContract, SnapshotError, Value,
    VerifyErrorKind, VmContext, VmError, VmStep,
};

const MINIMAL: &[u8] = include_bytes!("fixtures/compiled/MinimalClass.class");
const LOCALS: &[u8] = include_bytes!("fixtures/compiled/LocalArithmetic.class");
const BRANCH_LOOP: &[u8] = include_bytes!("fixtures/compiled/BranchLoop.class");
const NESTED: &[u8] = include_bytes!("fixtures/compiled/NestedStaticCalls.class");
const RECURSIVE: &[u8] = include_bytes!("fixtures/compiled/RecursiveStaticCalls.class");

#[test]
fn executes_original_kilox_fixtures_through_vm_core() {
    let mut vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    vm.load_class(MINIMAL).unwrap();
    let tid = vm
        .spawn_static("main", 5, "MinimalClass", "answer", "()I", &[])
        .unwrap();
    let outcome = vm.run(1_000).unwrap();
    assert_eq!(
        outcome,
        VmStep::ThreadReturned {
            thread: tid,
            value: Some(Value::Int(42)),
        }
    );

    let mut vm_nested = VmContext::new(ProfileContract::cldc11_midp20_large());
    vm_nested.load_class(NESTED).unwrap();
    let tid2 = vm_nested
        .spawn_static(
            "main",
            5,
            "NestedStaticCalls",
            "evaluate",
            "(I)I",
            &[Value::Int(4)],
        )
        .unwrap();
    let out2 = vm_nested.run(2_000).unwrap();
    assert!(matches!(
        out2,
        VmStep::ThreadReturned {
            thread,
            value: Some(Value::Int(_)),
        } if thread == tid2
    ));
}

#[test]
fn enforces_cldc10_vs_cldc11_edition_contracts() {
    let p10 = ProfileContract::cldc10_midp10_compact();
    let p11 = ProfileContract::cldc11_midp21_large();

    assert_eq!(
        p10.system_property("microedition.configuration"),
        Some("CLDC-1.0")
    );
    assert_eq!(
        p10.system_property("microedition.profiles"),
        Some("MIDP-1.0")
    );
    assert!(!p10.cldc.allows_floating_point());
    assert!(!p10.cldc.allows_weak_references());

    assert_eq!(
        p11.system_property("microedition.configuration"),
        Some("CLDC-1.1")
    );
    assert_eq!(
        p11.system_property("microedition.profiles"),
        Some("MIDP-2.1")
    );
    assert!(p11.cldc.allows_floating_point());
    assert!(p11.cldc.allows_weak_references());

    let vm10 = VmContext::new(p10);
    assert!(vm10
        .loader
        .find_class("java/lang/ref/WeakReference")
        .is_none());

    let vm11 = VmContext::new(p11);
    assert!(vm11
        .loader
        .find_class("java/lang/ref/WeakReference")
        .is_some());
}

#[test]
fn parses_legacy_cldc_stack_map_and_rejects_float_in_cldc10() {
    // 1 frame at offset 0x0004: 1 local (Integer=1), 1 stack (Float=2)
    let raw: &[u8] = &[0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00, 0x01, 0x02];

    let frames_11 = parse_legacy_stack_map(raw, &ProfileContract::cldc11_midp20_large()).unwrap();
    assert_eq!(frames_11.len(), 1);
    assert_eq!(frames_11[0].offset, 4);
    assert_eq!(frames_11[0].locals, vec![VerificationType::Integer]);
    assert_eq!(frames_11[0].stack, vec![VerificationType::Float]);

    let err_10 =
        parse_legacy_stack_map(raw, &ProfileContract::cldc10_midp10_compact()).unwrap_err();
    assert!(matches!(err_10.kind, VerifyErrorKind::InvalidStackMap(_)));
}

#[test]
fn heap_gc_reclaims_unreachable_and_clears_weak_references() {
    let mut vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    let obj_cls = vm.loader.well_known().object;
    let weak_cls = vm.loader.well_known().weak_reference.unwrap();

    let target = vm.heap.alloc_instance(obj_cls, Vec::new(), false).unwrap();
    let weak = vm.heap.alloc_instance(weak_cls, Vec::new(), true).unwrap();
    vm.heap.set_weak_referent(weak, Some(target)).unwrap();

    // Keep only `weak` strongly rooted via a static-like external root.
    let (reclaimed, cleared) = vm.heap.collect_garbage(&[weak]);
    assert_eq!(reclaimed, 1);
    assert_eq!(cleared, 1);
    assert_eq!(vm.heap.get_weak_referent(weak).unwrap(), None);
    assert!(vm.heap.get(target).is_err());

    // Verify primitive array allocation and budget accounting.
    let arr = vm
        .heap
        .alloc_primitive_array(obj_cls, ArrayKind::Int, 16)
        .unwrap();
    assert_eq!(vm.heap.array_len(arr).unwrap(), 16);
}

#[test]
fn checkpoint_and_atomic_restore_reproduces_identical_continuation() {
    let profile = ProfileContract::new(
        CldcVersion::Cldc11,
        MidpVersion::Midp20,
        HeapBudget::compact(),
    );

    let mut vm_a = VmContext::new(profile);
    vm_a.load_class(BRANCH_LOOP).unwrap();
    vm_a.load_class(LOCALS).unwrap();
    vm_a.load_class(RECURSIVE).unwrap();

    let tid = vm_a
        .spawn_static(
            "worker",
            5,
            "BranchLoop",
            "evaluate",
            "(I)I",
            &[Value::Int(6)],
        )
        .unwrap();

    // Advance partway, then capture a checkpoint at a global safepoint.
    let _ = vm_a.run(4).unwrap();
    let snap = vm_a.checkpoint();

    // Continue original VM to completion.
    let expected = vm_a.run(10_000).unwrap();

    // Restore into a brand-new VmContext (simulating a fresh OS process).
    let mut vm_b = VmContext::new(profile);
    vm_b.load_class(BRANCH_LOOP).unwrap();
    vm_b.load_class(LOCALS).unwrap();
    vm_b.load_class(RECURSIVE).unwrap();
    vm_b.restore(&snap).unwrap();

    let restored = vm_b.run(10_000).unwrap();
    assert_eq!(restored, expected);
    assert!(matches!(
        restored,
        VmStep::ThreadReturned {
            thread,
            value: Some(Value::Int(_)),
        } if thread == tid
    ));

    // Tampering with snapshot bytes must fail checksum atomically without mutating VM.
    let mut corrupted = snap.clone();
    corrupted[10] ^= 0xff;
    let before_status = vm_b.status();
    assert_eq!(
        vm_b.restore(&corrupted),
        Err(VmError::Snapshot(SnapshotError::ChecksumMismatch))
    );
    assert_eq!(vm_b.status(), before_status);
}

#[test]
fn monitor_reentrancy_and_wait_notify_semantics() {
    let mut vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    vm.load_class(MINIMAL).unwrap();
    let lock = vm
        .heap
        .alloc_instance(vm.loader.well_known().object, Vec::new(), false)
        .unwrap();

    let t1 = vm
        .spawn_static("t1", 5, "MinimalClass", "answer", "()I", &[])
        .unwrap();
    let t2 = vm
        .spawn_static("t2", 5, "MinimalClass", "answer", "()I", &[])
        .unwrap();

    assert!(vm.scheduler.monitor_enter(t1, lock));
    assert!(vm.scheduler.monitor_enter(t1, lock)); // reentrant depth = 2
    assert!(!vm.scheduler.monitor_enter(t2, lock)); // t2 blocks on entry queue

    // t1 calls wait(), releasing full reentrancy so t2 acquires lock.
    vm.scheduler.monitor_wait(t1, lock, 100).unwrap();
    // t2 notifies t1 and exits lock.
    vm.scheduler.monitor_notify(t2, lock, false).unwrap();
    vm.scheduler.monitor_exit(t2, lock).unwrap();
    // t1 should now be runnable again.
    assert!(vm.scheduler.select_runnable().is_some());
}

#[test]
fn restore_rejects_snapshot_exceeding_destination_heap_budget_atomically() {
    let mut large_vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    let obj_cls = large_vm.loader.well_known().object;
    for _ in 0..257 {
        large_vm
            .heap
            .alloc_instance(obj_cls, Vec::new(), false)
            .unwrap();
    }
    let snap = large_vm.checkpoint();

    let mut compact_vm = VmContext::new(ProfileContract::new(
        CldcVersion::Cldc11,
        MidpVersion::Midp20,
        HeapBudget::compact(),
    ));
    let before = compact_vm.status();
    let err = compact_vm.restore(&snap).unwrap_err();
    assert!(matches!(
        err,
        VmError::Snapshot(SnapshotError::BudgetExceeded(_))
    ));
    assert_eq!(compact_vm.status(), before);
}

#[test]
fn class_admission_rejects_operand_stack_underflow_at_load() {
    let mut mutated = MINIMAL.to_vec();
    let code_pos = mutated
        .windows(3)
        .position(|w| w == [0x10, 0x2a, 0xac])
        .expect("MinimalClass bipush 42; ireturn");
    // Replace `bipush 42; ireturn` with `nop; iadd; ireturn` (underflow on empty stack).
    mutated[code_pos] = 0x00;
    mutated[code_pos + 1] = 0x60;
    mutated[code_pos + 2] = 0xac;

    let mut vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    let err = vm.load_class(&mutated).unwrap_err();
    assert!(matches!(
        err,
        VmError::Loader(j2me_vm::vm::LoaderError::Verify(v))
            if v.kind == VerifyErrorKind::StackUnderflow
    ));
}
