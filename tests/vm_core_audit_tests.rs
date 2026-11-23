// SPDX-License-Identifier: GPL-3.0-only
//! Independent audit regressions for hostile JVM class files and VM snapshots.

use j2me_vm::vm::{CldcVersion, HeapBudget, MidpVersion, ProfileContract, VmContext};

#[test]
fn restore_rejects_heap_exceeding_destination_budget_atomically() {
    let mut large = VmContext::new(ProfileContract::cldc11_midp20_large());
    let object = large.loader.well_known().object;
    for _ in 0..=HeapBudget::compact().max_objects {
        large
            .heap
            .alloc_instance(object, Vec::new(), false)
            .expect("the source profile permits these allocations");
    }
    let snapshot = large.checkpoint();

    let compact_profile = ProfileContract::new(
        CldcVersion::Cldc11,
        MidpVersion::Midp20,
        HeapBudget::compact(),
    );
    let mut restored = VmContext::new(compact_profile);
    let before = restored.status();
    assert!(
        restored.restore(&snapshot).is_err(),
        "restoring more objects than the destination permits must fail"
    );
    assert_eq!(
        restored.status(),
        before,
        "a rejected restore must not change the VM state"
    );
}

#[test]
fn class_admission_rejects_operand_stack_underflow() {
    let mut malformed = include_bytes!("fixtures/compiled/MinimalClass.class").to_vec();
    // Replace answer()I's "bipush 42; ireturn" with
    // "iadd; nop; ireturn". The operand stack starts empty,
    // but iadd requires two integers. All instruction lengths remain valid.
    let offset = malformed
        .windows(3)
        .position(|window| window == [0x10, 0x2a, 0xac])
        .expect("known fixture contains the expected answer method");
    malformed[offset..offset + 3].copy_from_slice(&[0x60, 0x00, 0xac]);

    let mut vm = VmContext::new(ProfileContract::cldc11_midp20_large());
    assert!(
        vm.load_class(&malformed).is_err(),
        "the VM must reject an operand-stack-underflow method at admission"
    );
}
