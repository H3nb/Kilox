// SPDX-License-Identifier: GPL-3.0-only
//! Independent audit regression: restoring a valid snapshot must respect the
//! receiving VM's resource limits before any state is committed.

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
