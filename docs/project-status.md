# Current project status

Public code baseline reviewed on 2026-11-20 at `fc89ce9`. The
[roadmap](project-plan.md) owns development order and compatibility criteria.
[GitHub Issues](https://github.com/H3nb/Kilox/issues) own active assignments.

## Integrated public main

The [detailed capability inventory](capability-inventory.md) records checked
behaviors and remaining JVM, CLDC, MIDP and host gaps. On the reviewed public
`main`, verified bounded features include a structural classfile parser,
integer and same-class static-call execution proofs, ZIP/manifest readers and
an offscreen pixel surface. These are **foundations**, not a complete class
loader, CLDC runtime, MIDP environment or new-process save-state system.

For current implementation tasks use the [milestone roadmap](project-plan.md)
and its linked GitHub Issues; do not treat the inventory as a second task
registry. The [standards and dependency audit](standards-dependency-audit.md)
records type-level API coverage, unresolved member-level requirements and crate
admission decisions.


The public [package inventory](../examples/package_inventory.rs) reports
bounded structural archive, manifest and class-file results without exposing
suite names. A local run completed for all 23 corpus JARs, each with methods
carrying legacy `StackMap` attributes. This stage measures structural
admission only. Runtime preparation and execution are reported below.

## Local runtime experiments

The implementation used for these experiments is on the local
`codex/cldc-midp-runtime` branch. A fresh clone of public `main` can reproduce
the structural inventory above. Reproducing the runtime results requires
access to the local implementation and a permitted corpus. Public integration
is tracked in the [baseline milestone](https://github.com/H3nb/Kilox/issues/43).

The experimental branch has demonstrated bounded object execution, virtual
scheduling, portions of CLDC and MIDP, and several guest-state checkpoints
restored in a new process. In a local 23-package smoke run, one MIDP 2.0
package reached an interactive Form, paused, resumed and was destroyed.
Both CLDC `String.indexOf` overloads and the abstract `Reader` binding are
present in the local integration candidate. Fresh-process restore resumes
the original fixture while inherited `read` or `skip` has a pending guest
character read. A separate fixture verifies that a guest reference published
before a constructor throws remains usable after a catch and restore.

The local CLDC binding now covers `String.replace`, `String.regionMatches`,
and eight `String.valueOf` overloads, including binary32 formatting through
`Float.toString`, as well as `StringBuffer` array
append, insertion, and copying. Original guest fixtures check UTF-16,
mutation independence, invalid ranges, and fresh-process recovery.

The local default `InputStreamReader` converts ISO-8859-1 through virtual
guest stream calls. An original fixture resumes a pending read in a fresh
process. The named-encoding constructor remains open. All 69 package/profile
outcomes and diagnostics match the earlier run after these library changes.

Guest code can read the emulated configuration, profile, platform, and
default encoding through `System.getProperty`. Its identity hashes survive
collection and fresh-process restore. For untrusted MIDlets,
`getAppProperty` reads JAD values before manifest fallback. A new process
restores the fixture with the same JAD. A changed JAD is rejected before
the target session changes.

Three MIDP 2.0 variants pass their previous legacy `StackMap` and protected
constructor limits. With the default heap, two still reach the 64-record cap
during `startApp`. The third opens a 1,738,360-byte DEFLATE resource but
exceeds the default limit when allocating a byte array of the same size.

The opt-in expanded profile allows 256 object records and permits a byte
array to use the existing 4 MiB aggregate array budget. An original fixture
verifies the resource byte for byte across fresh-process restore. All three
variants return from `startApp` and reach a Canvas under this profile. Their
active Canvas state restores in a fresh process before the first visible
frame. Continued execution reaches the 256-record cap. The interactive Form
sample passes input, command dispatch and fresh-process recovery with both
profiles.

The local runtime now has an opt-in `Large` profile with 4,096 object records
and a shared budget of 262,144 user-instance field slots. All three Canvas
variants draw visible frames. For each variant, a fresh process restores its
first visible frame and runs another six seconds of simulated time with the
same timed keypad events. The frame-sequence checksums and final checkpoints
match uninterrupted execution. The interactive Form also passes its lifecycle
and input checks with `Large`. The 46 legacy and expanded package/profile
outcomes and diagnostics are unchanged.

All 11 MIDP 2.1 packages stopped during preparation. Eight need interfaces
outside the current bundle. Seven of those first need interfaces from Payment,
AMMS, Content Handler, Location, SIP or RMI. The other three first declare
fields typed as `Formatter`, `EGL10`, or `APDUConnection`.
[JSR 238](https://www.jcp.org/en/jsr/detail?id=238) ·
[JSR 239](https://www.jcp.org/en/jsr/detail?id=239) ·
[JSR 177](https://www.jcp.org/en/jsr/detail?id=177)

Four MIDP 2.0 packages first stop on fields typed as `SensorConnection`,
`VideoControl`, `Graphics3D`, or `World`. Both heap profiles report the same
first missing field types at preparation.
[JSR 256](https://www.jcp.org/en/jsr/detail?id=256) ·
[JSR 135](https://www.jcp.org/en/jsr/detail?id=135) ·
[JSR 184](https://www.jcp.org/en/jsr/detail?id=184)

These results describe the local corpus and candidate. Public runtime
integration remains subject to the rights review.

A separate test of 94 additional JARs declaring CLDC 1.1 and MIDP 2.1 in the
manifest stopped at preparation. Skipping opaque Code metadata let one
archive reach method resolution. Two archives first need String
`ConstantValue`.

At local runtime commit `4b4d9db`, original guest tests cover `Vector`
constructors, protected storage fields, positional operations, and
fresh-process restore while an insertion holds the monitor. Equality-based
search and removal, enumeration, and text conversion remain open.
All 94 archives still stopped at preparation. A temporary diagnostic at the
same commit showed that all 34 originally blocked on a `Vector` field reached
the next field check. Across the 94, the first unsupported field types are
now `Sprite` or `Sprite[]` in 58, `Hashtable` in 20, `Stack` in one, and
`TextBox` in one.

Local runtime commit `0bac52a` adds the protected `Writer` constructors
and lock field, UTF-16 convenience writes, and dispatch to a guest subclass.
An original fixture resumes the guest override in a fresh process while it
holds its configured lock. The concrete `OutputStreamWriter` remains open.

At local runtime commit `1c1d844`, virtual `Object.equals` and `hashCode`
reach guest overrides and the String, Integer and Long implementations.
Inherited defaults preserve object identity for ordinary and array receivers.
Commit `b89340a` adds CLDC 1.1 weak references. The collector clears
weak-only referents together and keeps ordinary subclass fields strongly
reachable. Fixtures recover live and cleared references in a separate
process. The combined candidate passed 714 locked offline Cargo tests and
strict all-target Clippy on Windows MSVC.

Commit `6b17efd` adds `Vector` search and removal through virtual guest
equality. The original fixture restores while equality is pending and
verifies that an exception releases the Vector monitor. This candidate
matched all 69 prior
package/profile diagnostics and reproduced three Canvas runs through
fresh-process recovery, plus interactive Form input and lifecycle recovery.

Local commit `48f6fc3` binds the five declared Stack methods and
`EmptyStackException`. An original fixture restores a pending search through
the inherited Vector implementation. In the additional MIDP 2.1 corpus, the
one archive previously stopped by a Stack field now reaches method admission,
where it needs support for a private synchronized method. All 94 archives
still stop during preparation.

Local commit `96506dd` initializes String-valued `ConstantValue` fields
through the interned literal pool before the declaring initializer. Both
previously blocked archives reach method resolution. Their next unresolved
references are `Display.callSerially(Runnable)` and
`IOException.toString()`. The other 92 outcomes match the Stack candidate.

Local commit `fccf0c3` adds `Vector.elements()`. Its original fixture checks
independent cursor positions, live growth, null elements, exhaustion, and
fresh-process recovery after collection. Vector text conversion remains
open.

Local runtime commit `6549304` binds MIDP Layer and Sprite position,
visibility, frame sequences, transforms, reference pixels and painting. An
original fixture verifies rendered pixels and resumes Sprite and Sprite array
state in a fresh process. Formatting, strict all-target Clippy and 725 locked
offline Cargo tests passed on Windows MSVC. Sprite collision, image
replacement and copy construction remain open.

All 58 additional MIDP 2.1 JARs that first failed on a Sprite or Sprite array
field advanced in preparation. Of those, 46 now first fail on a Hashtable
field, three on TiledLayer, one on LayerManager, and eight advance beyond the
field descriptor check. Across all 94 JARs, Hashtable is the first field
blocker in 67. All 94 still stop during preparation.

Local runtime commit `2bf3bbe` binds CLDC Hashtable construction, key lookup
and mutation, size, clearing, and protected rehash. An original fixture
checks colliding keys, reentrant mutation, and fresh-process recovery while
a guest equality call is active. Formatting, strict all-target Clippy, and
727 locked offline Cargo tests passed on Windows MSVC.

The same 67 archives now pass the Hashtable field check. Of those, 65
advance beyond field descriptor resolution. The other two next need
`java.lang.Runtime` and `HttpConnection`. All 94 archives in the additional
corpus still stop during preparation.

Local commit `c197647` supports synchronized guest instance methods. The
fixture checks private and virtual entry, contention, reentrant acquisition,
exception release, and fresh-process recovery. Formatting, strict all-target
Clippy, and 729 locked offline Cargo tests passed on Windows MSVC. Static
synchronized methods remain open.

The additional corpus at `3a55f9d` still stops during preparation. Seven JARs
that previously stopped on method access flags now report different first
failures. At the Hashtable baseline, method-resolution diagnostics identified
`Thread.currentThread()` as the first unresolved symbol in 52 of 94 JARs.
Those 52 preparation outcomes are unchanged by the monitor increment.

Local runtime commit `2d39070` includes MIDP HTTP GET through a host-supplied
adapter and CLDC `Throwable.toString()` through the runtime class name and
virtual `getMessage()`. Original fixtures recover a partially read HTTP body
and a suspended message override in new processes. The HTTP tests use a
deterministic in-memory adapter. Formatting, strict all-target Clippy, and
744 locked offline Cargo tests passed on Windows MSVC.

The archive that stopped on `IOException.toString()` now reaches an unresolved
`Image.createImage(...)` call. The archive that stopped on an `HttpConnection`
field next needs `TiledLayer`. All 94 additional archives still stop during
preparation. A constant-pool scan found `Image.createImage(String)` references
in 88 archives.

A release run at `44b18d1` matched all 69 paired package/profile diagnostics.
Three Canvas applications each replayed 360 ticks across fresh-process
recovery. An interactive Form passed fresh-process restore, text input,
command delivery, and a pause/resume/destroy cycle from the checkpoint.

At `b97dde3`, `Object.toString()` combines the runtime class name with
the unsigned hexadecimal result of virtual `hashCode()`. An original fixture
checks array names, platform and guest overrides, explicit superclass calls,
and fresh-process recovery while a hash override runs. The 94 additional
JAR preparation outcomes stayed the same.

At local runtime commit `28fd6a7`, scheduler-backed `Thread.currentThread()`
returns the same guest `Thread` object in a started worker and provides a
stable identity for root and callback contexts. Original fixtures verify
identity, priority, garbage collection, and fresh-process checkpoint recovery.
Formatting, strict all-target Clippy and 749 locked offline tests passed on
Windows MSVC.

All 52 archives that first stopped at `Thread.currentThread()` now pass that
call's preparation. The next blockers for those archives are
`Canvas.serviceRepaints()` in 15, a method resource limit in 14,
`Image.createImage(String)` in 12, `RecordStore.enumerateRecords(...)` in five,
`Graphics.setStrokeStyle(int)` in three, `StringBuffer.append(Object)` in two,
and `Sprite.collidesWith(Sprite, boolean)` in one. All 94 additional archives
still stop during preparation. Production and diagnostic probes agreed on
all 94 results.

Local runtime `acf7dcf` includes `Graphics.fillRoundRect()` for
mutable images and Canvas, and `Image.createImage(String)` for bounded
immutable PNG resources in the suite. MIDlet preparation accepts up to
16,384 code bytes per method within a frame-weighted verification budget.
An original MIDlet resumes inside a long `startApp()` method in a new
process. Formatting, strict all-target Clippy and 756 locked offline tests
passed on Windows MSVC.

One of the 94 additional archives that previously stopped on `fillRoundRect()`
entered `Active` and drew its Canvas on the first tick. It ran for 240
ticks in the initial probe. A second probe replayed 360 ticks with a queued
key press and release, then paused, resumed and destroyed the MIDlet.
Fresh-process restore produced the same frame digest and final checkpoint.

The 14 archives previously stopped by the method bytecode limit advanced to
method resolution. The 14 that first stopped on named image loading advanced
past that call. The remaining 93 archives stopped during preparation.
Production and diagnostic outcomes agreed across all 94. The most common
first unresolved calls were `RecordStore.enumerateRecords(...)` (24) and
`Canvas.serviceRepaints()` (16).

At local runtime `a5491d7`, `StringBuffer.setLength(int)` truncates or
pads with NUL, `insert(int, char)` inserts one UTF-16 unit, and
`append(Object)` dispatches the argument's virtual `toString()`. A
fixture restores during conversion in a fresh process and checks reentrant
mutation and monitor release after a guest exception. RMS now reads record
sizes and copies data into a caller-provided buffer after validating the
destination range. The original RMS fixture checks persisted sizes, empty
records, offset reads and preservation of the buffer on a rejected copy.
Formatting, strict all-target Clippy and 757 locked offline tests passed on
Windows MSVC.

Four of the 94 additional archives advanced beyond their first StringBuffer
blocker. One subsequently advanced past both new RMS reads and reached
`MIDlet.platformRequest(String)`. The previously launched Canvas still
replayed 360 ticks and completed pause, resume and destroy after
fresh-process restore. The remaining 93 archives stopped during
preparation. The most common first unresolved calls were
`RecordStore.enumerateRecords(...)` (26), `Canvas.serviceRepaints()` (17)
and `Throwable.printStackTrace()` (6). A separate diagnostic identified
an unavailable static method owner in ten other archives. Nine reference
Nokia `DeviceControl` and one references CLDC `java.lang.Byte`.

Local runtime `32979fb` prints `Throwable.printStackTrace()` to the
guest `System.err` with the virtual description and the stored creation
frames. Frame lines include the method's bytecode PC. Original fixtures
verify fresh-process restore at the output boundaries and confirm that
`System.out` stays separate. Formatting, strict all-target Clippy and
763 locked offline tests passed on Windows MSVC.

All seven archives with a first unresolved `printStackTrace()` call
advanced. Four now need `Canvas.serviceRepaints()`, one needs
`RecordStore.enumerateRecords(...)`, one needs `Object.wait()`, and one
needs `Form(String, Item[])`. Production and diagnostic probes agreed on
all 94 results. The same Canvas replayed 360 ticks and completed pause,
resume and destroy after fresh-process restore. The remaining 93 archives
stop during preparation. `RecordStore.enumerateRecords(...)` (27) and
`Canvas.serviceRepaints()` (21) remain the most frequent first unresolved
calls.

Local runtime `f500b9a` supports `Form(String, Item[])`. Its original
MIDlet fixture checks initial item order and independence from later array
writes, constructor faults without partial item ownership, and fresh-process
recovery. Alert and List constants now take their fixed heap identities
before standard streams are allocated. An Alert fixture verifies those
constants alongside guest `System.err` across restore. Formatting, strict
all-target Clippy and 763 locked offline tests passed on Windows MSVC.

The archive that first stopped on the Form constructor now enters `Active`
and shows a Form with one text field and two commands on its first tick.
It stayed active through a 240-tick probe, accepted a text edit and command
activation, and passed fresh-process checkpoint recovery and the
pause/resume/destroy cycle. The previously verified Canvas also remained
active during the 240-tick probe. Production and diagnostic runs agreed
on all 94 results. Two archives now run in this cohort and 92 still
stop during preparation.

Local runtime `aeb8710` implements the MIDP `Sprite(Sprite)` copy
constructor and the CLDC 1.1 `Byte` wrapper. Original guest fixtures verify
independent Sprite frame state, copied mutable image pixels, Byte range
checks and parsing, and fresh-process recovery for both bindings.
Formatting, strict all-target Clippy and 764 locked offline tests passed on
Windows MSVC.

In the 94-archive cohort, both archives that first needed the Sprite copy
constructor now reach `RecordStore.enumerateRecords(...)`, the first unresolved
call for 29 archives. The archive that first needed `Byte` now reaches
`Object.wait()`. Production and diagnostic probes agree on every result.
Two MIDlets reach `Active` and remain active through 240 ticks. The other 92
archives stop during preparation.

Local runtime `bc1a68a` binds solid and dotted strokes for lines, rectangles,
rounded rectangles and arcs. An original guest fixture checks clipping,
invalid-style rejection and stroke state after a fresh-process paint
restore. Three archives passed their previous `Graphics.setStrokeStyle()`
blocker and reached RMS enumeration. Formatting, strict all-target Clippy
and 766 locked offline tests passed on Windows MSVC.

Local runtime `5456b0d` adds synchronous `Canvas.serviceRepaints()` with
nested paint and recovery, and `RecordStore.enumerateRecords(..., false)`
with guest filter and comparator callbacks, cursor operations, rebuild and
recovery during a callback. Live enumeration updates remain open.
Formatting, strict all-target Clippy and 771 locked offline tests passed on
Windows MSVC.

In a startup probe limited to three ticks, 16 of the same 94 MIDlets reached
`Active` without a runtime fault. Eleven of the 14 new launches previously
stopped at RMS enumeration and three at `Canvas.serviceRepaints()`. Eight
showed non-background pixels or visible controls. Another 75 stopped in
preparation, one failed in its constructor and two failed during startup.
`StackMapTypeMismatch` was the most frequent preparation failure (24).
Production and diagnostic outcomes agreed for all 94 archives.

Local commit `17852e6` fixes reading the runtime class of a guest object
after its superclass constructor returns. This also fixes the default
`Object.toString()` when called from that constructor. Eight focused tests
passed, including fresh-process recovery in the Object description fixture.
All three archives that failed during construction or startup at
`5456b0d` reached `Active` with `17852e6`. The whole 94-archive rerun
at that revision produced 19 active sessions after three ticks. Ten showed
non-background pixels or visible controls. The other 75 stopped in
preparation. Seventeen of the active sessions exhausted the third tick's
instruction budget.

One newly admitted Canvas MIDlet was also exercised across 12 ticks with
queued key input and pause, resume and destroy. The original run and a fresh
process restored from its first visible frame produced a matching frame
checksum and identical final checkpoints. Gameplay and broad compatibility
remain to be verified.

Local runtime `ccafeaf` checks legacy StackMap reference compatibility
using inferred-to-declared assignability. The historical CLDC rule lets
class references match interface declarations. The verifier still infers
and checks execution state independently. An original regression accepts
an interface declaration and rejects a concrete type that the inferred
value cannot satisfy. Formatting, strict all-target Clippy and 772 locked
offline tests passed on Windows MSVC.

All 24 archives that previously reported `StackMapTypeMismatch` reached
`Active` by the third tick. The same 94 archive hashes were checked.
The total rose to 43 active sessions, 27 with non-background pixels or
visible controls. Thirty-eight active sessions exhausted their third
tick instruction budget. The other 51 archives stopped in preparation.

Two newly admitted Canvas MIDlets, one from each affected interface
cohort, completed 60 ticks of a replay with queued input, pause, resume
and destroy. Each recovered in a fresh process with a matching frame
checksum and byte-identical final checkpoint.

Local commit `e4c6e35` adds StringBuffer character reads and replacements,
range and single-code-unit deletions, and signed long insertion.
The original fixture checks capacity, a retained surrogate, caught
index faults and immutable String copies after fresh-process recovery.
All eight focused StringBuffer tests and strict focused Clippy passed.

Local runtime `21326c3` binds Sprite-to-Sprite collision, in bounds-only and
pixel modes, and `defineCollisionRectangle`. The original fixture tests
visibility, the eight transforms, frame selection and copying a custom
rectangle across a fresh-process restore. Image and TiledLayer collision
overloads remain open. Sprite programs select a new checkpoint profile
because the object layout has changed. A real MIDlet that previously
stopped at Sprite collision restored its initial scheduler checkpoint
byte-for-byte in a fresh process with the Large heap profile.
Formatting, strict all-target Clippy and 776 locked offline tests passed
on Windows MSVC.

Five additional archives reached `Active` with the Sprite and StringBuffer
increments, bringing the same three-tick cohort to 48 of 94. Two still
had `startApp()` pending at tick three. One showed a Canvas by tick 15 and
remained active at tick 30. The other stopped on an image allocation limit
at tick 9. A newly admitted Sprite MIDlet also hit an image allocation
limit after its first visible frame.

Local commits `9909754` and `752e385` add explicit `Error` and
`NoClassDefFoundError` constructors and admit `Timer` construction in
protected ranges. Separate focused suites verified retained error
messages and traces, timer behavior and fresh-process restore.
The one archive that progressed from Sprite collision to
`NoClassDefFoundError(String)` and then to protected Timer construction
reached `Active` in a targeted rerun, with `startApp()` still pending at
tick three. The other 93 archives were not rerun at `752e385`.

The local Large heap profile at `fbfdba7` allows up to 8 MiB of live decoded
image data. The Legacy and Expanded budgets and the per-image limit remain
at 4 MiB. Allocation and checkpoint restore enforce the same profile budget.
An original fixture retained 4.5 MiB of images and restored them in a
separate process without a checkpoint format change.

The same 94 archives were rerun at `fbfdba7`. At tick three, 49 were
`Active`, including 46 that completed `startApp()`. 29 had shown a frame.
The two applications previously stopped by image pressure both reached tick
120 with visible Canvas output and no pending lifecycle operation. In
separate runs, each restored its first visible frame in a fresh process,
replayed 60 ticks with a key tap, and then paused, resumed and destroyed.
Frame sequence hashes and final checkpoint bytes matched between the original
and restored runs. These bounded headless runs did not measure gameplay
coverage or real-time performance. Formatting, strict all-target Clippy and
776 locked Rust tests passed at `fbfdba7`.

In a separate class-admission check, the same local revision rejected an
integer operand at `areturn` when preparing a malformed variant of an original
fixture from its class bytes. This is the condition that failed on the
[separate audit candidate](https://github.com/H3nb/Kilox/actions/runs/45538411260).

Local revision `31f3004` binds `String.valueOf(Object)` in closed class
bundles. An original fixture verifies null input, String identity, guest
override results and exceptions, and fresh-process restore after the override
updates a field. Formatting, strict all-target Clippy, and 777 locked Rust
tests passed.

The same 94 archives produced 50 `Active` states at tick three, including
47 completed `startApp()` calls. The other 93 outcomes matched the previous
revision. The newly admitted MIDlet first drew a Canvas at tick four and
remained active through tick 120. A separate run restored that first visible
frame in a fresh process and replayed 60 ticks with a key tap, pause, resume
and destroy. Frame sequence hashes and final checkpoint bytes matched.

Local revision `644d435` accepts a complete final manifest header or
continuation at EOF when matching an untrusted MIDlet suite. The generic
archive parser still requires the final line terminator. Formatting, strict
all-target Clippy, and 25 focused tests passed, covering package integrity,
JAD matching, property precedence, launch and heap profile restore.

The same 94 unmodified archives yielded 52 `Active` states at tick three,
including 49 completed `startApp()` calls and 31 with visible output. The
two newly admitted MIDlets displayed Canvas output at tick one and were
still active at tick 120. Each restored that first visible frame in a fresh
process and replayed 60 ticks with input, pause, resume and destroy. Frame
sequence hashes and final checkpoint bytes matched. The other 92 three-tick
outcomes were unchanged.

A private link diagnostic identified `com.nokia.mid.ui.DeviceControl.setLights(int,int)`
as the first missing method owner for nine remaining archives. Six different
archives fail the historical identifier policy because they declare a field
with a Java keyword as its name. An experimental run accepting that name
advanced three to `Active` at tick three, including one with `startApp()`
still pending. The executable identifier policy remains unchanged.

Local revision `82dcb72` binds the Nokia screen backlight request, checks
the light ID and level, and retains the requested brightness in checkpoint
state for the presentation host. Its original fixture checks invalid argument
exceptions and fresh-process restore. All nine packages previously blocked
at this binding progressed to a later preparation check. Eight reached a
non-returning bytecode cycle, and one reached protected-constructor access.

Local revision `0ea92ab` accepts in-bounds cyclic methods and keeps the
fallthrough check. The same 94 archives yielded 61 `Active` states and 58
completed `startApp()` calls at tick three. Nine additional MIDlets became
active, including one whose cycle was already reachable before the
backlight binding. All nine displayed Canvas output by tick 75 and were
active at tick 120. The 84 other three-tick outcomes outside the ten
changed archives matched the prior baseline.

One of three targeted Canvas replays restored in a fresh process and matched
60 ticks of frame hashes, input, pause, resume, destroy and final checkpoint
bytes. The other two received `InvalidObjectGraph` when checkpointing the
first visible frame. A private diagnostic located one rejection in the
throwable trace root check. Formatting, strict all-target Clippy and 780
locked Rust tests passed at `0ea92ab`.

Local revision `8aade11` handles `MIDlet.platformRequest` through an explicit
host adapter, with guest-visible errors and fresh-process restore coverage.
The host retains approval and execution of external requests. Suite
preparation now shares the GCF exception class across both bindings and
accepts protected-constructor calls within the same runtime package.

At tick three, 68 of the same 94 archives were `Active`, 64 had completed
`startApp()`, 32 had displayed a frame, and 26 were blocked during preparation.
Six additional MIDlets became active through `platformRequest` and one through
the constructor fix. One other archive advanced to a later unresolved method.
All three newly active MIDlets selected for longer runs displayed Canvas output
by tick 18 and were still active at tick 120.

The two previously rejected Canvas checkpoints now accept throwable traces
rooted in guest Java threads. Both restored in a new process and matched frame
hashes and final checkpoint bytes across 60 ticks, key input, pause, resume
and destroy. Rustfmt, strict all-target Clippy and 48 focused Rust tests passed
on this revision. These runs measure startup and bounded replay. Gameplay,
broader checkpoint coverage and MIDP conformance remain to be tested.

The [CLDC milestone](https://github.com/H3nb/Kilox/issues/44) tracks the
shared verification and library work.

## Active dependencies

- Establish the implementation-use and distribution basis for public runtime
  integration. The [licensing and provenance record](licensing-and-provenance.md)
  tracks this review. The [specification map](specification-map.md) tracks
  technical evidence for the final CLDC clauses.
- [#33](https://github.com/H3nb/Kilox/issues/33) tracks the original local
  typed-reference feasibility experiment. Review it in the CLDC milestone
  alongside other independently authored candidate changes.
- Establish the reproducible baseline first. Then diagnose the first shared
  verification failure with a small original fixture and continue with the
  highest-impact CLDC and MIDP gaps.
