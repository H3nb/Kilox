// SPDX-License-Identifier: GPL-3.0-only
//! Edition-aware configuration and profile contracts for CLDC 1.0/1.1 and
//! MIDP 1.0/2.0/2.1, plus explicit bounded heap profiles.

/// Supported CLDC configuration editions (JSR 30 and JSR 139).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CldcVersion {
    /// JSR 30: no floating-point bytecodes/types, no `java.lang.ref`.
    Cldc10,
    /// JSR 139: adds IEEE 754 `float`/`double` and `WeakReference`.
    Cldc11,
}

impl CldcVersion {
    pub const fn as_property(self) -> &'static str {
        match self {
            Self::Cldc10 => "CLDC-1.0",
            Self::Cldc11 => "CLDC-1.1",
        }
    }

    pub const fn allows_floating_point(self) -> bool {
        matches!(self, Self::Cldc11)
    }

    pub const fn allows_weak_references(self) -> bool {
        matches!(self, Self::Cldc11)
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Cldc10 => 10,
            Self::Cldc11 => 11,
        }
    }

    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            10 => Some(Self::Cldc10),
            11 => Some(Self::Cldc11),
            _ => None,
        }
    }
}

/// Supported legacy MIDP profile editions (JSR 37 and JSR 118 / MR2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MidpVersion {
    /// JSR 37: basic LCDUI, RMS, MIDlet, HTTP; no Game API or media.
    Midp10,
    /// JSR 118: adds Game API, audio subset, PushRegistry, HTTPS/PKI, Timer.
    Midp20,
    /// JSR 118 MR2: MIDP 2.0 with maintenance clarifications.
    Midp21,
}

impl MidpVersion {
    pub const fn as_property(self) -> &'static str {
        match self {
            Self::Midp10 => "MIDP-1.0",
            Self::Midp20 => "MIDP-2.0",
            Self::Midp21 => "MIDP-2.1",
        }
    }

    pub const fn allows_game_api(self) -> bool {
        matches!(self, Self::Midp20 | Self::Midp21)
    }

    pub const fn allows_media_audio(self) -> bool {
        matches!(self, Self::Midp20 | Self::Midp21)
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Midp10 => 10,
            Self::Midp20 => 20,
            Self::Midp21 => 21,
        }
    }

    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            10 => Some(Self::Midp10),
            20 => Some(Self::Midp20),
            21 => Some(Self::Midp21),
            _ => None,
        }
    }
}

/// Deterministic resource limits for a `VmContext` heap and call stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapBudget {
    pub max_objects: usize,
    pub max_field_slots: usize,
    pub max_array_bytes: usize,
    pub max_frames_per_thread: usize,
    pub max_threads: usize,
    pub instruction_quantum: u32,
}

impl HeapBudget {
    /// Compact default profile for unit fixtures and minimal MIDlets.
    pub const fn compact() -> Self {
        Self {
            max_objects: 256,
            max_field_slots: 16_384,
            max_array_bytes: 4 * 1024 * 1024,
            max_frames_per_thread: 64,
            max_threads: 16,
            instruction_quantum: 1_024,
        }
    }

    /// Large profile aligned with Kilox real-world Canvas MIDlet experiments.
    pub const fn large() -> Self {
        Self {
            max_objects: 4_096,
            max_field_slots: 262_144,
            max_array_bytes: 16 * 1024 * 1024,
            max_frames_per_thread: 128,
            max_threads: 64,
            instruction_quantum: 2_048,
        }
    }
}

/// Immutable profile contract bound to a single `VmContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileContract {
    pub cldc: CldcVersion,
    pub midp: MidpVersion,
    pub budget: HeapBudget,
    /// When true, methods with branches require a valid legacy CLDC `StackMap`.
    pub require_stack_map: bool,
}

impl ProfileContract {
    pub const fn new(cldc: CldcVersion, midp: MidpVersion, budget: HeapBudget) -> Self {
        Self {
            cldc,
            midp,
            budget,
            require_stack_map: false,
        }
    }

    pub const fn cldc11_midp20_large() -> Self {
        Self::new(CldcVersion::Cldc11, MidpVersion::Midp20, HeapBudget::large())
    }

    pub const fn cldc11_midp21_large() -> Self {
        Self::new(CldcVersion::Cldc11, MidpVersion::Midp21, HeapBudget::large())
    }

    pub const fn cldc10_midp10_compact() -> Self {
        Self::new(
            CldcVersion::Cldc10,
            MidpVersion::Midp10,
            HeapBudget::compact(),
        )
    }

    pub const fn with_strict_stack_map(mut self, strict: bool) -> Self {
        self.require_stack_map = strict;
        self
    }

    /// Checks whether a class-file major/minor version is permitted under CLDC.
    pub const fn admits_class_version(&self, major: u16, minor: u16) -> bool {
        match major {
            45 => true,
            46..=48 => minor == 0,
            _ => false,
        }
    }

    /// Resolves standard read-only `System.getProperty` keys for this contract.
    pub fn system_property(&self, key: &str) -> Option<&'static str> {
        match key {
            "microedition.configuration" => Some(self.cldc.as_property()),
            "microedition.profiles" => Some(self.midp.as_property()),
            "microedition.platform" => Some("Kilox-j2me-vm"),
            "microedition.encoding" => Some("ISO-8859-1"),
            "microedition.locale" => Some("en-US"),
            _ => None,
        }
    }
}
