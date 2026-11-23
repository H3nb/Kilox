// SPDX-License-Identifier: GPL-3.0-only
//! Independent, host-neutral Java ME VM core in safe Rust.
//!
//! Preserves the bounded G1/WP02 foundations (`archive`, `classfile`,
//! `execution`, `surface`) and exposes the full Safe Rust VM Core under `vm`.

#![forbid(unsafe_code)]

pub mod archive;
pub mod classfile;
pub mod execution;
pub mod surface;
pub mod vm;
