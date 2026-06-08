//! Vtable-fingerprint anchored relocation: relocate a C++ virtual method across builds by matching the
//! structure of the vtable it is dispatched from.
//!
//! A virtual method is installed in its class's vtable, a run of consecutive code pointers. A recompile
//! rewrites individual method bodies, but the vtable's *shape*, the ordered set of methods it dispatches,
//! is fixed by the class layout and survives: the same class keeps the same methods in the same slots
//! build to build even when every method body changed. So a vtable is identifiable across builds by
//! fingerprinting each slot's function with a short mnemonic window and matching the table whose per-slot
//! fingerprints agree best under a Needleman-Wunsch alignment (so methods inserted or removed across
//! versions shift the match rather than breaking it); once the table is relocated, the target's aligned
//! slot is read back to recover the method's new address.
//!
//! This is the complement of the other anchors: where [`super::identity`]'s string anchor pins a function
//! by a read-only string it references and [`super::imports`] by the API set it calls, this pins it by the
//! class it belongs to, which is exactly the handle a virtual method with neither a distinctive string nor
//! a distinctive import set still has. A slot can dispatch through an MSVC adjustor thunk
//! (`add ecx, imm ; jmp`) under multiple inheritance; the thunk is followed so the real method, not the
//! thunk, is what relocates.
//!
//! Per-slot agreement is a distinctiveness-weighted mean Dice over the alignment (a method inherited
//! into many classes weighs little, a class-specific override weighs ~1), so a sibling that shares only
//! the inherited backbone cannot tie the real class. Measured on the real GMS v84 vtable at .text RVA
//! 0x78F16C (101 slots): a clean slot relocates to v88 at weighted agreement 0.993 (margin 0.31) and to
//! v83 at 1.000; chained through intermediate builds it carries v83 -> v84 -> v88 -> v91, and at a v95
//! class refactor the agreement falls below the gate, where the matcher declines rather than guess. The
//! caller ([`super::vtable_relocate`]) reaches builds over the highest-confidence chain and reports the
//! version ranges each minted AOB covers. x86 / PE32 only.

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};

use super::types::ImageInput;
use super::{bitness, read_at, read_region};
use crate::pattern::Arch;

// A vtable shorter than this carries too little structure to identify uniquely (a handful of common
// base-class slots recurs across many classes); only tables at least this long are used as anchors.
const MIN_SLOTS: usize = 8;
// A run shorter than this is not even enumerated as a candidate vtable.
const MIN_RUN: usize = 4;
// Mnemonics decoded per slot to fingerprint its function. Sixteen characterises a slot without spilling
// far into the next function for short methods.
const SLOT_WINDOW: usize = 16;
// Base of the candidate-size window (the resolver widens it by a quarter of the reference length): a
// table whose slot count is within the window is aligned and scored, one wildly different in size is a
// different class and skipped before the more expensive alignment runs.
const COUNT_TOLERANCE: usize = 8;
// Instructions decoded when following a dispatch thunk (an adjustor thunk is two instructions).
const THUNK_INSTRS: usize = 2;

/// The recompile-stable identity of a virtual method: the per-slot mnemonic fingerprint of the vtable it
/// is dispatched from, the index of its slot, and whether that slot dispatches through an adjustor thunk.
pub(super) struct VtableAnchor {
    pub slot: usize,
    pub via_thunk: bool,
    pub fingerprint: Vec<Vec<u16>>,
    /// Per-slot distinctiveness weight, the inverse of how many tables share that method: a
    /// class-specific override weighs ~1, a method inherited into many classes weighs little, so the
    /// shared base backbone cannot let a sibling class masquerade as the target's own table.
    pub weights: Vec<f64>,
}

fn in_code(img: &ImageInput, abs: usize) -> bool {
    img.code_regions
        .iter()
        .any(|r| abs >= r.base && abs < r.base + r.size)
}

fn whole_image(img: &ImageInput) -> Vec<u8> {
    read_region(img.source, img.base, img.size)
}

/// Every vtable in the image: a run of at least [`MIN_RUN`] consecutive 4-aligned pointers into
/// executable code. Returns each run's start RVA and the slot target RVAs. Vtables sit in `.rdata` or,
/// in this corpus, in `.text`; scanning the whole image by pointer-into-code finds them wherever they
/// live. Every loop is bounded by the buffer length so a malformed image cannot spin.
fn vtables(img: &ImageInput, buf: &[u8]) -> Vec<(usize, Vec<usize>)> {
    let base = img.base;
    let mut out = Vec::new();
    let mut i = 0usize;
    let end = buf.len() & !3;
    while i + 4 <= end {
        let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        if in_code(img, v) {
            let start = i;
            let mut slots = Vec::new();
            while i + 4 <= end {
                let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
                if !in_code(img, v) {
                    break;
                }
                slots.push(v - base);
                i += 4;
            }
            if slots.len() >= MIN_RUN {
                out.push((start, slots));
            }
        } else {
            i += 4;
        }
    }
    out
}

/// The first `n` instruction mnemonics of the function at `rva`, the multiset fingerprint of one slot.
fn slot_mnemonics(img: &ImageInput, rva: usize, n: usize) -> Vec<u16> {
    let bytes = read_at(img.source, img.base, rva, n * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = Vec::with_capacity(n);
    while dec.can_decode() && out.len() < n {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        out.push(instr.mnemonic() as u16);
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

/// A per-slot fingerprint sorted ascending, so [`dice_sorted`] can intersect two of them by a linear
/// merge with no per-call allocation (the alignment scores every slot pair, so this is the hot path).
fn sorted(v: &[u16]) -> Vec<u16> {
    let mut s = v.to_vec();
    s.sort_unstable();
    s
}

/// Sorensen-Dice over two pre-sorted mnemonic multisets, counting repeats: `2*inter / (|a| + |b|)`.
fn dice_sorted(a: &[u16], b: &[u16]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (mut i, mut j, mut inter) = (0usize, 0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    2.0 * inter as f64 / (a.len() + b.len()) as f64
}

// Affine-gap alignment constants, integer-scaled so the dynamic program is exact and deterministic. A
// matched pair scores round((2*dice - 1) * SCALE): +SCALE for an identical slot, 0 at Dice 0.5, -SCALE
// for a disjoint pair. Opening a gap costs just past a single fully mismatched slot, so the alignment
// never gaps a pair that shares any mnemonics; extending a gap is cheap, so a contiguous block of
// inserted or removed methods is one event, not many.
const SCALE: i64 = 100;
const GAP_OPEN: i64 = -120;
const GAP_EXTEND: i64 = -28;
// A sentinel for an unreachable cell, kept far from the i64 bounds so `saturating_add` never wraps.
const NEG: i64 = i64::MIN / 4;

/// Gotoh global alignment with affine gaps and free end-gaps, over two pre-sorted slot-fingerprint
/// sequences. Free end-gaps let a block of methods prepended or appended in a newer build (the usual
/// cross-major change) align at no cost instead of dragging the agreement down; affine gaps coalesce a
/// contiguous inserted or removed block into one penalty. Returns the mapping from each reference slot
/// to its aligned candidate slot (`None` where a method has no counterpart), which lets the target slot
/// follow methods inserted or removed before it. Match quality is then scored by [`weighted_agreement`].
fn align(ref_fp: &[Vec<u16>], cand_fp: &[Vec<u16>]) -> Vec<Option<usize>> {
    let m = ref_fp.len();
    let n = cand_fp.len();
    if m == 0 || n == 0 {
        return vec![None; m];
    }
    let w = n + 1;
    let sc = |i: usize, j: usize| -> i64 {
        ((2.0 * dice_sorted(&ref_fp[i], &cand_fp[j]) - 1.0) * SCALE as f64).round() as i64
    };
    let mut mm = vec![NEG; (m + 1) * w]; // best alignment ending by pairing ref[i-1] with cand[j-1]
    let mut gx = vec![NEG; (m + 1) * w]; // ending with ref[i-1] over a gap (cand not consumed)
    let mut gy = vec![NEG; (m + 1) * w]; // ending with cand[j-1] over a gap (ref not consumed)
    let mut mp = vec![0u8; (m + 1) * w]; // mm predecessor: 0 = mm, 1 = gx, 2 = gy at (i-1, j-1)
    let mut xp = vec![0u8; (m + 1) * w]; // gx predecessor: 0 = mm, 1 = gx at (i-1, j)
    let mut yp = vec![0u8; (m + 1) * w]; // gy predecessor: 0 = mm, 2 = gy at (i, j-1)
    mm[0] = 0;
    for i in 1..=m {
        gx[i * w] = 0; // free leading gap: a reference prefix with no counterpart costs nothing
    }
    gy[1..=n].fill(0); // free leading gap: a candidate prefix with no counterpart costs nothing
    for i in 1..=m {
        for j in 1..=n {
            let (mut bp, mut bv) = (0u8, mm[(i - 1) * w + (j - 1)]);
            if gx[(i - 1) * w + (j - 1)] > bv {
                bv = gx[(i - 1) * w + (j - 1)];
                bp = 1;
            }
            if gy[(i - 1) * w + (j - 1)] > bv {
                bv = gy[(i - 1) * w + (j - 1)];
                bp = 2;
            }
            mm[i * w + j] = sc(i - 1, j - 1).saturating_add(bv);
            mp[i * w + j] = bp;

            let open = mm[(i - 1) * w + j].saturating_add(GAP_OPEN);
            let ext = gx[(i - 1) * w + j].saturating_add(GAP_EXTEND);
            (gx[i * w + j], xp[i * w + j]) = if open >= ext { (open, 0) } else { (ext, 1) };

            let open = mm[i * w + (j - 1)].saturating_add(GAP_OPEN);
            let ext = gy[i * w + (j - 1)].saturating_add(GAP_EXTEND);
            (gy[i * w + j], yp[i * w + j]) = if open >= ext { (open, 0) } else { (ext, 2) };
        }
    }
    // Free trailing gaps: the alignment may end anywhere in the last row or last column.
    let (mut bi, mut bj, mut bs, mut bm) = (0usize, 0usize, NEG, 0u8);
    for j in 0..=n {
        for (mat, v) in [(0u8, mm[m * w + j]), (1, gx[m * w + j]), (2, gy[m * w + j])] {
            if v > bs {
                (bs, bi, bj, bm) = (v, m, j, mat);
            }
        }
    }
    for i in 0..=m {
        for (mat, v) in [(0u8, mm[i * w + n]), (1, gx[i * w + n]), (2, gy[i * w + n])] {
            if v > bs {
                (bs, bi, bj, bm) = (v, i, n, mat);
            }
        }
    }

    let mut mapping = vec![None; m];
    let (mut i, mut j, mut mat) = (bi, bj, bm);
    while i > 0 && j > 0 {
        match mat {
            0 => {
                mapping[i - 1] = Some(j - 1);
                mat = mp[i * w + j];
                i -= 1;
                j -= 1;
            }
            1 => {
                mat = xp[i * w + j];
                i -= 1;
            }
            _ => {
                mat = yp[i * w + j];
                j -= 1;
            }
        }
    }
    mapping
}

/// Distinctiveness-weighted mean matched Dice of a reference table against a candidate over an alignment
/// `mapping`. A reference slot aligned to a candidate slot contributes `weight * dice`; a gapped slot
/// contributes nothing but still counts in the denominator, so a missing class-specific override (high
/// weight) sharply lowers the score while a missing shared base method (low weight) barely moves it.
/// This is what separates the target's own table from a sibling class that shares only the backbone.
fn weighted_agreement(
    ref_fp: &[Vec<u16>],
    cand_fp: &[Vec<u16>],
    mapping: &[Option<usize>],
    weights: &[f64],
) -> f64 {
    let mut num = 0.0;
    let mut den = 0.0;
    for (i, slot) in mapping.iter().enumerate() {
        let weight = weights.get(i).copied().unwrap_or(1.0);
        den += weight;
        if let Some(j) = slot {
            num += weight * dice_sorted(&ref_fp[i], &cand_fp[*j]);
        }
    }
    if den > 0.0 { num / den } else { 0.0 }
}

// An MSVC adjustor thunk's first instruction adjusts the `this` pointer by a constant before the jump.
fn is_adjustor(instr: &Instruction) -> bool {
    matches!(instr.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
        && instr.op0_kind() == OpKind::Register
        && matches!(
            instr.op1_kind(),
            OpKind::Immediate8
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate16
                | OpKind::Immediate32
        )
}

/// Resolve a slot to the real method it dispatches, following one adjustor or plain-jump thunk. A direct
/// slot is returned unchanged; a thunk (`jmp fn`, or `add ecx, imm ; jmp fn` under multiple inheritance)
/// is followed to `fn`. The boolean reports whether a thunk was traversed.
fn follow_thunk(img: &ImageInput, slot_rva: usize) -> (usize, bool) {
    let bytes = read_at(img.source, img.base, slot_rva, THUNK_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + slot_rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    if !dec.can_decode() {
        return (slot_rva, false);
    }
    dec.decode_out(&mut instr);
    if instr.is_invalid() || instr.len() == 0 {
        return (slot_rva, false);
    }
    if instr.flow_control() == FlowControl::UnconditionalBranch {
        let t = instr.near_branch_target() as usize;
        if in_code(img, t) {
            return (t - img.base, true);
        }
        return (slot_rva, false);
    }
    if is_adjustor(&instr) && dec.can_decode() {
        dec.decode_out(&mut instr);
        if !instr.is_invalid() && instr.flow_control() == FlowControl::UnconditionalBranch {
            let t = instr.near_branch_target() as usize;
            if in_code(img, t) {
                return (t - img.base, true);
            }
        }
    }
    (slot_rva, false)
}

/// Build a vtable anchor for the method whose entry is `target_entry`: find the vtable that dispatches it
/// (directly or through a thunk) and capture that table's per-slot fingerprint and the target's slot.
/// Among several tables that contain the method, the largest is chosen (most structure to match on),
/// preferring a direct slot over a thunked one. Returns `None` if no table of at least [`MIN_SLOTS`]
/// dispatches the method. x86 only.
#[must_use]
pub(super) fn make_vtable_anchor(img: &ImageInput, target_entry: usize) -> Option<VtableAnchor> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    let buf = whole_image(img);
    let vts = vtables(img, &buf);
    // How many distinct tables share each method: an inherited base method recurs across many vtables, a
    // class-specific override appears in one. This drives the per-slot distinctiveness weight below.
    let mut table_count: HashMap<usize, u32> = HashMap::new();
    for (_s, slots) in &vts {
        for rva in slots.iter().copied().collect::<HashSet<_>>() {
            *table_count.entry(rva).or_default() += 1;
        }
    }
    // (slot count, slot index, via_thunk, slots) of the best table seen so far.
    let mut chosen: Option<(usize, usize, bool, Vec<usize>)> = None;
    for (_start, slots) in &vts {
        if slots.len() < MIN_SLOTS {
            continue;
        }
        for (i, &sv) in slots.iter().enumerate() {
            let (real, via) = follow_thunk(img, sv);
            if real == target_entry {
                let better = match &chosen {
                    None => true,
                    Some((n, _, prev_via, _)) => {
                        slots.len() > *n || (slots.len() == *n && *prev_via && !via)
                    }
                };
                if better {
                    chosen = Some((slots.len(), i, via, slots.clone()));
                }
                break; // a method rarely appears twice in one table; the first slot is enough
            }
        }
    }
    let (_, slot, via_thunk, slots) = chosen?;
    let fingerprint = slots
        .iter()
        .map(|&sv| slot_mnemonics(img, sv, SLOT_WINDOW))
        .collect();
    let weights = slots
        .iter()
        .map(|sv| 1.0 / f64::from(table_count.get(sv).copied().unwrap_or(1).max(1)))
        .collect();
    Some(VtableAnchor {
        slot,
        via_thunk,
        fingerprint,
        weights,
    })
}

/// Relocate a vtable anchor into `img`: find the table whose slot fingerprints best align to the
/// anchor's (by Needleman-Wunsch, so methods inserted or removed across versions shift the match rather
/// than breaking it), then read the aligned target slot and follow any thunk to the method's address
/// here. Returns the relocated method RVA, the best table's agreement, and the runner-up's, so the
/// caller can reject an ambiguous (low-margin) match. x86 only.
#[must_use]
pub(super) fn resolve_vtable_anchor(
    img: &ImageInput,
    anchor: &VtableAnchor,
) -> Option<(usize, f64, f64)> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    let buf = whole_image(img);
    let vts = vtables(img, &buf);
    let rl = anchor.fingerprint.len();
    // Alignment absorbs inserted and removed methods, so the size window can be generous; the agreement
    // and margin gates, not this filter, are what reject an unrelated table.
    let drift = rl / 4 + COUNT_TOLERANCE;
    let ref_fp: Vec<Vec<u16>> = anchor.fingerprint.iter().map(|v| sorted(v)).collect();
    let mut best_score = 0.0f64;
    let mut second = 0.0f64;
    let mut best: Option<(Vec<usize>, Vec<Option<usize>>)> = None;
    for (_start, slots) in &vts {
        if slots.is_empty() || slots.len() + drift < rl || slots.len() > rl + drift {
            continue;
        }
        let cand_fp: Vec<Vec<u16>> = slots
            .iter()
            .map(|&sv| sorted(&slot_mnemonics(img, sv, SLOT_WINDOW)))
            .collect();
        let mapping = align(&ref_fp, &cand_fp);
        let score = weighted_agreement(&ref_fp, &cand_fp, &mapping, &anchor.weights);
        if score > best_score {
            second = best_score;
            best_score = score;
            best = Some((slots.clone(), mapping));
        } else if score > second {
            second = score;
        }
    }
    let (slots, mapping) = best?;
    // The target method must have a counterpart in the matched table (it was not removed in this build).
    let cand_slot = mapping.get(anchor.slot).copied().flatten()?;
    let &slot_rva = slots.get(cand_slot)?;
    let (real, _) = follow_thunk(img, slot_rva);
    Some((real, best_score, second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

    const BASE: usize = 0x40_0000;

    // An x86 image whose code region holds ten tiny functions and whose data tail holds a vtable of
    // pointers to them. Functions use distinct one-byte instructions so per-slot fingerprints differ.
    fn synthetic() -> (Vec<u8>, Vec<usize>, usize) {
        let mut buf = vec![0u8; 0x400];
        let mut fn_rvas = Vec::new();
        for j in 0..10usize {
            let rva = 0x100 + j * 0x20;
            fn_rvas.push(rva);
            let opcode = 0x40 + (j as u8 % 8); // inc/dec eax..edi: a distinct one-byte instruction
            for k in 0..(j + 2) {
                buf[rva + k] = opcode;
            }
            buf[rva + j + 2] = 0xC3; // ret
        }
        // The vtable: ten absolute pointers to the functions, then a zero terminator.
        let table = 0x300usize;
        for (k, &rva) in fn_rvas.iter().enumerate() {
            let abs = (BASE + rva) as u32;
            buf[table + k * 4..table + k * 4 + 4].copy_from_slice(&abs.to_le_bytes());
        }
        (buf, fn_rvas, table)
    }

    fn image<'a>(src: &'a BufferSource, code: Region) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base: BASE,
            size: 0x400,
            code_regions: vec![code],
            regions: vec![Region {
                base: BASE,
                size: 0x400,
            }],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn vtables_enumerates_a_run_of_code_pointers() {
        let (buf, fn_rvas, table) = synthetic();
        let src = BufferSource::new(BASE, buf.clone());
        // Code region covers only the functions, so the table's bytes are data that point into it.
        let img = image(
            &src,
            Region {
                base: BASE + 0x100,
                size: 0x200,
            },
        );
        let found = vtables(&img, &buf);
        let vt = found
            .iter()
            .find(|(start, _)| *start == table)
            .expect("the function-pointer table is enumerated as a vtable");
        assert_eq!(vt.1, fn_rvas, "all ten slots resolve to the function RVAs");
    }

    #[test]
    fn make_and_resolve_round_trip_on_one_image() {
        let (buf, fn_rvas, _) = synthetic();
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE + 0x100,
                size: 0x200,
            },
        );
        let target = fn_rvas[3];
        let anchor = make_vtable_anchor(&img, target).expect("the method is a vtable slot");
        assert_eq!(anchor.slot, 3);
        assert!(!anchor.via_thunk);
        let (rva, agreement, _runner) =
            resolve_vtable_anchor(&img, &anchor).expect("the table relocates onto itself");
        assert_eq!(rva, target, "the slot reads back to the same method");
        assert!(agreement > 0.99, "an image matches itself at agreement 1.0");
    }

    #[test]
    fn follow_thunk_follows_a_plain_jump() {
        // jmp rel32 at rva 0x10 to a `ret` at rva 0x40; whole image is code.
        let mut buf = vec![0u8; 0x100];
        buf[0x40] = 0xC3;
        let rel = 0x40i32 - (0x10 + 5);
        buf[0x10] = 0xE9;
        buf[0x11..0x15].copy_from_slice(&rel.to_le_bytes());
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x40, true));
    }

    #[test]
    fn follow_thunk_follows_an_adjustor_thunk() {
        // add ecx, 8 ; jmp rel32 -> ret at 0x40.
        let mut buf = vec![0u8; 0x100];
        buf[0x40] = 0xC3;
        buf[0x10] = 0x83; // add ecx, 8
        buf[0x11] = 0xC1;
        buf[0x12] = 0x08;
        let rel = 0x40i32 - (0x13 + 5);
        buf[0x13] = 0xE9; // jmp rel32
        buf[0x14..0x18].copy_from_slice(&rel.to_le_bytes());
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x40, true));
    }

    #[test]
    fn follow_thunk_leaves_a_direct_function_unchanged() {
        // A real function entry (not a thunk) is returned as-is.
        let mut buf = vec![0u8; 0x100];
        buf[0x10] = 0x55; // push ebp
        buf[0x11] = 0x8B; // mov ebp, esp
        buf[0x12] = 0xEC;
        let src = BufferSource::new(BASE, buf);
        let img = image(
            &src,
            Region {
                base: BASE,
                size: 0x100,
            },
        );
        assert_eq!(follow_thunk(&img, 0x10), (0x10, false));
    }

    #[test]
    fn align_absorbs_a_front_insertion() {
        // The candidate prepends two methods with no counterpart in the reference; free end-gaps must
        // let the shared tail still align 1:1 at full agreement (the cross-major front-block case).
        let (a, b, c, d) = (vec![1u16, 2], vec![3u16, 4], vec![5u16, 6], vec![7u16, 8]);
        let ref_fp = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let cand_fp = vec![vec![20u16, 21], vec![22u16, 23], a, b, c, d];
        let mapping = align(&ref_fp, &cand_fp);
        assert_eq!(mapping, vec![Some(2), Some(3), Some(4), Some(5)]);
        let agree = weighted_agreement(&ref_fp, &cand_fp, &mapping, &[1.0; 4]);
        assert!(agree > 0.99, "shared tail must align fully, got {agree}");
    }

    #[test]
    fn align_absorbs_a_middle_block_insertion() {
        // Two methods inserted between B and C; affine gaps coalesce them and the rest aligns 1:1.
        let (a, b, c, d) = (vec![1u16, 2], vec![3u16, 4], vec![5u16, 6], vec![7u16, 8]);
        let ref_fp = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let cand_fp = vec![a, b, vec![30u16, 31], vec![32u16, 33], c, d];
        let mapping = align(&ref_fp, &cand_fp);
        assert_eq!(mapping, vec![Some(0), Some(1), Some(4), Some(5)]);
    }

    // Build an ImageInput over a real on-disk client. Returns None when the corpus is absent so the
    // ignored tests below can skip cleanly off the build machine.
    #[cfg(test)]
    fn open_real<'a>(img: &'a crate::fileimage::FileImage, label: &str) -> ImageInput<'a> {
        let pack = img.pack_report();
        ImageInput {
            label: label.to_string(),
            source: img,
            base: img.base(),
            size: img.size(),
            code_regions: img.code_regions(),
            regions: img.regions(),
            import: img.import_range(),
            arch: img.arch(),
            code_hash: img.code_hash(),
            packed: pack.likely_packed,
            pack_reasons: pack.reasons,
            reloc: None,
        }
    }

    // The headline claim, through the production resolver (run with `--ignored`): the 101-slot vtable at
    // v84 .text RVA 0x78F16C maps onto its counterpart in a real recompile (v88) and an adjacent build
    // (v83) with a high, unambiguous per-slot agreement, so a virtual method in it relocates by table
    // structure alone. Measured previously at v88 0.949 (margin 0.415) and v83 1.000 (margin 0.46).
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn vtable_matching_relocates_the_real_gms_table_across_builds() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let paths = [
            dir.join("GMS_v83.1_U_DEVM.exe"),
            dir.join("GMS_v84.1_U_DEVM.exe"),
            dir.join("GMS_v88.1_U_DEVM.exe"),
        ];
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let v83i = FileImage::open(&paths[0]).expect("open v83");
        let v84i = FileImage::open(&paths[1]).expect("open v84");
        let v88i = FileImage::open(&paths[2]).expect("open v88");
        let v83 = open_real(&v83i, "v83");
        let v84 = open_real(&v84i, "v84");
        let v88 = open_real(&v88i, "v88");

        // Locate the run that contains the known table start through the production enumerator.
        let buf84 = whole_image(&v84);
        let vts84 = vtables(&v84, &buf84);
        let (start, slots) = vts84
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("the target vtable is enumerated in v84");
        eprintln!("v84 target vtable @0x{start:X}: {} slots", slots.len());
        assert!(
            (90..=112).contains(&slots.len()),
            "target table slot count {} outside the expected window",
            slots.len()
        );

        // A direct (non-thunk) slot's method, anchored through the production path (weights and all).
        let slot_idx = slots
            .iter()
            .position(|&sv| !follow_thunk(&v84, sv).1)
            .expect("a direct slot in the table");
        let anchor =
            make_vtable_anchor(&v84, slots[slot_idx]).expect("anchor the clean slot method");

        // Self-match on v84: agreement 1.0, reads the same method back.
        let (r84, a84, run84) = resolve_vtable_anchor(&v84, &anchor).expect("v84 self-match");
        eprintln!(
            "v84 self: rva 0x{r84:X} agreement {a84:.3} margin {:.3}",
            a84 - run84
        );
        assert_eq!(r84, slots[slot_idx], "self-resolve reads the same slot");
        assert!(a84 > 0.99, "an image matches itself near 1.0");

        // v84 -> v88 (a real recompile) and v84 -> v83: the table maps with a clear margin. Bounds are
        // the production gates (VT_MIN_AGREEMENT 0.72 / VT_MIN_MARGIN 0.10); the actual values printed
        // here are far higher.
        for (img, name) in [(&v88, "v88"), (&v83, "v83")] {
            let (rva, agree, runner) =
                resolve_vtable_anchor(img, &anchor).unwrap_or_else(|| panic!("{name} match"));
            eprintln!(
                "{name}: rva 0x{rva:X} agreement {agree:.3} margin {:.3}",
                agree - runner
            );
            assert!(
                in_code(img, img.base + rva),
                "the relocated {name} method is in executable code"
            );
            assert!(agree >= 0.72, "{name} agreement {agree:.3} below the gate");
            assert!(
                agree - runner >= 0.10,
                "{name} margin {:.3} below the gate (ambiguous match)",
                agree - runner
            );
        }
    }

    // How far the vtable anchor actually carries (run with `--ignored`): anchor a clean direct method in
    // the v84 @0x78F16C table and resolve it across the full six-build span from the GUI screenshot,
    // including the major-version jumps to v95.x where the class layout may shift slots.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn clean_virtual_method_relocates_across_six_builds() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let names = [
            "GMS_v83.1_U_DEVM.exe",
            "GMS_v84.1_U_DEVM.exe",
            "GMS_v88.1_U_DEVM.exe",
            "GMS_v91.1_U_DEVM.exe",
            "GMS_v95.1_U_DEVM.exe",
            "GMS_v95.5_U_DEVM.exe",
        ];
        let paths: Vec<_> = names.iter().map(|n| dir.join(n)).collect();
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let imgs: Vec<FileImage> = paths.iter().map(|p| FileImage::open(p).unwrap()).collect();
        let labels = ["v83", "v84", "v88", "v91", "v95.1", "v95.5"];
        let inputs: Vec<ImageInput> = labels
            .iter()
            .zip(&imgs)
            .map(|(l, i)| open_real(i, l))
            .collect();

        let v84 = &inputs[1];
        let buf = whole_image(v84);
        let vts = vtables(v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("target table");
        let slot_idx = slots
            .iter()
            .position(|&sv| !follow_thunk(v84, sv).1)
            .expect("a direct slot");
        let anchor = make_vtable_anchor(v84, slots[slot_idx]).expect("anchor the method");
        eprintln!(
            "anchoring clean method 0x{:X} (slot {} of {}):",
            slots[slot_idx],
            anchor.slot,
            anchor.fingerprint.len()
        );
        for inp in &inputs {
            match resolve_vtable_anchor(inp, &anchor) {
                Some((rva, a, r)) if a >= 0.72 && a - r >= 0.10 => eprintln!(
                    "  {:>5}: 0x{rva:X}  agreement {a:.3} margin {:.3}  PIN",
                    inp.label,
                    a - r
                ),
                Some((rva, a, r)) => eprintln!(
                    "  {:>5}: 0x{rva:X}  agreement {a:.3} margin {:.3}  (below gate -> declines)",
                    inp.label,
                    a - r
                ),
                None => eprintln!("  {:>5}: no table match", inp.label),
            }
        }
    }

    // Validate the chaining hypothesis (run with `--ignored`): is stepwise relocation through adjacent
    // builds (v84->v88->v91->v95.1->v95.5, re-anchoring at each hop) more robust than a single direct
    // jump (v84->v95.x)? Prints both so the difference is measured, not assumed.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn chained_relocation_vs_direct_across_majors() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let dir = Path::new(r"X:\Client_Unpacked");
        let names = [
            "GMS_v83.1_U_DEVM.exe",
            "GMS_v84.1_U_DEVM.exe",
            "GMS_v88.1_U_DEVM.exe",
            "GMS_v91.1_U_DEVM.exe",
            "GMS_v95.1_U_DEVM.exe",
            "GMS_v95.5_U_DEVM.exe",
        ];
        let paths: Vec<_> = names.iter().map(|n| dir.join(n)).collect();
        if paths.iter().any(|p| !p.exists()) {
            eprintln!("real GMS clients not present; skipping");
            return;
        }
        let imgs: Vec<FileImage> = paths.iter().map(|p| FileImage::open(p).unwrap()).collect();
        let labels = ["v83", "v84", "v88", "v91", "v95.1", "v95.5"];
        let inputs: Vec<ImageInput> = labels
            .iter()
            .zip(&imgs)
            .map(|(l, i)| open_real(i, l))
            .collect();

        // Anchor a clean method in v84 (index 1): slot 0 of the 0x78F16C table.
        let v84 = &inputs[1];
        let buf = whole_image(v84);
        let vts = vtables(v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("target table");
        let slot0 = slots[0];

        eprintln!("DIRECT v84 -> each build (one big jump):");
        let v84_anchor = make_vtable_anchor(v84, slot0).expect("anchor in v84");
        for (i, inp) in inputs.iter().enumerate() {
            if let Some((rva, a, r)) = resolve_vtable_anchor(inp, &v84_anchor) {
                eprintln!(
                    "  v84 -> {:>5}: 0x{rva:X}  agree {a:.3} margin {:.3} {}",
                    labels[i],
                    a - r,
                    if a >= 0.72 && a - r >= 0.10 {
                        "PIN"
                    } else {
                        "decline"
                    }
                );
            }
        }

        eprintln!("CHAINED from v84, re-anchoring each hop (1->2->3->4->5):");
        // Walk forward through indices 2..=5, re-anchoring in the located build each hop.
        let mut cur_idx = 1usize;
        let mut cur_rva = slot0;
        for next in 2..inputs.len() {
            let anchor = match make_vtable_anchor(&inputs[cur_idx], cur_rva) {
                Some(a) => a,
                None => {
                    eprintln!("  re-anchor in {} FAILED at 0x{cur_rva:X}", labels[cur_idx]);
                    break;
                }
            };
            match resolve_vtable_anchor(&inputs[next], &anchor) {
                Some((rva, a, r)) => {
                    eprintln!(
                        "  {:>5} -> {:>5}: 0x{rva:X}  agree {a:.3} margin {:.3} {}",
                        labels[cur_idx],
                        labels[next],
                        a - r,
                        if a >= 0.72 && a - r >= 0.10 {
                            "PIN"
                        } else {
                            "decline"
                        }
                    );
                    cur_idx = next;
                    cur_rva = rva;
                }
                None => {
                    eprintln!("  {} -> {}: no match", labels[cur_idx], labels[next]);
                    break;
                }
            }
        }
        eprintln!(
            "chained final: {} at 0x{cur_rva:X} (direct v84->v95.5 was 0.630, below gate)",
            labels[cur_idx]
        );
    }

    // `make_vtable_anchor` on real data (run with `--ignored`): a virtual method in the target table is
    // anchored to its own table and reads back to itself on a self-resolve.
    #[test]
    #[ignore = "needs the real GMS clients in X:\\Client_Unpacked; run with --ignored"]
    fn make_vtable_anchor_pins_a_real_virtual_method() {
        use crate::fileimage::FileImage;
        use std::path::Path;

        let path = Path::new(r"X:\Client_Unpacked").join("GMS_v84.1_U_DEVM.exe");
        if !path.exists() {
            eprintln!("real GMS client not present; skipping");
            return;
        }
        let v84i = FileImage::open(&path).expect("open v84");
        let v84 = open_real(&v84i, "v84");

        let buf = whole_image(&v84);
        let vts = vtables(&v84, &buf);
        let (_, slots) = vts
            .iter()
            .find(|(s, sl)| *s <= 0x78F16C && 0x78F16C < *s + sl.len() * 4)
            .expect("the target vtable is enumerated");

        // The first direct slot whose method anchors back to a table of the same size (i.e. this one,
        // not a larger table that merely shares a base-class method); bounded so the scan stays cheap.
        let mut pinned = false;
        for &sv in slots
            .iter()
            .filter(|&&sv| !follow_thunk(&v84, sv).1)
            .take(24)
        {
            let Some(anchor) = make_vtable_anchor(&v84, sv) else {
                continue;
            };
            if anchor.fingerprint.len() != slots.len() {
                continue; // method also lives in a larger table; not a clean single-table method
            }
            let (rva, agree, _) = resolve_vtable_anchor(&v84, &anchor).expect("self-resolve");
            assert_eq!(rva, sv, "the anchored method reads back to itself");
            assert!(agree > 0.99);
            eprintln!("anchored real method 0x{sv:X} at slot {}", anchor.slot);
            pinned = true;
            break;
        }
        assert!(
            pinned,
            "no clean single-table virtual method found to anchor"
        );
    }
}
