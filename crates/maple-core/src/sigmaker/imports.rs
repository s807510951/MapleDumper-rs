//! Import-set anchored relocation: find the same function across builds by the distinctive set of
//! imported APIs it calls.
//!
//! Imported API names are recompile-stable (they are fixed by the DLLs the program links against), so
//! a function that calls a distinctive set of them, for example the twelve `ws2_32` socket APIs of the
//! network layer or the `advapi32` token-privilege trio, is identifiable in any build by that set even
//! when its bytes, mnemonic stream, and encoding have all been rewritten by a recompile. This is the
//! complement of [`super::identity`]'s string anchor: where that pins a function by a read-only string
//! it references, this pins it by the IAT slots it calls through. Measured on the real GMS v84 to v88
//! recompile, ~100 functions have an import set unique in both builds and relocate 1:1, the great
//! majority at mnemonic similarity 1.0.
//!
//! The anchor emits only when the import set pins exactly one function in every required build (so an
//! ambiguous or absent set declines rather than guess), and the relocated functions are checked for
//! cross-build consistency. x86 / PE32 only.

use std::collections::{BTreeSet, HashMap};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

use super::types::ImageInput;
use super::{bitness, read_at, read_region};
use crate::pattern::Arch;

/// The recompile-stable identity of a function as the set of imported API names it calls directly.
#[derive(Clone, Debug)]
pub(super) struct ImportAnchor {
    pub names: Vec<String>,
}

// Below this many distinct imports a set is not distinctive enough to pin one function: a lone
// `GetLastError` recurs in thousands of functions, so two or more is the floor for an anchor.
const MIN_IMPORTS: usize = 2;
// Instruction cap when scanning a function for its import calls (bounds untrusted input).
const SCAN_INSTRS: usize = 400;

fn rd32(img: &ImageInput, abs: usize) -> Option<u32> {
    let rva = abs.checked_sub(img.base)?;
    let b = read_at(img.source, img.base, rva, 4);
    (b.len() == 4).then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn cstr(img: &ImageInput, abs: usize) -> String {
    let Some(rva) = abs.checked_sub(img.base) else {
        return String::new();
    };
    read_at(img.source, img.base, rva, 128)
        .iter()
        .copied()
        .take_while(|&b| b != 0 && (0x20..=0x7E).contains(&b))
        .map(char::from)
        .collect()
}

/// Parse the PE32 import directory into a map of IAT slot VA to `"dll!func"`. Every loop is bounded so
/// a malformed directory in an untrusted image cannot spin or read out of range.
pub(super) fn import_map(img: &ImageInput) -> HashMap<usize, String> {
    let mut out = HashMap::new();
    if !matches!(img.arch, Arch::X86) {
        return out;
    }
    let Some((start, end)) = img.import else {
        return out;
    };
    let mut desc = start;
    let mut guard = 0;
    while desc + 20 <= end && guard < 8192 {
        guard += 1;
        let orig = rd32(img, desc).unwrap_or(0);
        let name_rva = rd32(img, desc + 0x0C).unwrap_or(0);
        let first = rd32(img, desc + 0x10).unwrap_or(0);
        if orig == 0 && first == 0 {
            break;
        }
        let dll = cstr(img, img.base + name_rva as usize);
        let int = if orig != 0 { orig } else { first };
        let mut i = 0usize;
        while i < 8192 {
            let Some(t) = rd32(img, img.base + int as usize + i * 4) else {
                break;
            };
            if t == 0 {
                break;
            }
            let slot = img.base + first as usize + i * 4;
            let name = if t & 0x8000_0000 != 0 {
                format!("{dll}!#{}", t & 0xFFFF)
            } else {
                format!("{dll}!{}", cstr(img, img.base + t as usize + 2))
            };
            out.insert(slot, name);
            i += 1;
        }
        desc += 20;
    }
    out
}

fn in_code(img: &ImageInput, abs: usize) -> bool {
    img.code_regions
        .iter()
        .any(|r| (r.base..r.base + r.size).contains(&abs))
}

/// The set of imported API names a function at `rva` calls directly (`call`/`jmp [IAT slot]`), decoded
/// to its first `ret` or [`SCAN_INSTRS`].
pub(super) fn import_set(
    img: &ImageInput,
    map: &HashMap<usize, String>,
    rva: usize,
) -> BTreeSet<String> {
    let bytes = read_at(img.source, img.base, rva, SCAN_INSTRS * 8);
    let mut dec = Decoder::with_ip(
        bitness(img.arch),
        &bytes,
        (img.base + rva) as u64,
        DecoderOptions::NONE,
    );
    let mut instr = Instruction::default();
    let mut out = BTreeSet::new();
    let mut n = 0;
    while dec.can_decode() && n < SCAN_INSTRS {
        dec.decode_out(&mut instr);
        if instr.is_invalid() || instr.len() == 0 {
            break;
        }
        n += 1;
        if matches!(
            instr.flow_control(),
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        ) {
            for i in 0..instr.op_count() {
                if instr.op_kind(i) == OpKind::Memory
                    && instr.memory_base() == Register::None
                    && instr.memory_index() == Register::None
                {
                    let slot = instr.memory_displacement64() as usize;
                    if let Some(name) = map.get(&slot) {
                        out.insert(name.clone());
                    }
                }
            }
        }
        if instr.flow_control() == FlowControl::Return {
            break;
        }
    }
    out
}

// Every E8 rel32 call target in the image's code: a clean set of real function entries to resolve
// against (a recompiled function that calls distinctive imports is itself called somewhere).
fn function_entries(img: &ImageInput) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for region in &img.code_regions {
        let bytes = read_region(img.source, region.base, region.size);
        for (i, w) in bytes.windows(5).enumerate() {
            if w[0] == 0xE8 {
                let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as i64;
                let t = (region.base + i + 5) as i64 + rel;
                if t > 0 && in_code(img, t as usize) {
                    set.insert(t as usize - img.base);
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Build an import anchor for the function at `rva`: the set of imports it calls directly, if it is
/// distinctive enough ([`MIN_IMPORTS`]). Uniqueness is validated at resolve time. x86 only.
#[must_use]
pub(super) fn make_import_anchor(img: &ImageInput, rva: usize) -> Option<ImportAnchor> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    let map = import_map(img);
    let set = import_set(img, &map, rva);
    (set.len() >= MIN_IMPORTS).then(|| ImportAnchor {
        names: set.into_iter().collect(),
    })
}

/// Resolve an import anchor to the single function in `img` whose direct import set equals it. Returns
/// `None` if no function matches or more than one does (an ambiguous anchor declines rather than guess).
#[must_use]
pub(super) fn resolve_import_anchor(img: &ImageInput, anchor: &ImportAnchor) -> Option<usize> {
    if !matches!(img.arch, Arch::X86) {
        return None;
    }
    let map = import_map(img);
    let want: BTreeSet<&str> = anchor.names.iter().map(String::as_str).collect();
    let mut found = None;
    for rva in function_entries(img) {
        let set = import_set(img, &map, rva);
        if set.len() == want.len() && set.iter().map(String::as_str).eq(want.iter().copied()) {
            if found.is_some() {
                return None; // not unique
            }
            found = Some(rva);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{BufferSource, Region};

    fn img<'a>(src: &'a BufferSource, base: usize, size: usize) -> ImageInput<'a> {
        ImageInput {
            label: "t".into(),
            source: src,
            base,
            size,
            code_regions: vec![Region { base, size }],
            regions: vec![Region { base, size }],
            import: None,
            arch: Arch::X86,
            code_hash: 0,
            packed: false,
            pack_reasons: Vec::new(),
            reloc: None,
        }
    }

    #[test]
    fn import_set_collects_indirect_call_targets() {
        // call [0x2000] ; call [0x2004] ; ret, with a map naming those two IAT slots.
        let code = vec![
            0xFF, 0x15, 0x00, 0x20, 0x00, 0x00, // call [0x2000]
            0xFF, 0x15, 0x04, 0x20, 0x00, 0x00, // call [0x2004]
            0xC3,
        ];
        let src = BufferSource::new(0x1000, code);
        let image = img(&src, 0x1000, 0x20);
        let mut map = HashMap::new();
        map.insert(0x2000usize, "ws2_32.dll!socket".to_string());
        map.insert(0x2004usize, "ws2_32.dll!closesocket".to_string());
        let set = import_set(&image, &map, 0);
        assert_eq!(set.len(), 2);
        assert!(set.contains("ws2_32.dll!socket"));
        assert!(set.contains("ws2_32.dll!closesocket"));
    }

    #[test]
    fn a_lone_import_is_below_the_anchor_floor() {
        // One import is not distinctive: make_import_anchor must decline (MIN_IMPORTS).
        let code = vec![0xFF, 0x15, 0x00, 0x20, 0x00, 0x00, 0xC3]; // call [0x2000] ; ret
        let src = BufferSource::new(0x1000, code);
        let image = img(&src, 0x1000, 0x20);
        let map = HashMap::new(); // no names -> empty set
        assert!(import_set(&image, &map, 0).is_empty());
        assert!(make_import_anchor(&image, 0).is_none());
    }
}
