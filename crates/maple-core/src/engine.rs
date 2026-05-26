use crate::memory::{MemorySource, Region};
use crate::output::Finding;
use crate::pattern::{Arch, Pattern};
use crate::resolver::{self, Kind};
use crate::scanner::{self, CompiledPattern};
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Found,
    Unresolved,
    NotFound,
}

impl Status {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Status::Found => "found",
            Status::Unresolved => "unresolved",
            Status::NotFound => "not found",
        }
    }
}

pub struct PatternRow {
    pub name: String,
    pub category: String,
    pub pattern: String,
    pub value: Option<u64>,
    pub is_offset: bool,
    pub matches: usize,
    pub status: Status,
    pub note: String,
}

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub rows: Vec<PatternRow>,
    pub found: Vec<String>,
    pub matched_unresolved: Vec<String>,
    pub not_found: Vec<String>,
    pub total_matches: usize,
}

struct Hit {
    pattern_idx: usize,
    addr: usize,
    value: Option<u64>,
    is_offset: bool,
}

fn rva(addr: usize, base: usize) -> u64 {
    addr.wrapping_sub(base) as u64
}

// Extra bytes read past a chunk's accept window so a pattern starting near the end still
// matches in full and the resolver has enough trailing bytes to decode.
const RESOLVE_MARGIN: usize = 24;
// Accept-window size per parallel work unit; large regions are split into this many bytes.
const SCAN_CHUNK: usize = 1 << 22;

#[allow(clippy::uninit_vec)]
fn read_range<S: MemorySource>(source: &S, base: usize, len: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    // SAFETY: read_into only writes into the buffer via the OS and never reads it; the length
    // is set to the bytes actually written, so no uninitialized byte is ever exposed.
    let read = {
        let spare = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr(), len) };
        source.read_into(base, spare).unwrap_or(0)
    };
    unsafe { buf.set_len(read) };
    buf
}

// One streamed block: (base address, accept-window length, buffer of accept+overlap bytes).
// A match is attributed to the single block whose accept window holds its start, so a pattern
// straddling a block boundary is found exactly once.
type Block = (usize, usize, Vec<u8>);

fn resolve<S: MemorySource>(
    kind: Kind,
    source: &S,
    module_base: usize,
    addr: usize,
    bytes: &[u8],
    arch: Arch,
) -> (Option<u64>, bool) {
    match kind {
        Kind::Direct => (Some(rva(addr, module_base)), false),
        Kind::Pointer => (
            resolver::extract_pointer(bytes, addr, arch).map(|t| rva(t, module_base)),
            false,
        ),
        Kind::Offset => (
            resolver::extract_offset(bytes, 4, arch).map(u64::from),
            true,
        ),
        Kind::Header => (resolver::extract_immediate(bytes, 4).map(u64::from), true),
        Kind::Call => (
            resolver::resolve_call(source, addr, bytes).map(|t| rva(t, module_base)),
            false,
        ),
    }
}

pub fn scan<S>(
    source: &S,
    module_base: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    scan_chunked(source, module_base, regions, patterns, arch, SCAN_CHUNK)
}

fn scan_chunked<S>(
    source: &S,
    module_base: usize,
    regions: &[Region],
    patterns: &[Pattern],
    arch: Arch,
    chunk: usize,
) -> ScanResult
where
    S: MemorySource + Sync,
{
    let compiled: Vec<(Kind, Option<CompiledPattern>)> = patterns
        .iter()
        .map(|p| {
            let (kind, _) = Kind::classify(&p.name);
            (kind, CompiledPattern::new(&p.signature))
        })
        .collect();

    let max_len = compiled
        .iter()
        .filter_map(|(_, c)| c.as_ref().map(CompiledPattern::len))
        .max()
        .unwrap_or(1);
    let overlap = max_len.max(RESOLVE_MARGIN);
    let block = chunk.max(1);

    // A single reader streams large blocks across the process boundary - one read at a time, so
    // the kernel never serializes competing reads - while the rayon pool scans already-read
    // blocks in parallel. Read and scan overlap, so the scan hides under the read and the wall
    // clock approaches the raw cross-process read time.
    let hits: Vec<Hit> = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Block>(8);
        scope.spawn(move || {
            for region in regions {
                let mut off = 0;
                while off < region.size {
                    let accept = block.min(region.size - off);
                    let read_len = (accept + overlap).min(region.size - off);
                    let buf = read_range(source, region.base + off, read_len);
                    if tx.send((region.base + off, accept, buf)).is_err() {
                        return;
                    }
                    off += accept;
                }
            }
        });
        rx.into_iter()
            .par_bridge()
            .flat_map_iter(|(base, accept_len, buf)| {
                let mut local = Vec::new();
                for (idx, (kind, compiled)) in compiled.iter().enumerate() {
                    let Some(cp) = compiled else { continue };
                    if buf.len() < cp.len() {
                        continue;
                    }
                    for off in scanner::find_all(&buf, cp) {
                        if off >= accept_len {
                            continue;
                        }
                        let addr = base + off;
                        let (value, is_offset) =
                            resolve(*kind, source, module_base, addr, &buf[off..], arch);
                        local.push(Hit {
                            pattern_idx: idx,
                            addr,
                            value,
                            is_offset,
                        });
                    }
                }
                local
            })
            .collect()
    });

    let total_matches = hits.len();
    let mut by_pattern: Vec<Vec<&Hit>> = vec![Vec::new(); patterns.len()];
    for hit in &hits {
        by_pattern[hit.pattern_idx].push(hit);
    }

    let mut findings = Vec::new();
    let mut rows = Vec::new();
    let mut found = Vec::new();
    let mut matched_unresolved = Vec::new();
    let mut not_found = Vec::new();

    for (idx, pattern) in patterns.iter().enumerate() {
        let (_, base) = Kind::classify(&pattern.name);
        let category = pattern
            .category
            .clone()
            .unwrap_or_else(|| crate::categorizer::builtin_category(base).to_string());
        let aob = pattern.signature.to_aob();
        let note = pattern.note.clone().unwrap_or_default();
        let group = &mut by_pattern[idx];
        let match_count = group.len();

        if group.is_empty() {
            not_found.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: 0,
                status: Status::NotFound,
                note,
            });
            continue;
        }

        group.sort_by_key(|h| h.addr);
        if let Some((value, is_offset)) =
            group.iter().find_map(|h| h.value.map(|v| (v, h.is_offset)))
        {
            findings.push(Finding {
                name: base.to_string(),
                category: category.clone(),
                value,
                is_offset,
            });
            found.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: Some(value),
                is_offset,
                matches: match_count,
                status: Status::Found,
                note,
            });
        } else {
            matched_unresolved.push(pattern.name.clone());
            rows.push(PatternRow {
                name: base.to_string(),
                category,
                pattern: aob,
                value: None,
                is_offset: false,
                matches: match_count,
                status: Status::Unresolved,
                note,
            });
        }
    }

    ScanResult {
        findings,
        rows,
        found,
        matched_unresolved,
        not_found,
        total_matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::BufferSource;
    use crate::pattern::Arch;
    use crate::pattern::parse_patterns;

    #[test]
    fn scans_and_resolves_against_buffer() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 64];
        data[0x10..0x14].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        data[0x20..0x27].copy_from_slice(&[0x48, 0x8D, 0x0D, 0x09, 0x00, 0x00, 0x00]);
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 64 }];
        let patterns = parse_patterns("Foo = DE AD BE EF\nBar_PTR = 48 8D 0D ? ? ? ?", Arch::X64);

        let result = scan(&source, base, &regions, &patterns, Arch::X64);

        let foo = result.findings.iter().find(|f| f.name == "Foo").unwrap();
        assert_eq!(foo.value, 0x10);
        assert!(!foo.is_offset);
        let bar = result.findings.iter().find(|f| f.name == "Bar").unwrap();
        assert_eq!(bar.value, 0x30);
        assert_eq!(result.found.len(), 2);
        assert!(result.not_found.is_empty());
        assert_eq!(result.rows.len(), 2);
        assert!(result.rows.iter().all(|r| r.status == Status::Found));
    }

    #[test]
    fn reports_not_found_and_unresolved() {
        let base = 0x2000usize;
        let data = vec![0u8; 32];
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 32 }];
        let patterns = parse_patterns("Missing = 11 22 33 44", Arch::X64);

        let result = scan(&source, base, &regions, &patterns, Arch::X64);
        assert_eq!(result.not_found, vec!["Missing"]);
        assert!(result.findings.is_empty());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].status, Status::NotFound);
    }

    #[test]
    fn chunked_scan_finds_boundary_straddling_matches_once() {
        let base = 0x1000usize;
        let mut data = vec![0u8; 200];
        let sig = [0xDE, 0xAD, 0xBE, 0xEF, 0x11];
        // starts landing before, on, across, and in the overlap of 16-byte chunk boundaries
        let starts = [3usize, 33, 48, 64, 100, 190];
        for &s in &starts {
            data[s..s + sig.len()].copy_from_slice(&sig);
        }
        let source = BufferSource::new(base, data);
        let regions = [Region { base, size: 200 }];
        let patterns = parse_patterns("Foo = DE AD BE EF 11", Arch::X64);

        // a deliberately tiny chunk forces many boundaries; each match must appear exactly once
        let result = scan_chunked(&source, base, &regions, &patterns, Arch::X64, 16);
        assert_eq!(result.total_matches, starts.len());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].matches, starts.len());
        assert_eq!(result.rows[0].status, Status::Found);
    }
}
