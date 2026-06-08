# Cross-version function relocation: a layered anchor stack with per-version AOB ranges

## The problem

A byte AOB (array-of-bytes signature) identifies a function by its exact bytes. Every MapleStory client patch recompiles the binary, which moves and rewrites those bytes, so a byte signature that matches one build rarely matches the next. Measured on real unpacked clients, an arbitrary function resolves uniquely across a same-lane build set only ~0-2% of the time by byte signature. A signature tool that only emits byte AOBs is therefore broken the moment the client updates.

This PR makes the Signature Maker **relocate a function across client versions by handles that survive a recompile**, and emit a **fresh, validated byte AOB per build** (grouped into the contiguous version ranges each AOB covers). It is fully automated end to end: load any reference function and any set of client versions, and the engine pins the function in every build it can reach and reports exactly where the old bytes break and which freshly minted pattern takes over.

Nothing is hardcoded to a particular function or version set; the whole pipeline is parameterized by the loaded clients and target.

## The anchor stack

`generate()` tries, in descending order of strength, and stops at the first that confidently pins the function. Each relocated build is handed a freshly minted, operand-masked per-build AOB.

```
byte AOB  ->  string  ->  import  ->  caller  ->  vtable  ->  encoding  ->  fingerprint  ->  shortlist
```

1. **Byte AOB (tier 0).** A single cross-build byte pattern that already matches every build is directly re-scannable and needs no relocation.
2. **String anchor.** A read-only string the function references (e.g. `UI/UIWindow.img/AranSkillGuide/%`) is build-invariant, so it pins the function in any build regardless of byte churn. Cross-version survival measured at 71-100% vs 0-2% for byte signatures.
3. **Import anchor.** The distinctive set of imported APIs a function calls (e.g. the twelve `ws2_32` socket APIs) is fixed by the DLLs the program links and survives a recompile.
4. **Caller anchor (new).** For a function with no handle of its own: anchor a *caller* that references a stable string, then re-find the target as the caller's callee whose identity matches the reference. Matching by identity, not call index, survives the call being reordered.
5. **Vtable anchor (new).** A C++ virtual method is pinned by the *class it belongs to*: the vtable is matched across builds by aligning its per-slot fingerprints, then the target's slot is read back. See "Key techniques" below.
6. **Encoding fingerprint.** Registers + operand sizes with immediate/displacement values masked, to disambiguate template-instance siblings that the mnemonic stream ties on.
7. **Mnemonic fingerprint.** A last-resort structural match.
8. **Shortlist.** When nothing pins the function uniquely, a per-build list of the structural family it belongs to, each with a minted AOB, for manual disambiguation, instead of a wrong answer.

The chain never guesses: every anchor declines rather than emit a confidently-wrong address, and the shortlist is the honest floor for a genuinely anchorless target.

## Key techniques

### Vtable matching: semi-global affine alignment + distinctiveness weighting

A class's vtable is a run of code pointers. A recompile rewrites each method body, but the class keeps the same methods in the same slots, so the table is identifiable by fingerprinting each slot (a 16-mnemonic window) and matching the table whose per-slot fingerprints agree best. The matcher is a **Needleman-Wunsch / Gotoh alignment with affine gaps and free end-gaps**, integer-scaled for determinism:

- **Free end-gaps** let a block of methods prepended or appended in a newer build align at no cost (the usual cross-major change), instead of dragging the agreement down.
- **Affine gaps** (`GAP_OPEN -120`, `GAP_EXTEND -28`) coalesce a contiguous inserted/removed method block into one penalty.
- **Distinctiveness weighting**: each slot is weighted by the inverse of how many tables share that method, so a sibling class that shares only the inherited base-class backbone cannot tie the real class.

MSVC adjustor thunks (`add ecx, imm ; jmp`) under multiple inheritance are followed so the real method relocates, not the thunk.

### Widest-path chaining

Cross-version similarity decays with distance. Rather than matching the reference directly to a far build, the engine relocates over the **maximum-bottleneck (widest) path through the build graph**: each newly located build re-anchors and offers edges to the rest, and a build is taken by the highest-confidence path that reaches it, so a long version jump is crossed as a chain of short, high-confidence hops. A path's confidence is its weakest hop; every hop is back-checked against the immutable source identity so a chain cannot drift method-by-method onto a neighbour. This is the data-driven generalisation of "diff v83->v84, then v84->v88, ..." that follows measured similarity rather than an assumed version order.

### Constructor grounding (closes the major-refactor gap)

A pure virtual method with no string, import, or caller of its own, whose class is refactored enough that the per-slot matcher declines, is still relocated through the **constructor that installs its vtable**. The constructor pins itself by a build-stable class string; resolving it in the target build, the vtable address it writes is recovered from a window around it and the target slot read back. This is tried only as a fallback when the structural match is weak, so confident adjacent-build matches stay exact.

### Per-version AOB ranges

After relocation, each build's minted AOB is collapsed into contiguous version ranges: the run's AOB is carried forward as long as it still matches the next build *at that build's relocated address* (a coincidental unique match elsewhere is rejected); when it stops, the run closes and the next build's freshly minted AOB starts a new run. The result is "AOB X works v83..v88, AOB Y works v91..v95", derived purely from the relocated addresses, so it works for any anchor type.

## Measured results (real GMS clients)

- Clean virtual method, slot 0 of the v84 `0x78F16C` vtable (101 slots): relocates v83 -> v84 -> v88 -> v91 at weighted agreement 0.99-1.00 with clear margins; one operand-masked AOB covers v83..v91.
- The AranSkillGuide window's slot-0 method, which declined past v91 at structural agreement 0.55, now **relocates into v95.1 (0x450650) and v95.5 (0x450900) at 0.900** via constructor grounding.
- String-anchorable functions bridge the v95 break directly: 68 of 74 sampled v91 string-referencing functions produced a unique, validated v95.1 AOB.
- Caller-relative anchoring bridges non-string callees of string-anchored functions (validated on real v91 -> v95.1 cases).
- The degenerate template-fragment target `B3 ?? 83 EC ?? 8B FC 8D 75 ??` correctly declines (no stable handle) and returns a 10-candidate per-build shortlist.

## Surfaced in the UI

- **CLI** (`mksig`): the chosen candidate plus a "version coverage" section listing each AOB and the builds it covers; also in the `--json` output.
- **Desktop Signature Maker** (Tauri): a "Version coverage" section under the chosen result, each range's AOB copyable, threaded through `SigReportView` and rendered in `sigmaker.js`.

## Testing

- Whole workspace is fmt-clean, clippy `-D warnings` clean.
- 236 maple-core unit tests, 20 maple-cli, 20 maple-app, 2 golden, 5 parser-property; 17 ignored real-corpus tests (need the unpacked clients).
- The committed **golden snapshot stays byte-stable**: all relocation work is additive and only fires when no byte signature hardens, so end-to-end scan+resolve output is unchanged.
- The alignment dynamic program was stress-tested with a 3,000,000-case fuzzer (no panics, no out-of-bounds, monotonic mappings).

## Honest limitations

- **x86 / PE32 only.** Every relocation anchor is 32-bit; x64 clients are not yet handled for relocation.
- A class that references **no string anywhere** (in any method or its constructor) and a function with no import/caller handle remain shortlist-only. This is rare for UI/window classes (which all reference `.img` paths).
- The degenerate generic-template-fragment target is genuinely anchorless across builds and stays a shortlist case.

## Commits

- `Relocate virtual methods across client versions by their vtable`
- `Show cross-version AOB coverage in the signature report` (CLI)
- `Cover automated v91-to-v95 signature generation with real-corpus tests`
- `Show cross-version AOB coverage in the desktop Signature Maker`
- `Relocate functions across versions by a string-anchored caller`
- `Ground a refactored vtable through its constructor to close the v95 gap`
