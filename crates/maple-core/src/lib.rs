pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod asmscan;
pub mod categorizer;
pub mod diff;
pub mod engine;
pub mod health;
pub mod memory;
pub mod output;
pub mod pattern;
pub mod resolver;
pub mod scanner;
pub mod stamp;

#[cfg(windows)]
pub mod process;

pub use asmscan::{AsmHit, AsmPattern, assembly_scan, parse_asm_patterns};
pub use diff::{DiffReport, Moved, diff, parse_dump};
pub use engine::{PatternRow, ProfileReport, ScanResult, Status, profile, scan};
pub use health::{Lint, lint};
pub use memory::{MemorySource, Region};
pub use output::Finding;
pub use pattern::{Arch, Pattern, Signature};
pub use resolver::Kind;
pub use scanner::{CompiledPattern, find_all};
pub use stamp::{BuildStamp, parse_stamp};

#[cfg(windows)]
pub use process::{AttachOptions, Locator, Target};
