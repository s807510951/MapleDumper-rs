//! Shared application state and its construction.
//!
//! [`AppState`] is the object Tauri manages; every command reads it through
//! `tauri::State`. [`LastScan`] caches the most recent scan so the export
//! commands can render it without rescanning the target.

use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

use maple_core::{BuildStamp, Finding};

use crate::history;
use crate::jobs::JobManager;

pub struct AppState {
    pub(crate) jobs: JobManager,
    pub(crate) last: Arc<Mutex<Option<LastScan>>>,
    pub(crate) db: Arc<Mutex<Connection>>,
}

/// Lock the history connection, recovering a poisoned mutex instead of propagating the poison. A
/// panic while another command briefly held the lock must not permanently break history reads for
/// the rest of the session (rusqlite upholds the connection's own invariants, so the recovered
/// guard is safe to use). This is the single, consistent locking policy for the database: reads and
/// writes both recover, rather than reads failing while writes recover.
pub(crate) fn lock_db(db: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct LastScan {
    pub(crate) findings: Vec<Finding>,
    pub(crate) module_name: String,
    pub(crate) module_base: u64,
    pub(crate) stamp: BuildStamp,
}

/// Open the on-disk history database, falling back to an in-memory store if the
/// real file cannot be opened so a session still works without persistence.
pub(crate) fn open_history_db() -> Connection {
    let path = history::default_db_path();
    match history::open(&path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!(
                "[warn] could not open history database at {}: {e}; history will not be saved this session",
                path.display()
            );
            history::open_memory()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_db_recovers_from_a_poisoned_mutex() {
        // ARCH-7: a panic while the lock is held poisons the mutex. The propagate-poison policy used
        // to break every later history read; lock_db must recover so reads keep working.
        let db = Arc::new(Mutex::new(history::open_memory()));
        let poisoner = Arc::clone(&db);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the connection mutex");
        })
        .join();
        assert!(db.lock().is_err(), "the mutex should be poisoned");

        let conn = lock_db(&db);
        let one: i64 = conn
            .query_row("SELECT 1", [], |row| row.get(0))
            .expect("the recovered connection is still usable");
        assert_eq!(one, 1);
    }
}
