//! The `export_text` command: render the most recent scan as a C/C++ header, a
//! Cheat Engine table, or a plain-text dump.

use maple_core::output::export;

use crate::state::AppState;

#[tauri::command]
pub fn export_text(state: tauri::State<'_, AppState>, format: String) -> Result<String, String> {
    let guard = state
        .last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let last = guard
        .as_ref()
        .ok_or_else(|| "run a scan first; there is nothing to export yet".to_string())?;
    let header = last.stamp.header_line();
    Ok(export(
        &last.findings,
        &last.module_name,
        last.module_base,
        Some(&header),
        &format,
    ))
}
