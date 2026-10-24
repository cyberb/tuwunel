use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct KeyBackupVersionRow {
	pub(super) user_id: String,
	pub(super) version: String,
	pub(super) algorithm: String,
	pub(super) auth_data: String,
}
