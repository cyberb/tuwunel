use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct KeyBackupRow {
	pub(super) user_id: String,
	pub(super) room_id: String,
	pub(super) session_id: String,
	pub(super) version: String,
	pub(super) first_message_index: u64,
	pub(super) forwarded_count: u64,
	pub(super) is_verified: bool,
	pub(super) session_data: String,
}
