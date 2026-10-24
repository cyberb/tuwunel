use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct CrossSigningKeyRow {
	pub(super) user_id: String,
	pub(super) key_type: i16,
	pub(super) key_data: String,
}
