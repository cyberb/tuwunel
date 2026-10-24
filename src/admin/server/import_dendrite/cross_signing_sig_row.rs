use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct CrossSigningSigRow {
	pub(super) origin_user_id: String,
	pub(super) origin_key_id: String,
	pub(super) target_user_id: String,
	pub(super) target_key_id: String,
	pub(super) signature: String,
}
