use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct AliasRow {
	pub(super) alias: String,
	pub(super) room_id: String,
	pub(super) creator_id: String,
}
