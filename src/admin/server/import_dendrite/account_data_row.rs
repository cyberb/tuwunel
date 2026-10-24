use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct AccountDataRow {
	pub(super) localpart: String,
	pub(super) server_name: String,
	pub(super) room_id: Option<String>,
	#[serde(rename = "type")]
	pub(super) kind: String,
	pub(super) content: String,
}
