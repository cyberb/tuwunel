use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct PublishedRow {
	pub(super) room_id: String,
}
