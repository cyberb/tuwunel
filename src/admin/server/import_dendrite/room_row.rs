use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct RoomRow {
	pub(super) room_id: String,
	pub(super) room_version: String,
	pub(super) latest_event_ids: Vec<String>,
}
