use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct StateRow {
	pub(super) room_id: String,
	pub(super) event_id: String,
}
