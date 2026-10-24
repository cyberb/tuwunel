use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct EventRow {
	pub(super) room_id: String,
	pub(super) event_id: String,
	pub(super) json: String,
	pub(super) timeline: bool,
	pub(super) rejected: bool,
}
