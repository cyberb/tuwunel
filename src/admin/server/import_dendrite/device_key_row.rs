use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct DeviceKeyRow {
	pub(super) user_id: String,
	pub(super) device_id: String,
	pub(super) key_json: String,
}
