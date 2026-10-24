use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct DeviceRow {
	pub(super) localpart: String,
	pub(super) server_name: String,
	pub(super) device_id: String,
	pub(super) access_token: String,
	pub(super) display_name: Option<String>,
	pub(super) ip: Option<String>,
}
