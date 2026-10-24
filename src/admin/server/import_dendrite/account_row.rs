use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct AccountRow {
	pub(super) localpart: String,
	pub(super) server_name: String,
	pub(super) has_password: bool,
	pub(super) appservice_id: Option<String>,
	pub(super) deactivated: bool,
	pub(super) account_type: i16,
}
