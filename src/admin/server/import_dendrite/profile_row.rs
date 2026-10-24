use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct ProfileRow {
	pub(super) localpart: String,
	pub(super) server_name: String,
	pub(super) display_name: Option<String>,
	pub(super) avatar_url: Option<String>,
}
