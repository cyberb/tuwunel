use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct MediaRow {
	pub(super) media_id: String,
	pub(super) media_origin: String,
	pub(super) content_type: String,
	pub(super) upload_name: String,
	pub(super) base64hash: String,
	pub(super) user_id: String,
}
