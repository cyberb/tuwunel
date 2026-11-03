use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct IsJoinedResponse {
	pub(super) joined: bool,
}
