use ruma::{OwnedServerName, OwnedUserId};
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct IsJoinedQuery {
	pub(super) mxid: Option<OwnedUserId>,
	pub(super) server_name: Option<OwnedServerName>,
}
