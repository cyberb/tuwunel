use axum::{
	Json,
	extract::{Path, RawQuery, State},
};
use axum_extra::{
	TypedHeader,
	headers::{Authorization, authorization::Bearer},
};
use ruma::{
	OwnedRoomId,
	api::error::{ErrorKind, UnknownTokenErrorData},
};
use tuwunel_core::{Err, Error, Result, err};

use super::{IsJoinedQuery, IsJoinedResponse};

const SCOPE: &str = "urn:matrix:client:io.element.msc4502:rooms:is_joined";

pub(crate) async fn is_joined_route(
	State(services): State<crate::State>,
	Path(room_id): Path<OwnedRoomId>,
	RawQuery(query): RawQuery,
	bearer: Option<TypedHeader<Authorization<Bearer>>>,
) -> Result<Json<IsJoinedResponse>> {
	let Some(TypedHeader(Authorization(bearer))) = bearer else {
		return Err!(Request(MissingToken("Missing access token.")));
	};

	let info = services
		.appservice
		.find_from_access_token(bearer.token())
		.await
		.map_err(|_| {
			Error::BadRequest(
				ErrorKind::UnknownToken(UnknownTokenErrorData::new()),
				"Unknown access token.",
			)
		})?;

	if !info.extensions.has_scope(SCOPE) {
		return Err!(Request(Forbidden("Appservice is not granted the is_joined scope.")));
	}

	let query: IsJoinedQuery = serde_html_form::from_str(query.as_deref().unwrap_or_default())
		.map_err(|e| err!(Request(InvalidParam("Invalid query: {e}"))))?;

	let joined = match (query.mxid, query.server_name) {
		| (Some(user_id), None) =>
			services
				.state_cache
				.is_joined(&user_id, &room_id)
				.await,
		| (None, Some(server_name)) =>
			services
				.state_cache
				.server_in_room(&server_name, &room_id)
				.await,
		| _ => return Err!(Request(InvalidParam("Expected exactly one of mxid or server_name."))),
	};

	Ok(Json(IsJoinedResponse { joined }))
}
