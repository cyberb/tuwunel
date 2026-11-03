use std::time::SystemTime;

use axum::{
	body::{Body, to_bytes},
	extract::{Request, State},
	response::Response,
};
use axum_extra::{
	TypedHeader,
	headers::{Authorization, authorization::Bearer},
};
use http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use ruma::api::error::{ErrorKind, UnknownTokenErrorData};
use tuwunel_core::{Err, Error, Result, err};

const PROXY_PREFIX: &str = "rtc/livekit";
const USER_ID_HEADER: &str = "x-matrix-user-identifier";
const MAX_BODY_BYTES: usize = 65_536;

pub(crate) async fn client_proxy_route(
	State(services): State<crate::State>,
	bearer: Option<TypedHeader<Authorization<Bearer>>>,
	request: Request,
) -> Result<Response> {
	let (parts, body) = request.into_parts();
	let query_token = parts
		.uri
		.query()
		.into_iter()
		.flat_map(|query| query.split('&'))
		.find_map(|pair| pair.strip_prefix("access_token="));

	let Some(token) = bearer
		.as_ref()
		.map(|TypedHeader(Authorization(bearer))| bearer.token())
		.or(query_token)
	else {
		return Err!(Request(MissingToken("Missing access token.")));
	};

	let (user_id, _, expires_at) = services
		.users
		.find_from_token(token)
		.await
		.map_err(|_| unknown_token(false))?;

	if expires_at.is_some_and(|expires_at| expires_at < SystemTime::now()) {
		return Err(unknown_token(true));
	}

	let Some(info) = services.appservice.find_proxy(PROXY_PREFIX).await else {
		return Err!(Request(Unrecognized("Unrecognized request")));
	};

	let query: Vec<&str> = parts
		.uri
		.query()
		.into_iter()
		.flat_map(|query| query.split('&'))
		.filter(|pair| !pair.starts_with("access_token="))
		.collect();

	let path_and_query = if query.is_empty() {
		parts.uri.path().to_owned()
	} else {
		format!("{}?{}", parts.uri.path(), query.join("&"))
	};

	let body = to_bytes(body, MAX_BODY_BYTES)
		.await
		.map_err(|e| err!(Request(TooLarge("Request body is too large: {e}"))))?;

	let mut headers = HeaderMap::new();
	if let Some(content_type) = parts.headers.get(CONTENT_TYPE) {
		headers.insert(CONTENT_TYPE, content_type.clone());
	}
	headers.insert(USER_ID_HEADER, HeaderValue::from_str(user_id.as_str())?);

	let upstream = services
		.appservice
		.proxy(&info, parts.method, &path_and_query, headers, body)
		.await?;

	let status = upstream.status();
	let content_type = upstream.headers().get(CONTENT_TYPE).cloned();
	let bytes = upstream.bytes().await?;

	let mut response = Response::builder().status(status);
	if let Some(content_type) = content_type {
		response = response.header(CONTENT_TYPE, content_type);
	}

	Ok(response.body(Body::from(bytes))?)
}

fn unknown_token(soft_logout: bool) -> Error {
	Error::BadRequest(
		ErrorKind::UnknownToken(UnknownTokenErrorData { soft_logout }),
		if soft_logout { "Expired access token." } else { "Unknown access token." },
	)
}
