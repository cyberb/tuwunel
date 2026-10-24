use std::time::Duration;

use reqwest::{Client, Method, RequestBuilder, redirect::Policy};
use tuwunel_core::{Config, Result, err};
use url::Url;

use super::Provider;

pub(crate) fn provider_request(
	default: &Client,
	config: &Config,
	provider: Option<&Provider>,
	method: Method,
	url: Url,
) -> Result<RequestBuilder> {
	let Some(socket) = provider.and_then(|provider| provider.unix_socket.as_ref()) else {
		return Ok(default.request(method, url));
	};

	let host = url
		.host_str()
		.ok_or_else(|| err!(Config("issuer_url", "Provider URL {url} has no host")))?
		.to_owned();

	let mut local = url;
	local
		.set_scheme("http")
		.map_err(|()| err!(Config("issuer_url", "Provider URL scheme cannot be rewritten")))?;
	local
		.set_port(None)
		.map_err(|()| err!(Config("issuer_url", "Provider URL port cannot be rewritten")))?;

	let client = Client::builder()
		.unix_socket(socket.as_path())
		.connect_timeout(Duration::from_secs(config.request_conn_timeout))
		.timeout(Duration::from_secs(config.request_total_timeout))
		.redirect(Policy::none())
		.user_agent(tuwunel_core::version::user_agent())
		.build()?;

	Ok(client
		.request(method, local)
		.header("X-Forwarded-Proto", "https")
		.header("X-Forwarded-Host", host))
}
