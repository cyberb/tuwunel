use bytes::Bytes;
use http::{HeaderMap, Method};
use tuwunel_core::{Err, Result, implement};

use super::RegistrationInfo;

#[implement(super::Service)]
pub async fn find_proxy(&self, prefix: &str) -> Option<RegistrationInfo> {
	self.read()
		.await
		.values()
		.find(|info| {
			info.extensions.proxy_url.is_some()
				&& info.extensions.proxy_prefix.as_deref() == Some(prefix)
		})
		.cloned()
}

#[implement(super::Service)]
pub async fn proxy(
	&self,
	info: &RegistrationInfo,
	method: Method,
	path_and_query: &str,
	headers: HeaderMap,
	body: Bytes,
) -> Result<reqwest::Response> {
	let Some(dest) = info.extensions.proxy_url.as_deref() else {
		return Err!(Request(Unrecognized("No proxy configured.")));
	};

	let (client, base) = self.transport(dest)?;
	let url = format!("{}{path_and_query}", base.trim_end_matches('/'));

	Ok(client
		.request(method, url)
		.headers(headers)
		.bearer_auth(&info.registration.hs_token)
		.body(body)
		.send()
		.await?)
}
