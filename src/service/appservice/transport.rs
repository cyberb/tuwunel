use std::time::Duration;

use reqwest::Client;
use tuwunel_core::{Result, implement};

const UNIX_SCHEME: &str = "unix://";
const UNIX_BASE: &str = "http://localhost";

#[implement(super::Service)]
pub(super) fn transport(&self, dest: &str) -> Result<(Client, String)> {
	let Some(socket) = dest.strip_prefix(UNIX_SCHEME) else {
		return Ok((self.services.client.appservice.clone(), dest.to_owned()));
	};

	let mut clients = self.unix_clients.lock()?;
	if let Some(client) = clients.get(socket) {
		return Ok((client.clone(), UNIX_BASE.to_owned()));
	}

	let config = &self.services.config;
	let client = Client::builder()
		.unix_socket(socket)
		.connect_timeout(Duration::from_secs(5))
		.read_timeout(Duration::from_secs(config.appservice_timeout))
		.timeout(Duration::from_secs(config.appservice_timeout))
		.pool_max_idle_per_host(1)
		.pool_idle_timeout(Duration::from_secs(config.appservice_idle_timeout))
		.user_agent(tuwunel_core::version::user_agent())
		.build()?;

	clients.insert(socket.to_owned(), client.clone());

	Ok((client, UNIX_BASE.to_owned()))
}
