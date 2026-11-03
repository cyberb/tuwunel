use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Extensions {
	#[serde(rename = "io.element.msc4502.scopes", default)]
	pub scopes: Vec<String>,

	#[serde(rename = "io.element.msc4512.proxy_prefix")]
	pub proxy_prefix: Option<String>,

	#[serde(rename = "io.element.msc4512.proxy_url")]
	pub proxy_url: Option<String>,
}

impl Extensions {
	#[must_use]
	pub fn has_scope(&self, scope: &str) -> bool { self.scopes.iter().any(|s| s == scope) }
}
