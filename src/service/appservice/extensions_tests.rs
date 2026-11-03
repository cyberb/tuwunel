use super::Extensions;

#[test]
fn parses_rtc_extensions() {
	let yaml = br#"
id: livekit-jwt
as_token: a
hs_token: h
sender_localpart: _lk_jwt_service
url: null
namespaces:
  users:
    - exclusive: false
      regex: ".*"
io.element.msc4502.scopes: ["urn:matrix:client:io.element.msc4502:rooms:is_joined"]
io.element.msc4512.proxy_prefix: rtc/livekit
io.element.msc4512.proxy_url: unix:///run/lk.sock
"#;
	let extensions: Extensions = serde_yaml::from_slice(yaml).unwrap();

	assert!(extensions.has_scope("urn:matrix:client:io.element.msc4502:rooms:is_joined"));
	assert_eq!(extensions.proxy_prefix.as_deref(), Some("rtc/livekit"));
	assert_eq!(extensions.proxy_url.as_deref(), Some("unix:///run/lk.sock"));
}

#[test]
fn defaults_without_rtc_extensions() {
	let extensions: Extensions = serde_yaml::from_slice(b"id: bridge\nurl: http://x\n").unwrap();

	assert!(extensions.scopes.is_empty());
	assert!(extensions.proxy_prefix.is_none());
	assert!(extensions.proxy_url.is_none());
}
