#[derive(Debug, Default)]
pub(super) struct Summary {
	pub(super) users: usize,
	pub(super) profiles: usize,
	pub(super) account_data: usize,
	pub(super) devices: usize,
	pub(super) device_keys: usize,
	pub(super) cross_signing: usize,
	pub(super) key_backups: usize,
	pub(super) rooms: usize,
	pub(super) events: usize,
	pub(super) aliases: usize,
	pub(super) media: usize,
	pub(super) skipped: usize,
}
