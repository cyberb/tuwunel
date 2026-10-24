mod account_data_row;
mod account_row;
mod alias_row;
mod cross_signing_key_row;
mod cross_signing_sig_row;
mod device_key_row;
mod device_row;
mod event_row;
mod key_backup_row;
mod key_backup_version_row;
mod media_row;
mod profile_row;
mod published_row;
mod room_row;
mod state_row;
mod summary;

use std::{
	borrow::Borrow,
	collections::{HashMap, HashSet},
	fs::{self, File},
	io::{BufRead, BufReader},
	iter::once,
	mem,
	path::{Path, PathBuf},
	sync::Arc,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures::{StreamExt, stream};
use ruma::{
	CanonicalJsonObject, CanonicalJsonValue, DeviceId, EventId, Mxc, OwnedEventId, OwnedMxcUri,
	OwnedRoomId, OwnedUserId, RoomAliasId, RoomId, RoomVersionId, ServerName, UserId,
	api::client::backup::{BackupAlgorithm, KeyBackupData},
	encryption::{CrossSigningKey, DeviceKeys},
	events::{RoomAccountDataEventType, StateEventType},
	serde::Raw,
	signatures::Ed25519KeyPair,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json, value::RawValue};
use tuwunel_core::{
	Err, Result, err, info,
	matrix::{PduEvent, event::gen_event_id_canonical_json, room_version},
	utils::content_disposition::make_content_disposition,
	warn,
};
use tuwunel_service::{
	Services,
	users::PASSWORD_SENTINEL,
	rooms::{
		state::RoomMutexGuard,
		state_compressor::{CompressedState, HashSetCompressStateEvent},
	},
};

use self::{
	account_data_row::AccountDataRow, account_row::AccountRow, alias_row::AliasRow,
	cross_signing_key_row::CrossSigningKeyRow, cross_signing_sig_row::CrossSigningSigRow,
	device_key_row::DeviceKeyRow, device_row::DeviceRow, event_row::EventRow,
	key_backup_row::KeyBackupRow, key_backup_version_row::KeyBackupVersionRow,
	media_row::MediaRow, profile_row::ProfileRow, published_row::PublishedRow,
	room_row::RoomRow, state_row::StateRow, summary::Summary,
};
use crate::admin_command;

const ED25519_PKCS8_PREFIX: [u8; 16] = [
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const ACCOUNT_TYPE_ADMIN: i16 = 3;

#[admin_command]
pub(super) async fn import_dendrite(
	&self,
	path: PathBuf,
	signing_key: PathBuf,
	media_path: PathBuf,
) -> Result {
	let services = self.services;
	let mut summary = Summary::default();

	import_signing_key(services, &signing_key)?;
	let (users, admins) = import_accounts(services, &path, &mut summary).await?;
	import_profiles(services, &path, &mut summary).await?;
	import_account_data(services, &path, &mut summary).await?;
	import_devices(services, &path, &mut summary).await?;
	import_cross_signing(services, &path, &mut summary).await?;
	import_key_backups(services, &path, &mut summary).await?;
	import_rooms(services, &path, &mut summary).await?;
	import_aliases(services, &path, &mut summary).await?;
	import_media(services, &path, &media_path, &mut summary).await?;
	reset_notifications(services, &users).await;

	for user_id in &admins {
		services.admin.make_user_admin(user_id).await?;
	}

	info!(?summary, "Dendrite import complete");
	fs::write(path.join("imported"), format!("{summary:?}"))?;

	write!(self, "Imported Dendrite data: {summary:?}").await
}

fn rows<T: DeserializeOwned>(path: &Path, name: &str) -> Result<Vec<T>> {
	let file = path.join(name);
	if !file.exists() {
		return Ok(Vec::new());
	}

	let mut rows = Vec::new();
	for line in BufReader::new(File::open(file)?).lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}

		rows.push(serde_json::from_str(&line)?);
	}

	Ok(rows)
}

fn raw<T>(value: &Value) -> Result<Raw<T>> {
	Ok(Raw::from_json(serde_json::value::to_raw_value(value)?))
}

fn local_user(services: &Services, localpart: &str, server_name: &str) -> Option<OwnedUserId> {
	if server_name != services.globals.server_name().as_str() {
		return None;
	}

	UserId::parse_with_server_name(localpart, services.globals.server_name()).ok()
}

fn import_signing_key(services: &Services, file: &Path) -> Result {
	let pem = fs::read_to_string(file)?;
	let key_id = pem
		.lines()
		.find_map(|line| line.strip_prefix("Key-ID:"))
		.map(str::trim)
		.ok_or_else(|| err!("Signing key {file:?} has no Key-ID header"))?;

	let version = key_id
		.strip_prefix("ed25519:")
		.ok_or_else(|| err!("Signing key {file:?} is not ed25519: {key_id}"))?;

	let body: String = pem
		.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty() && !line.starts_with("-----") && !line.contains(':'))
		.collect();

	let seed = STANDARD
		.decode(body)
		.map_err(|e| err!("Signing key {file:?} is not base64: {e}"))?;

	if seed.len() != 32 {
		return Err!("Signing key {file:?} has {} bytes, expected 32", seed.len());
	}

	let der = [ED25519_PKCS8_PREFIX.as_slice(), seed.as_slice()].concat();
	Ed25519KeyPair::from_der(&der, version.to_owned())
		.map_err(|e| err!("Signing key {file:?} is invalid: {e:?}"))?;

	let value: (String, Vec<u8>) = (version.to_owned(), der);
	services.db["global"].raw_put(b"keypair", &value);
	info!(%key_id, "Imported signing key");

	Ok(())
}

async fn import_accounts(
	services: &Services,
	path: &Path,
	summary: &mut Summary,
) -> Result<(Vec<OwnedUserId>, Vec<OwnedUserId>)> {
	let mut users = Vec::new();
	let mut admins = Vec::new();

	for row in rows::<AccountRow>(path, "accounts.jsonl")? {
		let Some(user_id) = local_user(services, &row.localpart, &row.server_name) else {
			summary.skipped += 1;
			continue;
		};

		if services.users.exists(&user_id).await {
			continue;
		}

		let person = row.appservice_id.is_none() && !row.deactivated;
		let password = person.then_some(PASSWORD_SENTINEL);
		let origin = person.then_some("sso");
		services
			.users
			.create(&user_id, password, origin)
			.await?;

		if person && row.account_type == ACCOUNT_TYPE_ADMIN {
			admins.push(user_id.clone());
		}

		if person {
			users.push(user_id);
		}

		summary.users += 1;
	}

	Ok((users, admins))
}

async fn import_profiles(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	for row in rows::<ProfileRow>(path, "profiles.jsonl")? {
		let Some(user_id) = local_user(services, &row.localpart, &row.server_name) else {
			continue;
		};

		if !services.users.exists(&user_id).await {
			continue;
		}

		if let Some(name) = row.display_name.as_deref().filter(|name| !name.is_empty()) {
			services
				.profile
				.set_displayname(&user_id, Some(name), None)
				.await?;
		}

		if let Some(url) = row.avatar_url.filter(|url| !url.is_empty()) {
			let url = OwnedMxcUri::from(url);
			services
				.profile
				.set_avatar_url(&user_id, Some(&url), None)
				.await?;
		}

		summary.profiles += 1;
	}

	Ok(())
}

async fn import_account_data(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	for row in rows::<AccountDataRow>(path, "account_data.jsonl")? {
		let Some(user_id) = local_user(services, &row.localpart, &row.server_name) else {
			continue;
		};

		let room_id = match row.room_id.as_deref().filter(|room_id| !room_id.is_empty()) {
			| Some(room_id) => Some(RoomId::parse(room_id)?),
			| None => None,
		};

		let Ok(content) = serde_json::from_str::<Value>(&row.content) else {
			warn!(%user_id, kind = %row.kind, "Skipping unparsable account data");
			summary.skipped += 1;
			continue;
		};

		let event = json!({ "type": row.kind, "content": content });
		services
			.account_data
			.update(
				room_id.as_deref(),
				&user_id,
				RoomAccountDataEventType::from(row.kind.as_str()),
				&event,
			)
			.await?;

		summary.account_data += 1;
	}

	Ok(())
}

fn signatures_for(
	sigs: &[CrossSigningSigRow],
	target_user_id: &str,
	target_key_ids: &[&str],
	value: &mut Value,
) {
	for sig in sigs.iter().filter(|sig| {
		sig.target_user_id == target_user_id && target_key_ids.contains(&sig.target_key_id.as_str())
	}) {
		let Some(object) = value.as_object_mut() else {
			return;
		};

		let signatures = object
			.entry("signatures")
			.or_insert_with(|| json!({}));

		if let Some(signatures) = signatures.as_object_mut() {
			let by_user = signatures
				.entry(sig.origin_user_id.clone())
				.or_insert_with(|| json!({}));

			if let Some(by_user) = by_user.as_object_mut() {
				by_user.insert(sig.origin_key_id.clone(), Value::String(sig.signature.clone()));
			}
		}
	}
}

async fn import_devices(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	let mut devices = HashSet::new();

	for row in rows::<DeviceRow>(path, "devices.jsonl")? {
		let Some(user_id) = local_user(services, &row.localpart, &row.server_name) else {
			continue;
		};

		if !services.users.exists(&user_id).await {
			continue;
		}

		let device_id: &DeviceId = row.device_id.as_str().into();
		let ip = row.ip.as_deref().and_then(|ip| ip.parse().ok());
		let created = services
			.users
			.create_device(
				&user_id,
				Some(device_id),
				(Some(row.access_token.as_str()), None),
				None,
				row.display_name.as_deref(),
				ip,
			)
			.await;

		if let Err(e) = created {
			warn!(%user_id, %device_id, "Skipping device: {e}");
			summary.skipped += 1;
			continue;
		}

		devices.insert((user_id.to_string(), row.device_id));
		summary.devices += 1;
	}

	let sigs = rows::<CrossSigningSigRow>(path, "cross_signing_sigs.jsonl")?;

	for row in rows::<DeviceKeyRow>(path, "device_keys.jsonl")? {
		if row.key_json.is_empty() || !devices.contains(&(row.user_id.clone(), row.device_id.clone())) {
			continue;
		}

		let Ok(mut value) = serde_json::from_str::<Value>(&row.key_json) else {
			summary.skipped += 1;
			continue;
		};

		signatures_for(&sigs, &row.user_id, &[row.device_id.as_str()], &mut value);

		let user_id = UserId::parse(&row.user_id)?;
		let device_id: &DeviceId = row.device_id.as_str().into();
		let keys: Raw<DeviceKeys> = raw(&value)?;
		services
			.users
			.add_device_keys(&user_id, device_id, &keys)
			.await;

		summary.device_keys += 1;
	}

	Ok(())
}

fn cross_signing_key(
	sigs: &[CrossSigningSigRow],
	row: &CrossSigningKeyRow,
	usage: &str,
) -> Result<Raw<CrossSigningKey>> {
	let key_id = format!("ed25519:{}", row.key_data);
	let mut value = json!({
		"user_id": row.user_id,
		"usage": [usage],
		"keys": { key_id.clone(): row.key_data },
	});

	signatures_for(sigs, &row.user_id, &[key_id.as_str(), row.key_data.as_str()], &mut value);

	raw(&value)
}

async fn import_cross_signing(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	let sigs = rows::<CrossSigningSigRow>(path, "cross_signing_sigs.jsonl")?;
	let mut by_user: HashMap<String, Vec<CrossSigningKeyRow>> = HashMap::new();
	for row in rows::<CrossSigningKeyRow>(path, "cross_signing_keys.jsonl")? {
		by_user
			.entry(row.user_id.clone())
			.or_default()
			.push(row);
	}

	for (user, keys) in by_user {
		let user_id = UserId::parse(&user)?;
		if !services.globals.user_is_local(&user_id) || !services.users.exists(&user_id).await {
			continue;
		}

		let mut master = None;
		let mut self_signing = None;
		let mut user_signing = None;
		for row in &keys {
			match row.key_type {
				| 1 => master = Some(cross_signing_key(&sigs, row, "master")?),
				| 2 => self_signing = Some(cross_signing_key(&sigs, row, "self_signing")?),
				| 3 => user_signing = Some(cross_signing_key(&sigs, row, "user_signing")?),
				| _ => summary.skipped += 1,
			}
		}

		if master.is_none() {
			continue;
		}

		match services
			.users
			.add_cross_signing_keys(&user_id, &master, &self_signing, &user_signing, false)
			.await
		{
			| Ok(()) => summary.cross_signing += 1,
			| Err(e) => {
				warn!(%user_id, "Skipping cross-signing keys: {e}");
				summary.skipped += 1;
			},
		}
	}

	Ok(())
}

async fn import_key_backups(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	let mut latest: HashMap<String, KeyBackupVersionRow> = HashMap::new();
	for row in rows::<KeyBackupVersionRow>(path, "key_backup_versions.jsonl")? {
		let newer = latest.get(&row.user_id).is_none_or(|current| {
			current.version.parse::<u64>().unwrap_or(0) < row.version.parse::<u64>().unwrap_or(0)
		});

		if newer {
			latest.insert(row.user_id.clone(), row);
		}
	}

	let mut keys: HashMap<(String, String), Vec<KeyBackupRow>> = HashMap::new();
	for row in rows::<KeyBackupRow>(path, "key_backups.jsonl")? {
		keys.entry((row.user_id.clone(), row.version.clone()))
			.or_default()
			.push(row);
	}

	for (user, version) in latest {
		let user_id = UserId::parse(&user)?;
		if !services.globals.user_is_local(&user_id) || !services.users.exists(&user_id).await {
			continue;
		}

		let Ok(auth_data) = serde_json::from_str::<Value>(&version.auth_data) else {
			summary.skipped += 1;
			continue;
		};

		let algorithm: Raw<BackupAlgorithm> =
			raw(&json!({ "algorithm": version.algorithm, "auth_data": auth_data }))?;

		let new_version = services
			.key_backups
			.create_backup(&user_id, &algorithm)
			.await?;

		let mut entries: Vec<(OwnedRoomId, String, Raw<KeyBackupData>)> = Vec::new();
		for row in keys
			.remove(&(user.clone(), version.version.clone()))
			.unwrap_or_default()
		{
			let Ok(session_data) = serde_json::from_str::<Value>(&row.session_data) else {
				summary.skipped += 1;
				continue;
			};

			entries.push((
				RoomId::parse(&row.room_id)?,
				row.session_id,
				raw(&json!({
					"first_message_index": row.first_message_index,
					"forwarded_count": row.forwarded_count,
					"is_verified": row.is_verified,
					"session_data": session_data,
				}))?,
			));
		}

		let (count, _) = services
			.key_backups
			.add_keys(
				&user_id,
				&new_version,
				stream::iter(
					entries
						.iter()
						.map(|(room_id, session_id, data)| {
							(room_id.as_ref(), session_id.as_str(), data)
						}),
				),
			)
			.await?;

		summary.key_backups += count;
	}

	Ok(())
}

async fn import_rooms(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	let rooms: HashMap<String, RoomRow> = rows::<RoomRow>(path, "rooms.jsonl")?
		.into_iter()
		.map(|room| (room.room_id.clone(), room))
		.collect();

	let mut state: HashMap<String, Vec<String>> = HashMap::new();
	for row in rows::<StateRow>(path, "state.jsonl")? {
		state
			.entry(row.room_id)
			.or_default()
			.push(row.event_id);
	}

	let file = path.join("events.jsonl");
	if !file.exists() {
		return Ok(());
	}

	let mut batch: Vec<EventRow> = Vec::new();
	for line in BufReader::new(File::open(file)?).lines() {
		let line = line?;
		if line.trim().is_empty() {
			continue;
		}

		let row: EventRow = serde_json::from_str(&line)?;
		if batch
			.first()
			.is_some_and(|first| first.room_id != row.room_id)
		{
			import_room(services, &rooms, &state, mem::take(&mut batch), summary).await?;
		}

		batch.push(row);
	}

	if !batch.is_empty() {
		import_room(services, &rooms, &state, batch, summary).await?;
	}

	Ok(())
}

fn string_field<'a>(value: &'a CanonicalJsonObject, field: &str) -> Option<&'a str> {
	match value.get(field) {
		| Some(CanonicalJsonValue::String(value)) => Some(value.as_str()),
		| _ => None,
	}
}

async fn import_room(
	services: &Services,
	rooms: &HashMap<String, RoomRow>,
	state: &HashMap<String, Vec<String>>,
	events: Vec<EventRow>,
	summary: &mut Summary,
) -> Result {
	let Some(room) = events
		.first()
		.and_then(|event| rooms.get(&event.room_id))
	else {
		summary.skipped += events.len();
		return Ok(());
	};

	let room_id = RoomId::parse(&room.room_id)?;
	let room_version_id = RoomVersionId::try_from(room.room_version.as_str())?;
	let rules = room_version::rules(&room_version_id)?;

	services
		.short
		.get_or_create_shortroomid(&room_id)
		.await;

	let state_lock = services.state.mutex.lock(&room_id).await;

	let mut keys: HashMap<OwnedEventId, (String, String)> = HashMap::new();
	let mut timeline = Vec::new();
	for row in events {
		let raw = RawValue::from_string(row.json)?;
		let (event_id, mut value) = match gen_event_id_canonical_json(&raw, &room_version_id) {
			| Ok(parsed) => parsed,
			| Err(e) => {
				warn!(%room_id, event_id = %row.event_id, "Skipping unparsable event: {e}");
				summary.skipped += 1;
				continue;
			},
		};

		if event_id.as_str() != row.event_id {
			warn!(%room_id, %event_id, dendrite = %row.event_id, "Event ID mismatch");
		}

		if !rules.event_format.require_event_id {
			value.insert("event_id".into(), CanonicalJsonValue::String(event_id.as_str().into()));
		}

		if let (Some(kind), Some(state_key)) =
			(string_field(&value, "type"), string_field(&value, "state_key"))
		{
			keys.insert(event_id.clone(), (kind.to_owned(), state_key.to_owned()));
		}

		services
			.timeline
			.add_pdu_outlier(&event_id, &value);

		if row.timeline && !row.rejected {
			timeline.push((event_id, value));
		}
	}

	let current = state_map(services, &keys, state.get(&room.room_id)).await;
	if current.is_empty() {
		warn!(%room_id, "Skipping room without current state");
		summary.skipped += 1;
		return Ok(());
	}

	let starts_with_create = timeline
		.first()
		.is_some_and(|(_, value)| string_field(value, "type") == Some("m.room.create"));

	if !starts_with_create {
		force_room_state(services, &room_id, &current, &state_lock).await?;
	}

	for (event_id, value) in timeline {
		let (pdu, value) =
			match PduEvent::from_object_federation(&room_id, &event_id, value, &rules) {
				| Ok(parsed) => parsed,
				| Err(e) => {
					warn!(%room_id, %event_id, "Skipping invalid event: {e}");
					summary.skipped += 1;
					continue;
				},
			};

		let statehash = services.state.append_to_state(&pdu).await?;
		services
			.timeline
			.append_pdu(&pdu, value, once(pdu.event_id.borrow()), &state_lock)
			.await?;

		services
			.state
			.set_room_state(&room_id, statehash, &state_lock);

		summary.events += 1;
	}

	force_room_state(services, &room_id, &current, &state_lock).await?;

	let latest: Vec<OwnedEventId> = room
		.latest_event_ids
		.iter()
		.filter_map(|event_id| EventId::parse(event_id).ok())
		.collect();

	if !latest.is_empty() {
		services
			.state
			.set_forward_extremities(&room_id, latest.iter().map(Borrow::borrow), &state_lock)
			.await;
	}

	services
		.state_cache
		.update_joined_count(&room_id)
		.await;

	summary.rooms += 1;

	Ok(())
}

async fn state_map(
	services: &Services,
	keys: &HashMap<OwnedEventId, (String, String)>,
	state_ids: Option<&Vec<String>>,
) -> HashMap<u64, OwnedEventId> {
	let mut map = HashMap::new();
	for id in state_ids.into_iter().flatten() {
		let Ok(event_id) = EventId::parse(id) else {
			continue;
		};

		let Some((kind, state_key)) = keys.get(&event_id) else {
			warn!(%event_id, "Current state event missing from export");
			continue;
		};

		let shortstatekey = services
			.short
			.get_or_create_shortstatekey(&StateEventType::from(kind.as_str()), state_key)
			.await;

		map.insert(shortstatekey, event_id);
	}

	map
}

async fn force_room_state(
	services: &Services,
	room_id: &RoomId,
	state: &HashMap<u64, OwnedEventId>,
	state_lock: &RoomMutexGuard,
) -> Result {
	let compressed: CompressedState = services
		.state_compressor
		.compress_state_events(state.iter().map(|(key, event_id)| (key, event_id.borrow())))
		.collect()
		.await;

	let HashSetCompressStateEvent { shortstatehash, added, removed } = services
		.state_compressor
		.save_state(room_id, Arc::new(compressed))
		.await?;

	services
		.state
		.force_state(room_id, shortstatehash, added, removed, state_lock)
		.await
}

async fn import_aliases(services: &Services, path: &Path, summary: &mut Summary) -> Result {
	for row in rows::<AliasRow>(path, "aliases.jsonl")? {
		let (Ok(alias), Ok(room_id)) = (RoomAliasId::parse(&row.alias), RoomId::parse(&row.room_id))
		else {
			summary.skipped += 1;
			continue;
		};

		let creator = UserId::parse(&row.creator_id)
			.ok()
			.filter(|user_id| services.globals.user_is_local(user_id));

		let result = match &creator {
			| Some(creator) => services.alias.set_alias_by(&alias, &room_id, creator),
			| None => services.alias.set_alias(&alias, &room_id),
		};

		match result {
			| Ok(()) => summary.aliases += 1,
			| Err(e) => {
				warn!(%alias, "Skipping alias: {e}");
				summary.skipped += 1;
			},
		}
	}

	for row in rows::<PublishedRow>(path, "published.jsonl")? {
		if let Ok(room_id) = RoomId::parse(&row.room_id) {
			services.directory.set_public(&room_id, None);
		}
	}

	Ok(())
}

fn media_file(media_path: &Path, hash: &str) -> Option<PathBuf> {
	if hash.len() < 3 || !hash.is_char_boundary(2) {
		return None;
	}

	Some(
		media_path
			.join(&hash[0..1])
			.join(&hash[1..2])
			.join(&hash[2..])
			.join("file"),
	)
}

async fn import_media(
	services: &Services,
	path: &Path,
	media_path: &Path,
	summary: &mut Summary,
) -> Result {
	for row in rows::<MediaRow>(path, "media.jsonl")? {
		let Some(file) = media_file(media_path, &row.base64hash) else {
			summary.skipped += 1;
			continue;
		};

		let Ok(bytes) = fs::read(&file) else {
			warn!(media_id = %row.media_id, ?file, "Skipping missing media file");
			summary.skipped += 1;
			continue;
		};

		let Ok(server_name) = ServerName::parse(&row.media_origin) else {
			summary.skipped += 1;
			continue;
		};

		let user = UserId::parse(&row.user_id)
			.ok()
			.filter(|user_id| services.globals.user_is_local(user_id));

		let content_type = Some(row.content_type.as_str()).filter(|value| !value.is_empty());
		let filename = Some(row.upload_name.as_str()).filter(|value| !value.is_empty());
		let content_disposition = make_content_disposition(None, content_type, filename);
		let mxc = Mxc { server_name: &server_name, media_id: &row.media_id };

		services
			.media
			.create(&mxc, user.as_deref(), Some(&content_disposition), content_type, &bytes)
			.await?;

		summary.media += 1;
	}

	Ok(())
}

async fn reset_notifications(services: &Services, users: &[OwnedUserId]) {
	for user_id in users {
		let rooms: Vec<OwnedRoomId> = services
			.state_cache
			.rooms_joined(user_id)
			.map(ToOwned::to_owned)
			.collect()
			.await;

		for room_id in rooms {
			services
				.pusher
				.reset_notification_counts(user_id, &room_id)
				.await;
		}
	}
}
