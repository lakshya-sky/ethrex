use crate::peer_handler::DumpError;
use ethrex_common::{H256, H512, U256, types::AccountState, utils::keccak};
use ethrex_rlp::encode::RLPEncode;
use secp256k1::{PublicKey, SecretKey};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::error;

/// Computes the node_id from a public key (aka computes the Keccak256 hash of the given public key)
pub fn node_id(public_key: &H512) -> H256 {
    keccak(public_key)
}

pub fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn get_msg_expiration_from_seconds(seconds: u64) -> u64 {
    (SystemTime::now() + Duration::from_secs(seconds))
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn is_msg_expired(expiration: u64) -> bool {
    // this cast to a signed integer is needed as the rlp decoder doesn't take into account the sign
    // otherwise if a msg contains a negative expiration, it would pass since as it would wrap around the u64.
    (expiration as i64) < (current_unix_time() as i64)
}

pub fn public_key_from_signing_key(signer: &SecretKey) -> H512 {
    let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, signer);
    let encoded = public_key.serialize_uncompressed();
    H512::from_slice(&encoded[1..])
}

/// Deletes the snap folders needed for downloading the leaves during the initial
/// step of snap sync.
pub fn delete_leaves_folder(datadir: &Path) {
    // We ignore the errors because this can happen when the folders don't exist
    let _ = std::fs::remove_dir_all(get_account_state_snapshots_dir(datadir));
    let _ = std::fs::remove_dir_all(get_account_storages_snapshots_dir(datadir));
    let _ = std::fs::remove_dir_all(get_code_hashes_snapshots_dir(datadir));
    #[cfg(feature = "rocksdb")]
    {
        let _ = std::fs::remove_dir_all(get_rocksdb_temp_accounts_dir(datadir));
        let _ = std::fs::remove_dir_all(get_rocksdb_temp_storage_dir(datadir));
    };
}

pub fn get_account_storages_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("account_storages_snapshots")
}

pub fn get_account_state_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("account_state_snapshots")
}

pub fn get_rocksdb_temp_accounts_dir(datadir: &Path) -> PathBuf {
    datadir.join("temp_acc_dir")
}

pub fn get_rocksdb_temp_storage_dir(datadir: &Path) -> PathBuf {
    datadir.join("temp_storage_dir")
}

pub fn get_account_state_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("account_state_chunk.rlp.{chunk_index}"))
}

pub fn get_account_storages_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("account_storages_chunk.rlp.{chunk_index}"))
}

#[cfg(feature = "rocksdb")]
pub fn dump_accounts_to_rocks_db(
    path: &Path,
    mut contents: Vec<(H256, AccountState)>,
) -> Result<(), rocksdb::Error> {
    // This can happen sometimes during download, and the sst ingestion method
    // fails with empty chunk files
    if contents.is_empty() {
        return Ok(());
    }
    contents.sort_by_key(|(k, _)| *k);
    contents.dedup_by_key(|(k, _)| {
        let mut buf = [0u8; 32];
        buf[..32].copy_from_slice(&k.0);
        buf
    });
    let mut buffer: Vec<u8> = Vec::new();
    let writer_options = rocksdb::Options::default();
    let mut writer = rocksdb::SstFileWriter::create(&writer_options);
    writer.open(std::path::Path::new(&path))?;
    for (key, account) in contents {
        buffer.clear();
        account.encode(&mut buffer);
        writer.put(key.0.as_ref(), buffer.as_slice())?;
    }
    writer.finish()
}

#[cfg(feature = "rocksdb")]
pub fn dump_storages_to_rocks_db(
    path: &Path,
    mut contents: Vec<(H256, H256, U256)>,
) -> Result<(), rocksdb::Error> {
    // This can happen sometimes during download, and the sst ingestion method
    // fails with empty chunk files
    if contents.is_empty() {
        return Ok(());
    }
    contents.sort();
    contents.dedup_by_key(|(k0, k1, _)| {
        let mut buffer = [0_u8; 64];
        buffer[0..32].copy_from_slice(&k0.0);
        buffer[32..64].copy_from_slice(&k1.0);
        buffer
    });
    let writer_options = rocksdb::Options::default();
    let mut writer = rocksdb::SstFileWriter::create(&writer_options);
    let mut buffer_key = [0_u8; 64];
    let mut buffer_storage: Vec<u8> = Vec::new();
    writer.open(std::path::Path::new(&path))?;
    for (account, slot_hash, slot_value) in contents {
        buffer_key[0..32].copy_from_slice(&account.0);
        buffer_key[32..64].copy_from_slice(&slot_hash.0);
        buffer_storage.clear();
        slot_value.encode(&mut buffer_storage);
        writer.put(buffer_key.as_ref(), buffer_storage.as_slice())?;
    }
    writer.finish()
}

pub fn get_code_hashes_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("bytecode_hashes_snapshots")
}

pub fn get_code_hashes_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("bytecode_hashes_chunk.rlp.{chunk_index}"))
}

pub fn dump_to_file(path: &Path, contents: Vec<u8>) -> Result<(), DumpError> {
    std::fs::write(path, &contents)
        .inspect_err(|err| error!(%err, ?path, "Failed to dump snapshot to file"))
        .map_err(|err| DumpError {
            path: path.to_path_buf(),
            contents,
            error: err.kind(),
        })
}

pub fn dump_accounts_to_file(
    path: &Path,
    accounts: Vec<(H256, AccountState)>,
) -> Result<(), DumpError> {
    #[cfg(feature = "rocksdb")]
    return dump_accounts_to_rocks_db(path, accounts)
        .inspect_err(|err| error!("Rocksdb writing stt error {err:?}"))
        .map_err(|_| DumpError {
            path: path.to_path_buf(),
            contents: Vec::new(),
            error: std::io::ErrorKind::Other,
        });
    #[cfg(not(feature = "rocksdb"))]
    dump_to_file(path, accounts.encode_to_vec())
}

/// Struct representing the storage slots of certain accounts that share the same storage root
pub struct AccountsWithStorage {
    /// Accounts with the same storage root
    pub accounts: Vec<H256>,
    /// All slots in the trie from the accounts
    pub storages: Vec<(H256, U256)>,
}

pub fn dump_storages_to_file(
    path: &Path,
    storages: Vec<AccountsWithStorage>,
) -> Result<(), DumpError> {
    #[cfg(feature = "rocksdb")]
    return dump_storages_to_rocks_db(
        path,
        storages
            .into_iter()
            .flat_map(|accounts_with_slots| {
                accounts_with_slots
                    .accounts
                    .into_iter()
                    .map(|hash| {
                        accounts_with_slots
                            .storages
                            .iter()
                            .map(move |(slot_hash, slot_value)| (hash, *slot_hash, *slot_value))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>(),
    )
    .inspect_err(|err| error!("Rocksdb writing stt error {err:?}"))
    .map_err(|_| DumpError {
        path: path.to_path_buf(),
        contents: Vec::new(),
        error: std::io::ErrorKind::Other,
    });

    #[cfg(not(feature = "rocksdb"))]
    dump_to_file(
        path,
        storages
            .into_iter()
            .map(|accounts_with_slots| (accounts_with_slots.accounts, accounts_with_slots.storages))
            .collect::<Vec<_>>()
            .encode_to_vec(),
    )
}

// is_valid_relay_ip reports whether an IP relayed from the given sender IP is a valid connection target.
pub fn is_valid_relay_ip(sender: IpAddr, addr: IpAddr) -> bool {
    if addr.is_unspecified() {
        return false;
    }

    if addr_is_special_network(addr) {
        return false;
    }

    if addr.is_loopback() && !sender.is_loopback() {
        return false;
    }

    if addr_is_lan(addr) && !addr_is_lan(sender) {
        return false;
    }

    true
}

pub fn addr_is_special_network(mut ip: IpAddr) -> bool {
    ip = ip.to_canonical();

    if ip.is_multicast() {
        return true;
    }

    false
}

pub fn addr_is_lan(mut ip: IpAddr) -> bool {
    ip = ip.to_canonical();

    if ip.is_loopback() {
        return true;
    }

    let is_private = match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    };

    let is_link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    };

    is_private || is_link_local
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_addr_is_lan() {
        // Test cases that should return true (LAN addresses)
        let lan_addresses = vec![
            // Loopback
            "127.0.0.1",
            // Private IPv4
            "10.0.1.1",
            "10.22.0.3",
            "172.31.252.251",
            "192.168.1.4",
            // IPv6 link-local and unique local
            "fe80::f4a1:8eff:fec5:9d9d",
            "febf::ab32:2233",
            "fc00::4",
            // IPv4-in-IPv6 (loopback and private)
            "::ffff:127.0.0.1",
            "::ffff:10.10.0.2",
        ];

        for addr_str in lan_addresses {
            let ip: IpAddr = addr_str.parse().unwrap();
            assert!(
                addr_is_lan(ip),
                "Expected {} to be identified as LAN",
                addr_str
            );
        }

        // Test cases that should return false (non-LAN addresses)
        let non_lan_addresses = vec![
            "192.0.2.1",
            "1.0.0.0",
            "172.32.0.1",
            "fec0::2233",
            // IPv4-in-IPv6 (public)
            "::ffff:88.99.100.2",
        ];

        for addr_str in non_lan_addresses {
            let ip: IpAddr = addr_str.parse().unwrap();
            assert!(
                !addr_is_lan(ip),
                "Expected {} to NOT be identified as LAN",
                addr_str
            );
        }
    }

    #[test]
    fn test_addr_is_special_network() {
        // Test cases that should return true (multicast addresses)
        let special_addresses = vec![
            // IPv4 multicast
            "224.0.0.22",
            // IPv6 multicast
            "ff05::1:3",
        ];

        for addr_str in special_addresses {
            let ip: IpAddr = addr_str.parse().unwrap();
            assert!(
                addr_is_special_network(ip),
                "Expected {} to be identified as special network",
                addr_str
            );
        }

        // Test cases that should return false (non-multicast addresses)
        let non_special_addresses = vec![
            "192.0.3.1",
            "1.0.0.0",
            "172.32.0.1",
            "fec0::2233",
            "127.0.0.1",
            "192.168.1.1",
        ];

        for addr_str in non_special_addresses {
            let ip: IpAddr = addr_str.parse().unwrap();
            assert!(
                !addr_is_special_network(ip),
                "Expected {} to NOT be identified as special network",
                addr_str
            );
        }
    }

    #[test]
    fn test_is_valid_relay_ip() {
        let test_cases = vec![
            // (sender, addr, expected_result)
            // Unspecified addresses should return false
            ("127.0.0.1", "0.0.0.0", false),
            ("192.168.0.1", "0.0.0.0", false),
            ("23.55.1.242", "0.0.0.0", false),
            // Multicast (special network) should return false
            ("127.0.0.1", "224.0.0.22", false),
            ("192.168.0.1", "224.0.0.22", false),
            ("23.55.1.242", "224.0.0.22", false),
            // Loopback from non-loopback should return false
            ("192.168.0.1", "127.0.2.19", false),
            // LAN from non-LAN should return false
            ("23.55.1.242", "192.168.0.1", false),
            // Valid cases should return true
            // Loopback to loopback is OK
            ("127.0.0.1", "127.0.2.19", true),
            // Loopback to LAN is OK
            ("127.0.0.1", "192.168.0.1", true),
            // Loopback to public is OK
            ("127.0.0.1", "23.55.1.242", true),
            // LAN to LAN is OK
            ("192.168.0.1", "192.168.0.1", true),
            // LAN to public is OK
            ("192.168.0.1", "23.55.1.242", true),
            // Public to public is OK
            ("23.55.1.242", "23.55.1.242", true),
        ];

        for (sender_str, addr_str, expected) in test_cases {
            let sender: IpAddr = sender_str.parse().unwrap();
            let addr: IpAddr = addr_str.parse().unwrap();
            let result = is_valid_relay_ip(sender, addr);
            assert_eq!(
                result, expected,
                "is_valid_relay_ip({}, {}) returned {:?}, expected {:?}",
                sender_str, addr_str, result, expected
            );
        }
    }
}
