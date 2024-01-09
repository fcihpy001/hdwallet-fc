use bip39::{Error, Mnemonic};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{
    network::constants::Network,
    util::bip32::{DerivationPath, ExtendedPubKey},
    Address,
};
use hdpath::{AccountHDPath, Purpose, StandardHDPath};
use secp256k1::Secp256k1;
use std::convert::TryInto;

pub fn get_private_key(seed: [u8; 64], hd_path: &StandardHDPath) -> ExtendedPrivKey {
    let secp = Secp256k1::new();

    let master = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    println!("bip32根密钥 {}", master.to_string());
    let private_key = master
        .derive_priv(&secp, &DerivationPath::from(hd_path))
        .unwrap();
    return private_key;
}

#[test]
fn test_get_private_key() {
    let test_mnemonic_phrase: &str =
        "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let test_seed = self::get_mnemonic(test_mnemonic_phrase)
        .unwrap()
        .to_seed("");
    println!("bip39种子(seed): {:?}", hex::encode(test_seed));

    let hd_path = AccountHDPath::new(Purpose::Pubkey, 0, 0)
        .address_at(0, 0)
        .unwrap();
    let seed_byte = hex::decode(hex::encode(test_seed)).unwrap();
    // 获取扩展私钥
    let private_key = get_private_key(test_seed, &hd_path);
    println!("子私钥 {}", private_key.private_key.to_string());

    assert_eq!(
        private_key.private_key.to_string(),
        "L3sQh1LbgjxxsGW9hgSskg87MaMJWGcp4Pf8acAjbbeFSNBrPVC4"
    )
}

pub fn get_public_key(private_key: ExtendedPrivKey) -> ExtendedPubKey {
    let secp = Secp256k1::new();
    ExtendedPubKey::from_private(&secp, &private_key)
}

#[test]
fn test_get_public_key() {
    let test_mnemonic_phrase: &str =
        "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let test_seed = self::get_mnemonic(test_mnemonic_phrase)
        .unwrap()
        .to_seed("");

    let hd_path = AccountHDPath::new(Purpose::Pubkey, 0, 0)
        .address_at(0, 0)
        .unwrap();
    let private_key = get_private_key(test_seed, &hd_path);

    let public_key = get_public_key(private_key);
    assert_eq!(
        "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded",
        public_key.public_key.to_string()
    );
}

pub fn pubkey_address(pubkey: ExtendedPubKey) -> [(&'static str, String); 3] {
    let p2pkh: String = Address::p2pkh(&pubkey.public_key, Network::Bitcoin).to_string();

    let p2wpkh: String = Address::p2wpkh(&pubkey.public_key, Network::Bitcoin)
        .unwrap()
        .to_string();

    let p2shwpkh: String = Address::p2shwpkh(&pubkey.public_key, Network::Bitcoin)
        .unwrap()
        .to_string();

    [("p2pkh", p2pkh), ("p2wpkh", p2wpkh), ("p2shwpkh", p2shwpkh)]
}

//
#[test]
fn test_pubkey_address() {
    let test_mnemonic_phrase: &str =
        "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let test_seed = self::get_mnemonic(test_mnemonic_phrase)
        .unwrap()
        .to_seed("");

    let hd_path = AccountHDPath::new(Purpose::Pubkey, 0, 0)
        .address_at(0, 0)
        .unwrap();
    let private_key = get_private_key(test_seed, &hd_path);

    let public_key = get_public_key(private_key);

    let expected_results = [
        ["p2pkh", "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1"],
        ["p2wpkh", "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca"],
        ["p2shwpkh", "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9"],
    ];
    let addresses = pubkey_address(public_key);
    for (i, address) in IntoIterator::into_iter(addresses).enumerate() {
        assert_eq!(expected_results[i][0], address.0);
        assert_eq!(expected_results[i][1], address.1);
    }
}

fn get_mnemonic(mnemonic: &str) -> Result<Mnemonic, Error> {
    return Mnemonic::parse_normalized(&mnemonic);
}
