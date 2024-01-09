use bip39::{Error, Mnemonic};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::{network::constants::Network, util::bip32::{DerivationPath, ExtendedPubKey}, Address, PublicKey};
use hdpath::{AccountHDPath, Purpose, StandardHDPath};
use secp256k1::Secp256k1;
use std::convert::TryInto;

pub fn get_private_key(seed: [u8; 64], purpose: u32,coin_type: u32) -> ExtendedPrivKey {
    let secp = Secp256k1::new();

    let master = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    // println!("bip32根密钥 {}", master.to_string());

    let path = vec![
        ChildNumber::Hardened {index:purpose},
        ChildNumber::Hardened {index:coin_type},
        ChildNumber::Hardened {index:0},
        ChildNumber::Normal {index:0},
        ChildNumber::Normal {index:0},
    ];

    let private_key = master
        .derive_priv(&secp, &path)
        .unwrap();
    // println!("扩展私钥 {}", private_key.to_string());
    return private_key;
}


pub fn get_public_key(private_key: ExtendedPrivKey) -> ExtendedPubKey {
    let secp = Secp256k1::new();
    ExtendedPubKey::from_private(&secp, &private_key)
}


pub fn btc_addr_p2pkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2pkh(&pubkey.public_key, Network::Bitcoin).to_string();

}

pub fn btc_addr_p2shwpkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 49,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2shwpkh(&pubkey.public_key, Network::Bitcoin).unwrap().to_string();

}

pub fn btc_addr_p2wpkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 84,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2wpkh(&pubkey.public_key, Network::Bitcoin).unwrap().to_string();
}

pub fn eth_private(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,60);
    let pubkey = get_public_key(private_key);
    // let secp = Secp256k1::new();
    // println!("子私钥 {}", private_key.private_key.key.to_string());
    // println!("子公钥 {}", private_key.private_key.public_key(&secp).to_string());
    return private_key.private_key.key.to_string();
}

#[cfg(test)]
pub mod tests {
    use hdpath::{AccountHDPath, Purpose};
    use crate::wallet::{btc_addr_p2pkh, btc_addr_p2shwpkh, btc_addr_p2wpkh, eth_addr, get_mnemonic, get_private_key, get_public_key};

    #[test]
    fn test_p2p2kh_addr() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = btc_addr_p2pkh(mn);
        assert_eq!(addr, "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1")
    }

    #[test]
    fn test_p2shwpkh_addr() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = btc_addr_p2shwpkh(mn);
        assert_eq!(addr, "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9")
    }


    #[test]
    fn test_p2wpkh_addr() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = btc_addr_p2wpkh(mn);
        assert_eq!(addr, "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca")
    }

    #[test]
    fn test_eth_addr() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = eth_addr(mn);
        assert_eq!(addr, "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca")
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
        let private_key = get_private_key(test_seed,44,0);
        println!("子私钥 {}", private_key.private_key.to_string());

        assert_eq!(
            private_key.private_key.to_string(),
            "L3sQh1LbgjxxsGW9hgSskg87MaMJWGcp4Pf8acAjbbeFSNBrPVC4"
        )
    }

    #[test]
    fn test_get_public_key() {
        let test_mnemonic_phrase: &str =
            "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let test_seed = get_mnemonic(test_mnemonic_phrase)
            .unwrap()
            .to_seed("");

        let hd_path = AccountHDPath::new(Purpose::Pubkey, 0, 0)
            .address_at(0, 0)
            .unwrap();
        let private_key = get_private_key(test_seed, 44,0);

        let public_key = get_public_key(private_key);
        assert_eq!(
            "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded",
            public_key.public_key.to_string()
        );
    }
}

fn get_mnemonic(mnemonic: &str) -> Result<Mnemonic, Error> {
    return Mnemonic::parse_normalized(&mnemonic);
}
