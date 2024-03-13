use bip39::{Error, Mnemonic};
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::{network::Network, bip32::{Xpub}, Address, PublicKey};
use std::convert::TryInto;
use std::str::FromStr;
use std::time::Instant;
use bitcoin::secp256k1::Secp256k1;
use crate::Address::{eth_addr_from_pub_str, tron_addr_from_pub_str};

// 获取私钥
pub fn get_private_key(seed: [u8; 64], purpose: u32,coin_type: u32) -> Xpriv {
    let secp = Secp256k1::new();

    let master = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    // println!("bip32根密钥 {}", master.to_string());

    let path = vec![
        ChildNumber::Hardened {index:purpose},
        ChildNumber::Hardened {index:coin_type},
        ChildNumber::Hardened {index:0},
        ChildNumber::Normal {index:0},
        ChildNumber::Normal {index:0},
    ];

    let private_key = master.derive_priv(&secp, &path).unwrap();
    return private_key;
}

// 根据私钥获取公钥
pub fn get_public_key(private_key: Xpriv) -> Xpub {
    let secp = Secp256k1::new();
    // Xpub::from_private(&secp, &private_key)
    Xpub::from_priv(&secp, &private_key)
}

// 根据助记词获取b2pkh类型的btc地址
pub fn btc_addr_p2pkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,0);
    let pubkey = get_public_key(private_key);
    let str = pubkey.to_pub().to_string();
    let public_key = PublicKey::from_str(str.as_str()).unwrap();
    return  Address::p2pkh(&public_key, Network::Bitcoin).to_string();
}

// 根据助记词获取p2shwpkh类型的btc地址
pub fn btc_addr_p2shwpkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 49,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2shwpkh(&pubkey.to_pub(), Network::Bitcoin).unwrap().to_string();

}
// 根据助记词获取p2wpkh类型的btc地址
pub fn btc_addr_p2wpkh(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 84,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2wpkh(&pubkey.to_pub(), Network::Bitcoin).unwrap().to_string();
}

// 根据助记词获得以太私钥
pub fn eth_private(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,60);
    // let pubkey = get_public_key(private_key);
    // let secp = Secp256k1::new();
    // println!("子私钥 {}", private_key.private_key.key.to_string());
    // println!("子公钥 {}", private_key.private_key.public_key(&secp).to_string());
    // return private_key.private_key.key.to_string();
    return hex::encode(private_key.private_key.as_ref())
}

// 根据助记词获取p2pkh_类型的btc地址
pub fn btc_p2pkh_addr_from_mnemonic(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,0);
    let pubkey = get_public_key(private_key);
    let str = pubkey.to_pub().to_string();
    // println!("pub_key:: {}", str.clone());
    let public_key = PublicKey::from_str(str.as_str()).unwrap();
    return  Address::p2pkh(&public_key, Network::Bitcoin).to_string();
}

// 根据助记词获取p2shwpkh类型的btc地址
pub fn btc_p2shwpkh_addr_from_mnemonic(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 49,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2shwpkh(&pubkey.to_pub(), Network::Bitcoin).unwrap().to_string();

}

// 根据助记词获取p2wpkh类型的btc地址
pub fn btc_p2wpkh_addr_from_mnemonic(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 84,0);
    let pubkey = get_public_key(private_key);
    return  Address::p2wpkh(&pubkey.to_pub(), Network::Bitcoin).unwrap().to_string();
}

// 根据助记词获取eth地址
pub fn eth_addr_from_mnemonic(mnemonic: &str) -> String {
    let start_time = Instant::now();

    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,60);
    let pubkey = get_public_key(private_key);
    let secp = Secp256k1::new();
    // println!("子私钥 {}", private_key.private_key.key.to_string());
    // println!("子公钥 {}", private_key.private_key.public_key(&secp).to_string());
    // return private_key.private_key.key.to_string();
    // return hex::encode(private_key.private_key.as_ref())
    let pub_key_str = private_key.private_key.public_key(&secp).to_string();
     let str = eth_addr_from_pub_str(pub_key_str.as_str());
    println!("time: {}", start_time.elapsed().as_micros());
    return str;
}

// 根据助记词获取tron地址
pub fn tron_addr_from_mnemonic(mnemonic: &str) -> String {
    let mn = Mnemonic::parse_normalized(mnemonic);
    let seed = mn.unwrap().to_seed("");
    let private_key = get_private_key(seed, 44,195);
    let secp = Secp256k1::new();
    let pub_key_str = private_key.private_key.public_key(&secp).to_string();
    tron_addr_from_pub_str(pub_key_str.as_str())
}

// 根据字符串得到助记词
fn get_mnemonic(mnemonic: &str) -> Result<Mnemonic, Error> {
    return Mnemonic::parse_normalized(&mnemonic);
}

#[cfg(test)]
pub mod tests {

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
    fn test_eth_private() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = eth_private(mn);
        assert_eq!(addr, "ff4d431538ee621168a8063e640653b2413ff4dbb519f954748d5eef669a6347")
    }

    use crate::wallet::{btc_addr_p2pkh, btc_addr_p2shwpkh, btc_addr_p2wpkh, eth_addr_from_mnemonic, eth_private, get_mnemonic, get_private_key, get_public_key, tron_addr_from_mnemonic};

    #[test]
    fn test_get_private_key() {
        let test_mnemonic_phrase: &str =
            "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let test_seed = get_mnemonic(test_mnemonic_phrase)
            .unwrap()
            .to_seed("");
        println!("bip39种子(seed): {:?}", hex::encode(test_seed));

        // 获取扩展私钥
        let private_key = get_private_key(test_seed,44,0);
        println!("扩展密钥 {}", private_key.to_string());
        // println!("子私钥 {}", private_key.private_key.to_string());

        assert_eq!(
            private_key.to_priv().to_string(),
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

        let private_key = get_private_key(test_seed, 44,0);

        let public_key = get_public_key(private_key);
        assert_eq!(
            "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded",
            public_key.public_key.to_string()
        );
    }

    #[test]
    fn test_eth_addr_from_mnemonic() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = eth_addr_from_mnemonic(mn);
        assert_eq!(addr, "0x24A6eE07E3D55b2552051cfb1AB9b4F34f34Add7".to_lowercase());
    }

    #[test]
    fn test_tron_addr_from_mnemonic() {
        let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
        let addr = tron_addr_from_mnemonic(mn);
        assert_eq!(addr, "TTAKsCvL9GjHzgADxQZEn5Lhd4UsMqay5a");
    }
}
