use std::str::FromStr;
use bitcoin::{Address, Network};
use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};

// 通过公钥推导出地址

pub fn eth_addr_from_pub_str(pub_key_str: &str) -> String {
    let pub_key = PublicKey::from_str(pub_key_str).unwrap();
    // 解析公钥为非压缩公式,并丢弃第一个字节0x04
    let pub_key_byte = pub_key.serialize_uncompressed()[1..].to_vec();

    // 对处理过的公钥进行Keccak-256 hashing
    let mut sha256_hasher = Keccak256::new();
    sha256_hasher.update(pub_key_byte);
    let output = sha256_hasher.finalize();

    let last20byte = &output[12..32];
    // 取最后20字节的数据，然后在开头拼接成0x生成钱包地址
    let addr = hex::encode(last20byte);
    format!("0x{}", addr)
}

pub fn tron_addr_from_pub_str(pub_key_str: &str) -> String {
    let pub_key = PublicKey::from_str(pub_key_str).unwrap();
    // 解析公钥为非压缩公式,并丢弃第一个字节0x04
    let pub_key_byte = pub_key.serialize_uncompressed()[1..].to_vec();

    // 对处理过的公钥进行Keccak-256 hashing
    let mut sha256_hasher = Keccak256::new();
    sha256_hasher.update(pub_key_byte);
    let output = sha256_hasher.finalize();

    let last20byte = &output[12..32];

    let mut  address = vec![0x41];
    address.extend(last20byte);
    // 取最后20字节的数据，然后在开头拼接成0x生成钱包地址
    let addr = bs58::encode(&address).with_check();
    addr.into_string()
}

pub fn btc_p2pkh_addr_from_pub_str(pub_key_str: &str) -> String {
    let pub_key = bitcoin::key::PublicKey::from_str(pub_key_str).unwrap();
    return  Address::p2pkh(&pub_key, Network::Bitcoin).to_string();
}

pub fn btc_p2pshwpkh_addr_from_pub_str(pub_key_str: &str) -> String {
    let pub_key = bitcoin::key::PublicKey::from_str(pub_key_str).unwrap();
    return  Address::p2shwpkh(&pub_key, Network::Bitcoin).unwrap().to_string();
}

pub fn btc_p2wpkh_addr_from_pub_str(pub_key_str: &str) -> String {
    let pub_key = bitcoin::key::PublicKey::from_str(pub_key_str).unwrap();
    return  Address::p2wpkh(&pub_key, Network::Bitcoin).unwrap().to_string();
}

#[cfg(test)]
pub mod tests {
    use crate::Address::{btc_p2pkh_addr_from_pub_str, btc_p2pshwpkh_addr_from_pub_str, btc_p2wpkh_addr_from_pub_str, eth_addr_from_pub_str, tron_addr_from_pub_str};

    #[test]
    fn test_p2pkh_addr() {
        let pub_key_str = "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded";
        let addr = btc_p2pkh_addr_from_pub_str(pub_key_str);
        assert_eq!(addr, "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1");
    }

    #[test]
    fn test_p2sh_addr() {
        let pub_key_str = "021b1d2ed87d9ebc238f44414dfa42288cf93ab215e9ded6938745b2ce10f4f683";
        let addr = btc_p2pshwpkh_addr_from_pub_str(pub_key_str);
        assert_eq!(addr, "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9");
    }

    #[test]
    fn test_p2wpkh_addr() {
        let pub_key_str = "0230932da3a4b44a48cdf27ddae80031e490b96b1486980dd0cee7f617e6dae3f1";
        let addr = btc_p2wpkh_addr_from_pub_str(pub_key_str);
        assert_eq!(addr, "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca");
    }

    #[test]
    fn test_eth_addr() {
        let pub_key_str = "02671160d3e027c45495c567c7d101457b951a7a48483cfb156af70d9daec0c266";
        let addr = eth_addr_from_pub_str(pub_key_str);
        assert_eq!(addr, "0x24A6eE07E3D55b2552051cfb1AB9b4F34f34Add7".to_lowercase());
    }

    #[test]
    fn test_tron_addr() {
        let pub_key_str = "03708cfa5ab20c3e8a9554d81f3db20a77eba98c9e050918e206ecf862f7c3682a";
        let addr = tron_addr_from_pub_str(pub_key_str);
        assert_eq!(addr, "TV5x391v25E9KZMLXJcaDVdZ5XRRwKzimj");
    }
}