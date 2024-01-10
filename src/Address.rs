use bitcoin::{Address, Network, PublicKey};
use sha3::Keccak256;

// 通过公钥推导出地址

fn eth_addr(pub_key: PublicKey) -> String {
    // // 解析公钥为非压缩公式,并丢弃第一个字节0x04
    // let pub_key_byte = pub_key.serialize_uncompressed()[1..].to_vec();
    //
    // // 对处理过的公钥进行Keccak-256 hashing
    // let mut sha256_hasher = Keccak256::new();
    // sha256_hasher.update(pub_key_byte);
    // let output = sha256_hasher.finalize();
    //
    // let last20byte = &output[12..32];
    // // 取最后20字节的数据，然后在开头拼接成0x生成钱包地址
    // let addr = hex::encode(last20byte);
    // format!("0x{}", addr).to_lowercase()
    "".to_string()
}

fn tron_addr(pub_key: PublicKey) -> String {
    // // 解析公钥为非压缩公式,并丢弃第一个字节0x04
    // let pub_key_byte = pub_key.serialize_uncompressed()[1..].to_vec();
    //
    // // 对处理过的公钥进行Keccak-256 hashing
    // let mut sha256_hasher = Keccak256::new();
    // sha256_hasher.update(pub_key_byte);
    // let output = sha256_hasher.finalize();
    //
    // let last20byte = &output[12..32];
    //
    // let mut  address = vec![0x41];
    // address.extend(last20byte);
    // // 取最后20字节的数据，然后在开头拼接成0x生成钱包地址
    // let addr = bs58::encode(&address).with_check();
    // addr.into_string().to_lowercase()
    "".to_string()
}

fn btc_p2pkh_addr(pub_key: PublicKey) -> String {
    return  Address::p2pkh(&pub_key, Network::Bitcoin).to_string().to_lowercase();
}

fn btc_p2pshwpkh_addr(pub_key: PublicKey) -> String {
    return  Address::p2shwpkh(&pub_key, Network::Bitcoin).unwrap().to_string().to_lowercase();
}

fn btc_p2pwkh_addr(pub_key: PublicKey) -> String {
    return  Address::p2wpkh(&pub_key, Network::Bitcoin).unwrap().to_string().to_lowercase();
}