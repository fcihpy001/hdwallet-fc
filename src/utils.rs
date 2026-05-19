use hex::FromHex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// 根据私钥推导出公钥
pub fn public_key(hex_64_private_key: &str) -> PublicKey {

    // 根据私钥生成加密种子
    let secp = Secp256k1::new();
    let key_byte = Vec::from_hex(hex_64_private_key).unwrap();

    let secret_key = SecretKey::from_slice(&key_byte).unwrap();

    PublicKey::from_secret_key(&secp, &secret_key)
}

fn check_private(key: Vec<u8>) -> bool {
    // 校验私钥长度
    if key.len() != 32 {
        return false;
    }

    // 校验私钥是否合法
    SecretKey::from_slice(&key).is_ok()
}

#[cfg(test)]
pub mod tests {
    use hex::FromHex;
    use crate::utils::{check_private, public_key};

    #[test]
    fn test_private_public() {
        let key = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let pub_key = public_key(key);
        assert_eq!(
            hex::encode(pub_key.serialize_uncompressed()),
            "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235"
        );
        assert_eq!(
            hex::encode(pub_key.serialize()),
            "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
        );
    }

    #[test]
    fn test_check_private_accepts_valid_32_byte_secret() {
        let key =
            Vec::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert!(check_private(key));
    }

    #[test]
    fn test_check_private_rejects_invalid_length() {
        let key = Vec::from_hex("e3b0c44298fc1c14").unwrap();
        assert!(!check_private(key));
    }

    #[test]
    fn test_check_private_rejects_zero_secret() {
        assert!(!check_private(vec![0; 32]));
    }

    #[test]
    #[should_panic]
    fn test_public_key_panics_on_invalid_private_key() {
        public_key("0000000000000000000000000000000000000000000000000000000000000000");
    }

    // #[test]
    // fn test_generate_32_byte() {
    //     let key = private_key_32_byte();
    //     // println!("key:{}", key);
    //     // assert_eq!(is_hex_string(key.as_str()), false)
    //     assert!(is_hex_string(key.as_str()));
    // }

    // #[test]
    // fn test_generate_256_bit() {
    //     let key = private_key_256_bit();
    //
    //     println!("hex: {}",hex::encode(key.clone()));
    //     assert_eq!(key.len(), 32);
    //     assert!(!is_hex_string(hex::encode(key).as_str()));
    // }
}
