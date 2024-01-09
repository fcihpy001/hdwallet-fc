# 功能介绍
- 根据助记词生成btc各种钱包地址
- 根据助记词生成eth私钥

* 使用方法
### 根据助记词生成p2pk2类型的钱包地址
```rust
fn test_p2p2kh_addr() {
    let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let addr = btc_addr_p2pkh(mn);
    assert_eq!(addr, "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1")
}
```

### 根据助记词生成以太系私钥
```rust
fn test_eth_private() {
    let mn = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let addr = eth_private(mn);
    assert_eq!(addr, "ff4d431538ee621168a8063e640653b2413ff4dbb519f954748d5eef669a6347")
}
```

### 根据助记词和派生路径生成对应的扩展私钥
```rust
 fn test_get_private_key() {
    let test_mnemonic_phrase: &str =
     "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
    let test_seed = self::get_mnemonic(test_mnemonic_phrase)
      .unwrap()
     .to_seed("");
    println!("bip39种子(seed): {:?}", hex::encode(test_seed));

    // 获取扩展私钥
    let private_key = get_private_key(test_seed,44,0);
    println!("扩展密钥 {}", private_key.to_string());
    println!("子私钥 {}", private_key.private_key.to_string());

    assert_eq!(
       private_key.private_key.to_string(),
     "L3sQh1LbgjxxsGW9hgSskg87MaMJWGcp4Pf8acAjbbeFSNBrPVC4"
    )
}
```

### 根据助记词和派生路径生成对应公钥
```rust
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
```