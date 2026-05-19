# hdwallet-fc

## 中文

### 功能介绍

`hdwallet-fc` 是一个层级确定性钱包工具库，支持从 BIP39 助记词和 secp256k1 公私钥推导常见链地址。

- 根据助记词生成 Bitcoin 地址：P2PKH、P2SH-P2WPKH、P2WPKH。
- 根据助记词生成 Ethereum 私钥和地址。
- 根据助记词生成 TRON 地址。
- 根据扩展私钥推导扩展公钥。
- 根据公钥字符串推导 Bitcoin、Ethereum、TRON 地址。
- 根据 64 位十六进制私钥推导 secp256k1 公钥。

### 支持场景和约定

- 当前地址生成均使用主网：Bitcoin Mainnet、Ethereum Mainnet 地址格式、TRON Mainnet 地址格式。
- 助记词使用 BIP39 标准解析，当前示例均使用空 passphrase。
- 助记词派生路径固定为 `m / purpose' / coin_type' / 0' / 0 / 0`，其中 `purpose` 和 `coin_type` 由具体函数决定。
- Bitcoin 地址函数对应的常用路径为：P2PKH 使用 `m/44'/0'/0'/0/0`，P2SH-P2WPKH 使用 `m/49'/0'/0'/0/0`，P2WPKH 使用 `m/84'/0'/0'/0/0`。
- Ethereum 私钥和地址使用 `m/44'/60'/0'/0/0`。
- TRON 地址使用 `m/44'/195'/0'/0/0`。
- Ethereum 地址当前返回小写十六进制地址，不做 EIP-55 checksum 格式化。
- 输入无效助记词、无效公钥或无效私钥时，当前 API 会 panic。

### 使用说明

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
hdwallet-fc = "0.2.8"
```

#### 根据助记词生成 Bitcoin P2PKH 地址

```rust
use hdwallet_fc::wallet::btc_addr_p2pkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2pkh(mnemonic);

assert_eq!(addr, "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1");
```

#### 根据助记词生成 Bitcoin P2SH-P2WPKH 地址

```rust
use hdwallet_fc::wallet::btc_addr_p2shwpkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2shwpkh(mnemonic);

assert_eq!(addr, "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9");
```

#### 根据助记词生成 Bitcoin P2WPKH 地址

```rust
use hdwallet_fc::wallet::btc_addr_p2wpkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2wpkh(mnemonic);

assert_eq!(addr, "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca");
```

也可以使用等价的助记词函数：

```rust
use hdwallet_fc::wallet::{
    btc_p2pkh_addr_from_mnemonic, btc_p2shwpkh_addr_from_mnemonic,
    btc_p2wpkh_addr_from_mnemonic,
};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";

assert_eq!(
    btc_p2pkh_addr_from_mnemonic(mnemonic),
    "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1"
);
assert_eq!(
    btc_p2shwpkh_addr_from_mnemonic(mnemonic),
    "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9"
);
assert_eq!(
    btc_p2wpkh_addr_from_mnemonic(mnemonic),
    "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca"
);
```

#### 根据助记词生成 Ethereum 私钥和地址

```rust
use hdwallet_fc::wallet::{eth_addr_from_mnemonic, eth_private};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";

let private_key = eth_private(mnemonic);
assert_eq!(
    private_key,
    "ff4d431538ee621168a8063e640653b2413ff4dbb519f954748d5eef669a6347"
);

let addr = eth_addr_from_mnemonic(mnemonic);
assert_eq!(addr, "0x24a6ee07e3d55b2552051cfb1ab9b4f34f34add7");
```

#### 根据助记词生成 TRON 地址

```rust
use hdwallet_fc::wallet::tron_addr_from_mnemonic;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = tron_addr_from_mnemonic(mnemonic);

assert_eq!(addr, "TTAKsCvL9GjHzgADxQZEn5Lhd4UsMqay5a");
```

#### 根据助记词和派生路径参数生成扩展私钥、公钥

`get_private_key(seed, purpose, coin_type)` 使用路径：

```text
m / purpose' / coin_type' / 0' / 0 / 0
```

示例：

```rust
use bip39::Mnemonic;
use hdwallet_fc::wallet::{get_private_key, get_public_key};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let seed = Mnemonic::parse_normalized(mnemonic).unwrap().to_seed("");

let private_key = get_private_key(seed, 44, 0);
assert_eq!(
    private_key.to_priv().to_string(),
    "L3sQh1LbgjxxsGW9hgSskg87MaMJWGcp4Pf8acAjbbeFSNBrPVC4"
);

let public_key = get_public_key(private_key);
assert_eq!(
    public_key.public_key.to_string(),
    "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded"
);
```

#### 根据公钥字符串生成地址

```rust
use hdwallet_fc::Address::{
    btc_p2pkh_addr_from_pub_str, btc_p2pshwpkh_addr_from_pub_str,
    btc_p2wpkh_addr_from_pub_str, eth_addr_from_pub_str, tron_addr_from_pub_str,
};

let btc_p2pkh_pub_key = "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded";
assert_eq!(
    btc_p2pkh_addr_from_pub_str(btc_p2pkh_pub_key),
    "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1"
);

let btc_p2shwpkh_pub_key = "021b1d2ed87d9ebc238f44414dfa42288cf93ab215e9ded6938745b2ce10f4f683";
assert_eq!(
    btc_p2pshwpkh_addr_from_pub_str(btc_p2shwpkh_pub_key),
    "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9"
);

let btc_p2wpkh_pub_key = "0230932da3a4b44a48cdf27ddae80031e490b96b1486980dd0cee7f617e6dae3f1";
assert_eq!(
    btc_p2wpkh_addr_from_pub_str(btc_p2wpkh_pub_key),
    "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca"
);

let eth_pub_key = "02671160d3e027c45495c567c7d101457b951a7a48483cfb156af70d9daec0c266";
assert_eq!(
    eth_addr_from_pub_str(eth_pub_key),
    "0x24a6ee07e3d55b2552051cfb1ab9b4f34f34add7"
);

let tron_pub_key = "03708cfa5ab20c3e8a9554d81f3db20a77eba98c9e050918e206ecf862f7c3682a";
assert_eq!(tron_addr_from_pub_str(tron_pub_key), "TV5x391v25E9KZMLXJcaDVdZ5XRRwKzimj");
```

#### 根据私钥推导公钥

```rust
use hdwallet_fc::utils::public_key;

let private_key = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
let pub_key = public_key(private_key);

assert_eq!(
    hex::encode(pub_key.serialize()),
    "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
);
```

## English

### Features

`hdwallet-fc` is a hierarchical deterministic wallet utility library. It derives common blockchain addresses from BIP39 mnemonics and secp256k1 public/private keys.

- Derive Bitcoin addresses from a mnemonic: P2PKH, P2SH-P2WPKH, and P2WPKH.
- Derive Ethereum private keys and addresses from a mnemonic.
- Derive TRON addresses from a mnemonic.
- Derive extended public keys from extended private keys.
- Derive Bitcoin, Ethereum, and TRON addresses from public key strings.
- Derive a secp256k1 public key from a 64-character hex private key.

### Supported Scenarios and Conventions

- Address generation currently uses mainnet formats: Bitcoin Mainnet, Ethereum Mainnet address format, and TRON Mainnet address format.
- Mnemonics are parsed with BIP39. The examples use an empty passphrase.
- Mnemonic derivation uses the fixed path `m / purpose' / coin_type' / 0' / 0 / 0`, where `purpose` and `coin_type` are selected by each function.
- Bitcoin address paths are: P2PKH uses `m/44'/0'/0'/0/0`, P2SH-P2WPKH uses `m/49'/0'/0'/0/0`, and P2WPKH uses `m/84'/0'/0'/0/0`.
- Ethereum private keys and addresses use `m/44'/60'/0'/0/0`.
- TRON addresses use `m/44'/195'/0'/0/0`.
- Ethereum addresses are returned as lowercase hex addresses, not EIP-55 checksum addresses.
- Invalid mnemonics, invalid public keys, and invalid private keys currently cause the API to panic.

### Usage

Add the crate to `Cargo.toml`:

```toml
[dependencies]
hdwallet-fc = "0.2.8"
```

#### Derive a Bitcoin P2PKH address from a mnemonic

```rust
use hdwallet_fc::wallet::btc_addr_p2pkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2pkh(mnemonic);

assert_eq!(addr, "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1");
```

#### Derive a Bitcoin P2SH-P2WPKH address from a mnemonic

```rust
use hdwallet_fc::wallet::btc_addr_p2shwpkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2shwpkh(mnemonic);

assert_eq!(addr, "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9");
```

#### Derive a Bitcoin P2WPKH address from a mnemonic

```rust
use hdwallet_fc::wallet::btc_addr_p2wpkh;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = btc_addr_p2wpkh(mnemonic);

assert_eq!(addr, "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca");
```

Equivalent mnemonic helper functions are also available:

```rust
use hdwallet_fc::wallet::{
    btc_p2pkh_addr_from_mnemonic, btc_p2shwpkh_addr_from_mnemonic,
    btc_p2wpkh_addr_from_mnemonic,
};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";

assert_eq!(
    btc_p2pkh_addr_from_mnemonic(mnemonic),
    "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1"
);
assert_eq!(
    btc_p2shwpkh_addr_from_mnemonic(mnemonic),
    "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9"
);
assert_eq!(
    btc_p2wpkh_addr_from_mnemonic(mnemonic),
    "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca"
);
```

#### Derive an Ethereum private key and address from a mnemonic

```rust
use hdwallet_fc::wallet::{eth_addr_from_mnemonic, eth_private};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";

let private_key = eth_private(mnemonic);
assert_eq!(
    private_key,
    "ff4d431538ee621168a8063e640653b2413ff4dbb519f954748d5eef669a6347"
);

let addr = eth_addr_from_mnemonic(mnemonic);
assert_eq!(addr, "0x24a6ee07e3d55b2552051cfb1ab9b4f34f34add7");
```

#### Derive a TRON address from a mnemonic

```rust
use hdwallet_fc::wallet::tron_addr_from_mnemonic;

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let addr = tron_addr_from_mnemonic(mnemonic);

assert_eq!(addr, "TTAKsCvL9GjHzgADxQZEn5Lhd4UsMqay5a");
```

#### Derive an extended private key and public key from a mnemonic

`get_private_key(seed, purpose, coin_type)` uses this path:

```text
m / purpose' / coin_type' / 0' / 0 / 0
```

Example:

```rust
use bip39::Mnemonic;
use hdwallet_fc::wallet::{get_private_key, get_public_key};

let mnemonic = "pulp gun crisp mechanic hub ahead blouse hurry life boss option evolve";
let seed = Mnemonic::parse_normalized(mnemonic).unwrap().to_seed("");

let private_key = get_private_key(seed, 44, 0);
assert_eq!(
    private_key.to_priv().to_string(),
    "L3sQh1LbgjxxsGW9hgSskg87MaMJWGcp4Pf8acAjbbeFSNBrPVC4"
);

let public_key = get_public_key(private_key);
assert_eq!(
    public_key.public_key.to_string(),
    "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded"
);
```

#### Derive addresses from public key strings

```rust
use hdwallet_fc::Address::{
    btc_p2pkh_addr_from_pub_str, btc_p2pshwpkh_addr_from_pub_str,
    btc_p2wpkh_addr_from_pub_str, eth_addr_from_pub_str, tron_addr_from_pub_str,
};

let btc_p2pkh_pub_key = "032352a1c4465934cdff949e4f0bb9a050676a9f6162ecca238612b08519bdcded";
assert_eq!(
    btc_p2pkh_addr_from_pub_str(btc_p2pkh_pub_key),
    "1NDScYSjEqrYAMGRr7DwLhwFRACqo1BCU1"
);

let btc_p2shwpkh_pub_key = "021b1d2ed87d9ebc238f44414dfa42288cf93ab215e9ded6938745b2ce10f4f683";
assert_eq!(
    btc_p2pshwpkh_addr_from_pub_str(btc_p2shwpkh_pub_key),
    "33TPM4YMjigYdFE3J1zeVk7Y3pyBgXnNT9"
);

let btc_p2wpkh_pub_key = "0230932da3a4b44a48cdf27ddae80031e490b96b1486980dd0cee7f617e6dae3f1";
assert_eq!(
    btc_p2wpkh_addr_from_pub_str(btc_p2wpkh_pub_key),
    "bc1qdk8g0wn5lnvuf6da2rxfk5922285qje3tz7dca"
);

let eth_pub_key = "02671160d3e027c45495c567c7d101457b951a7a48483cfb156af70d9daec0c266";
assert_eq!(
    eth_addr_from_pub_str(eth_pub_key),
    "0x24a6ee07e3d55b2552051cfb1ab9b4f34f34add7"
);

let tron_pub_key = "03708cfa5ab20c3e8a9554d81f3db20a77eba98c9e050918e206ecf862f7c3682a";
assert_eq!(tron_addr_from_pub_str(tron_pub_key), "TV5x391v25E9KZMLXJcaDVdZ5XRRwKzimj");
```

#### Derive a public key from a private key

```rust
use hdwallet_fc::utils::public_key;

let private_key = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
let pub_key = public_key(private_key);

assert_eq!(
    hex::encode(pub_key.serialize()),
    "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
);
```
