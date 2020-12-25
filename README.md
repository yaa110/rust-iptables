Rust iptables
=============

[![crates.io](https://img.shields.io/crates/v/iptables.svg)](https://crates.io/crates/iptables) [![Documentation](https://img.shields.io/badge/Docs-iptables-blue.svg)](https://docs.rs/iptables) [![Build Status](https://travis-ci.org/yaa110/rust-iptables.svg)](https://travis-ci.org/yaa110/rust-iptables) [![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/yaa110/rust-iptables/blob/master/LICENSE)

This crate provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux (inspired by [go-iptables](https://github.com/coreos/go-iptables)). This crate uses iptables binary to manipulate chains and tables. This source code is licensed under MIT license that can be found in the LICENSE file.

```toml
[dependencies]
iptables = "0.3"
```

## Getting started
1- Import the crate `iptables` and manipulate chains:

```rust
let ipt = iptables::new(false).unwrap();

assert_eq!(ipt.new_chain("nat", "NEWCHAINNAME").unwrap(), true);
assert_eq!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
assert_eq!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
assert_eq!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
assert_eq!(ipt.delete_chain("nat", "NEWCHAINNAME").unwrap(), true);
```

For more information, please check the test file in `tests` folder.
