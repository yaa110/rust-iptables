extern crate iptables;

use std::panic;

#[test]
fn test_new() {
    nat(iptables::new(false).unwrap(), "NATNEW", "NATNEW2");
    filter(iptables::new(false).unwrap(), "FILTERNEW");
}

#[test]
fn test_old() {
    nat(iptables::IPTables{
        cmd: "iptables",
        has_wait: false,
        has_check: false,
    }, "NATOLD", "NATOLD2");

    filter(iptables::IPTables{
        cmd: "iptables",
        has_wait: false,
        has_check: false,
    }, "FILTEROLD");
}

fn nat(ipt: iptables::IPTables, old_name: &str, new_name: &str) {
    assert_eq!(ipt.new_chain("nat", old_name).unwrap(), true);
    assert_eq!(ipt.rename_chain("nat", old_name, new_name).unwrap(), true);
    assert_eq!(ipt.append("nat", new_name, "-j ACCEPT").unwrap(), true);
    assert_eq!(ipt.exists("nat", new_name, "-j ACCEPT").unwrap(), true);
    assert_eq!(ipt.delete("nat", new_name, "-j ACCEPT").unwrap(), true);
    assert_eq!(ipt.insert("nat", new_name, "-j ACCEPT", 1).unwrap(), true);
    assert_eq!(ipt.append("nat", new_name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.exists("nat", new_name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.append("nat", new_name, "-m comment --comment 'single-quoted comment' -j ACCEPT").unwrap(), true);
    // The following `exists`-check has to use double-quotes, since the iptables output (if it
    // doesn't have the check-functionality) will use double quotes.
    assert_eq!(ipt.exists("nat", new_name, "-m comment --comment \"single-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.flush_chain("nat", new_name).unwrap(), true);
    assert_eq!(ipt.exists("nat", new_name, "-j ACCEPT").unwrap(), false);
    assert!(ipt.execute("nat", &format!("-A {} -j ACCEPT", new_name)).is_ok());
    assert_eq!(ipt.exists("nat", new_name, "-j ACCEPT").unwrap(), true);
    assert_eq!(ipt.flush_chain("nat", new_name).unwrap(), true);
    assert_eq!(ipt.chain_exists("nat", new_name).unwrap(), true);
    assert_eq!(ipt.delete_chain("nat", new_name).unwrap(), true);
    assert_eq!(ipt.chain_exists("nat", new_name).unwrap(), false);
}

fn filter(ipt: iptables::IPTables, name: &str) {
    assert_eq!(ipt.new_chain("filter", name).unwrap(), true);
    assert_eq!(ipt.insert("filter", name, "-j ACCEPT", 1).unwrap(), true);
    assert_eq!(ipt.replace("filter", name, "-j DROP", 1).unwrap(), true);
    assert_eq!(ipt.exists("filter", name, "-j DROP").unwrap(), true);
    assert_eq!(ipt.exists("filter", name, "-j ACCEPT").unwrap(), false);
    assert_eq!(ipt.delete("filter", name, "-j DROP").unwrap(), true);
    assert_eq!(ipt.list("filter", name).unwrap().len(), 1);
    assert!(ipt.execute("filter", &format!("-A {} -j ACCEPT", name)).is_ok());
    assert_eq!(ipt.exists("filter", name, "-j ACCEPT").unwrap(), true);
    assert_eq!(ipt.append("filter", name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.exists("filter", name, "-m comment --comment \"double-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.append("filter", name, "-m comment --comment 'single-quoted comment' -j ACCEPT").unwrap(), true);
    // The following `exists`-check has to use double-quotes, since the iptables output (if it
    // doesn't have the check-functionality) will use double quotes.
    assert_eq!(ipt.exists("filter", name, "-m comment --comment \"single-quoted comment\" -j ACCEPT").unwrap(), true);
    assert_eq!(ipt.flush_chain("filter", name).unwrap(), true);
    assert_eq!(ipt.chain_exists("filter", name).unwrap(), true);
    assert_eq!(ipt.delete_chain("filter", name).unwrap(), true);
    assert_eq!(ipt.chain_exists("filter", name).unwrap(), false);
}

#[test]
fn test_get_policy() {
    let ipt = iptables::new(false).unwrap();

    // filter
    assert!(ipt.get_policy("filter", "INPUT").is_ok());
    assert!(ipt.get_policy("filter", "FORWARD").is_ok());
    assert!(ipt.get_policy("filter", "OUTPUT").is_ok());
    // mangle
    assert!(ipt.get_policy("mangle", "PREROUTING").is_ok());
    assert!(ipt.get_policy("mangle", "OUTPUT").is_ok());
    assert!(ipt.get_policy("mangle", "INPUT").is_ok());
    assert!(ipt.get_policy("mangle", "FORWARD").is_ok());
    assert!(ipt.get_policy("mangle", "POSTROUTING").is_ok());
    // nat
    assert!(ipt.get_policy("nat", "PREROUTING").is_ok());
    assert!(ipt.get_policy("nat", "POSTROUTING").is_ok());
    assert!(ipt.get_policy("nat", "OUTPUT").is_ok());
    // raw
    assert!(ipt.get_policy("raw", "PREROUTING").is_ok());
    assert!(ipt.get_policy("raw", "OUTPUT").is_ok());
    // security
    assert!(ipt.get_policy("security", "INPUT").is_ok());
    assert!(ipt.get_policy("security", "OUTPUT").is_ok());
    assert!(ipt.get_policy("security", "FORWARD").is_ok());

    // Wrong table
    assert!(ipt.get_policy("not_existant", "_").is_err());
    // Wrong chain
    assert!(ipt.get_policy("filter", "_").is_err());
}

#[test]
#[ignore]
fn test_set_policy() {
    let ipt = iptables::new(false).unwrap();

    // Since we can only set policies on built-in chains, we have to retain the policy of the chain
    // before setting it, to restore it to its original state.
    let current_policy = ipt.get_policy("mangle", "FORWARD").unwrap();

    // If the following assertions fail or any other panic occurs, we still have to ensure not to
    // change the policy for the user.
    let result = panic::catch_unwind(|| {
        assert_eq!(ipt.set_policy("mangle", "FORWARD", "DROP").unwrap(), true);
        assert_eq!(ipt.get_policy("mangle", "FORWARD").unwrap(), "DROP");
    });

    // Reset the policy to the retained value
    ipt.set_policy("mangle", "FORWARD", &current_policy).unwrap();

    // "Rethrow" a potential caught panic
    assert!(result.is_ok());
}
