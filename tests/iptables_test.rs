extern crate iptables;

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
    assert_eq!(ipt.flush_chain("nat", new_name).unwrap(), true);
    assert_eq!(ipt.exists("nat", new_name, "-j ACCEPT").unwrap(), false);
    assert_eq!(ipt.delete_chain("nat", new_name).unwrap(), true);
}

fn filter(ipt: iptables::IPTables, name: &str) {
    let chains_start = ipt.list_chains("filter").unwrap();
    let table_start = ipt.list_table("filter").unwrap();
    assert_eq!(ipt.new_chain("filter", name).unwrap(), true);
    assert_eq!(ipt.insert("filter", name, "-j ACCEPT", 1).unwrap(), true);
    assert_eq!(ipt.replace("filter", name, "-j DROP", 1).unwrap(), true);
    assert_eq!(ipt.exists("filter", name, "-j DROP").unwrap(), true);
    assert_eq!(ipt.exists("filter", name, "-j ACCEPT").unwrap(), false);
    assert_eq!(ipt.delete("filter", name, "-j DROP").unwrap(), true);
    assert_eq!(ipt.list("filter", name).unwrap().len(), 1);
    assert_eq!(ipt.delete_chain("filter", name).unwrap(), true);
    assert_eq!(ipt.list_table("filter").unwrap(), table_start);
    assert_eq!(ipt.list_chains("filter").unwrap(), chains_start);
}
