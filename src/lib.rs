// In the name of Allah

//! Provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux.
//! This crate uses iptables binary to manipulate chains and tables.
//! This source code is licensed under MIT license that can be found in the LICENSE file.
//!
//! # Example
//! ```
//! extern crate iptables;
//!
//! fn main() {
//!     let ipt = iptables::new(false).unwrap();
//!     assert_eq!(ipt.new_chain("nat", "NEWCHAINNAME").unwrap(), true);
//!     assert_eq!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
//!     assert_eq!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
//!     assert_eq!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap(), true);
//!     assert_eq!(ipt.delete_chain("nat", "NEWCHAINNAME").unwrap(), true);
//! }
//! ```

#[macro_use]
extern crate lazy_static;
extern crate nix;
extern crate regex;

pub mod error;

use error::{IPTError, IPTResult};
use nix::fcntl::{flock, FlockArg};
use regex::{Match, Regex};
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Output};
use std::vec::Vec;

// List of built-in chains taken from: man 8 iptables
const BUILTIN_CHAINS_FILTER: &'static [&'static str] = &["INPUT", "FORWARD", "OUTPUT"];
const BUILTIN_CHAINS_MANGLE: &'static [&'static str] =
    &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"];
const BUILTIN_CHAINS_NAT: &'static [&'static str] = &["PREROUTING", "POSTROUTING", "OUTPUT"];
const BUILTIN_CHAINS_RAW: &'static [&'static str] = &["PREROUTING", "OUTPUT"];
const BUILTIN_CHAINS_SECURITY: &'static [&'static str] = &["INPUT", "OUTPUT", "FORWARD"];

lazy_static! {
    static ref RE_SPLIT: Regex = Regex::new(r#"["'].+?["']|[^ ]+"#).unwrap();
}

trait SplitQuoted {
    fn split_quoted(&self) -> Vec<&str>;
}

impl SplitQuoted for str {
    fn split_quoted(&self) -> Vec<&str> {
        RE_SPLIT
            // Iterate over matched segments
            .find_iter(self)
            // Get match as str
            .map(|m| Match::as_str(&m))
            // Remove any surrounding quotes (they will be reinserted by `Command`)
            .map(|s| s.trim_matches(|c| c == '"' || c == '\''))
            // Collect
            .collect::<Vec<_>>()
    }
}

fn get_builtin_chains(table: &str) -> IPTResult<&[&str]> {
    match table {
        "filter" => Ok(BUILTIN_CHAINS_FILTER),
        "mangle" => Ok(BUILTIN_CHAINS_MANGLE),
        "nat" => Ok(BUILTIN_CHAINS_NAT),
        "raw" => Ok(BUILTIN_CHAINS_RAW),
        "security" => Ok(BUILTIN_CHAINS_SECURITY),
        _ => Err(IPTError::Other("given table is not supported by iptables")),
    }
}

/// Contains the iptables command and shows if it supports -w and -C options.
/// Use `new` method to create a new instance of this struct.
pub struct IPTables {
    /// The utility command which must be 'iptables' or 'ip6tables'.
    pub cmd: &'static str,

    /// Indicates if iptables has -C (--check) option
    pub has_check: bool,

    /// Indicates if iptables has -w (--wait) option
    pub has_wait: bool,
}

/// Returns `None` because iptables only works on linux
#[cfg(not(target_os = "linux"))]
pub fn new(is_ipv6: bool) -> IPTResult<IPTables> {
    Err(IPTError::Other("iptables only works on Linux"))
}

/// Creates a new `IPTables` Result with the command of 'iptables' if `is_ipv6` is `false`, otherwise the command is 'ip6tables'.
#[cfg(target_os = "linux")]
pub fn new(is_ipv6: bool) -> IPTResult<IPTables> {
    let cmd = if is_ipv6 { "ip6tables" } else { "iptables" };

    let version_output = Command::new(cmd).arg("--version").output()?;
    let re = Regex::new(r"v(\d+)\.(\d+)\.(\d+)")?;
    let version_string = String::from_utf8_lossy(&version_output.stdout).into_owned();
    let versions = re
        .captures(&version_string)
        .ok_or("invalid version number")?;
    let v_major = versions
        .get(1)
        .ok_or("unable to get major version number")?
        .as_str()
        .parse::<i32>()?;
    let v_minor = versions
        .get(2)
        .ok_or("unable to get minor version number")?
        .as_str()
        .parse::<i32>()?;
    let v_patch = versions
        .get(3)
        .ok_or("unable to get patch version number")?
        .as_str()
        .parse::<i32>()?;

    Ok(IPTables {
        cmd: cmd,
        has_check: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 10),
        has_wait: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 19),
    })
}

impl IPTables {
    /// Get the default policy for a table/chain.
    pub fn get_policy(&self, table: &str, chain: &str) -> IPTResult<String> {
        let builtin_chains = get_builtin_chains(table)?;
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(IPTError::Other(
                "given chain is not a default chain in the given table, can't get policy",
            ));
        }

        let output =
            String::from_utf8_lossy(&self.run(&["-t", table, "-L", chain])?.stdout).into_owned();
        for item in output.trim().split("\n") {
            let fields = item.split(" ").collect::<Vec<&str>>();
            if fields.len() > 1 && fields[0] == "Chain" && fields[1] == chain {
                return Ok(fields[3].replace(")", ""));
            }
        }
        Err(IPTError::Other(
            "could not find the default policy for table and chain",
        ))
    }

    /// Set the default policy for a table/chain.
    pub fn set_policy(&self, table: &str, chain: &str, policy: &str) -> IPTResult<()> {
        let builtin_chains = get_builtin_chains(table)?;
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(IPTError::Other(
                "given chain is not a default chain in the given table, can't set policy",
            ));
        }

        match self.run(&["-t", table, "-P", chain, policy]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Executes a given `command` on the chain.
    /// Returns the command output if successful.
    pub fn execute(&self, table: &str, command: &str) -> IPTResult<Output> {
        self.run(&[&["-t", table], command.split_quoted().as_slice()].concat())
    }

    /// Checks for the existence of the `rule` in the table/chain.
    /// Returns true if the rule exists.
    #[cfg(target_os = "linux")]
    pub fn exists(&self, table: &str, chain: &str, rule: &str) -> IPTResult<bool> {
        if !self.has_check {
            return self.exists_old_version(table, chain, rule);
        }

        match self.run(&[&["-t", table, "-C", chain], rule.split_quoted().as_slice()].concat()) {
            Ok(_) => Ok(true),
            Err(IPTError::BadExitStatus(1)) => Ok(false),
            Err(IPTError::BadExitStatus(2)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Checks for the existence of the `chain` in the table.
    /// Returns true if the chain exists.
    #[cfg(target_os = "linux")]
    pub fn chain_exists(&self, table: &str, chain: &str) -> IPTResult<bool> {
        match self.run(&["-t", table, "-L", chain]) {
            Ok(_) => Ok(true),
            Err(IPTError::BadExitStatus(1)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Inserts `rule` in the `position` to the table/chain.
    /// Returns `true` if the rule is inserted.
    pub fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> IPTResult<()> {
        match self.run(
            &[
                &["-t", table, "-I", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Inserts `rule` in the `position` to the table/chain if it does not exist.
    /// Returns `true` if the rule is inserted.
    pub fn insert_unique(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
        position: i32,
    ) -> IPTResult<()> {
        if self.exists(table, chain, rule)? {
            return Err(IPTError::Other("the rule exists in the table/chain"));
        }

        self.insert(table, chain, rule, position)
    }

    /// Replaces `rule` in the `position` to the table/chain.
    /// Returns `true` if the rule is replaced.
    pub fn replace(&self, table: &str, chain: &str, rule: &str, position: i32) -> IPTResult<()> {
        match self.run(
            &[
                &["-t", table, "-R", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Appends `rule` to the table/chain.
    /// Returns `true` if the rule is appended.
    pub fn append(&self, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
        match self.run(&[&["-t", table, "-A", chain], rule.split_quoted().as_slice()].concat()) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Appends `rule` to the table/chain if it does not exist.
    /// Returns `true` if the rule is appended.
    pub fn append_unique(&self, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
        if self.exists(table, chain, rule)? {
            return Err(IPTError::Other("the rule exists in the table/chain"));
        }

        self.append(table, chain, rule)
    }

    /// Appends or replaces `rule` to the table/chain if it does not exist.
    /// Returns `true` if the rule is appended or replaced.
    pub fn append_replace(&self, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
        if self.exists(table, chain, rule)? {
            self.delete(table, chain, rule)?;
        }

        self.append(table, chain, rule)
    }

    /// Deletes `rule` from the table/chain.
    /// Returns `true` if the rule is deleted.
    pub fn delete(&self, table: &str, chain: &str, rule: &str) -> IPTResult<()> {
        match self.run(&[&["-t", table, "-D", chain], rule.split_quoted().as_slice()].concat()) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Deletes all repetition of the `rule` from the table/chain.
    /// Returns `true` if the rules are deleted.
    pub fn delete_all(&self, table: &str, chain: &str, rule: &str) -> IPTResult<bool> {
        while self.exists(table, chain, rule)? {
            self.delete(table, chain, rule)?;
        }
        Ok(true)
    }

    /// Lists rules in the table/chain.
    pub fn list(&self, table: &str, chain: &str) -> IPTResult<Vec<String>> {
        self.get_list(&["-t", table, "-S", chain])
    }

    /// Lists rules in the table.
    pub fn list_table(&self, table: &str) -> IPTResult<Vec<String>> {
        self.get_list(&["-t", table, "-S"])
    }

    /// Lists the name of each chain in the table.
    pub fn list_chains(&self, table: &str) -> IPTResult<Vec<String>> {
        let mut list = Vec::new();
        let output = String::from_utf8_lossy(&self.run(&["-t", table, "-S"])?.stdout).into_owned();
        for item in output.trim().split("\n") {
            let fields = item.split(" ").collect::<Vec<&str>>();
            if fields.len() > 1 && (fields[0] == "-P" || fields[0] == "-N") {
                list.push(fields[1].to_string());
            }
        }
        Ok(list)
    }

    /// Creates a new user-defined chain.
    /// Returns `true` if the chain is created.
    pub fn new_chain(&self, table: &str, chain: &str) -> IPTResult<()> {
        match self.run(&["-t", table, "-N", chain]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Flushes (deletes all rules) a chain.
    /// Returns `true` if the chain is flushed.
    pub fn flush_chain(&self, table: &str, chain: &str) -> IPTResult<()> {
        match self.run(&["-t", table, "-F", chain]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Renames a chain in the table.
    /// Returns `true` if the chain is renamed.
    pub fn rename_chain(&self, table: &str, old_chain: &str, new_chain: &str) -> IPTResult<()> {
        match self.run(&["-t", table, "-E", old_chain, new_chain]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Deletes a user-defined chain in the table.
    /// Returns `true` if the chain is deleted.
    pub fn delete_chain(&self, table: &str, chain: &str) -> IPTResult<()> {
        match self.run(&["-t", table, "-X", chain]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Flushes all chains in a table.
    /// Returns `true` if the chains are flushed.
    pub fn flush_table(&self, table: &str) -> IPTResult<()> {
        match self.run(&["-t", table, "-F"]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn exists_old_version(&self, table: &str, chain: &str, rule: &str) -> IPTResult<bool> {
        match self.run(&["-t", table, "-S"]) {
            Ok(output) => Ok(String::from_utf8_lossy(&output.stdout)
                .into_owned()
                .contains(&format!("-A {} {}", chain, rule))),
            Err(err) => Err(err),
        }
    }

    fn get_list<S: AsRef<OsStr>>(&self, args: &[S]) -> IPTResult<Vec<String>> {
        let mut list = Vec::new();
        let output = String::from_utf8_lossy(&self.run(args)?.stdout).into_owned();
        for item in output.trim().split("\n") {
            list.push(item.to_string())
        }
        Ok(list)
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> IPTResult<Output> {
        let mut file_lock = None;

        let mut output_cmd = Command::new(self.cmd);
        let output;

        if self.has_wait {
            output = output_cmd.args(args).arg("--wait").output()?;
        } else {
            file_lock = Some(File::create("/var/run/xtables_old.lock")?);

            let mut need_retry = true;
            while need_retry {
                match flock(
                    file_lock.as_ref().unwrap().as_raw_fd(),
                    FlockArg::LockExclusiveNonblock,
                ) {
                    Ok(_) => need_retry = false,
                    Err(e) => {
                        if e.errno() == nix::errno::EAGAIN {
                            // FIXME: may cause infinite loop
                            need_retry = true;
                        } else {
                            return Err(IPTError::Nix(e));
                        }
                    }
                }
            }
            output = output_cmd.args(args).output()?;
        }

        if !self.has_wait {
            match file_lock {
                Some(f) => drop(f),
                None => (),
            };
        }

        match output.status.code() {
            None => Ok(output),
            Some(0) => Ok(output),
            Some(i) => Err(IPTError::BadExitStatus(i)),
        }
    }
}
